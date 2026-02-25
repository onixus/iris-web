#!/usr/bin/env python3
"""
DFIR-IRIS Incident Response Pipeline (RU)
Автоматизированный pipeline реагирования на инциденты.
Поддерживает: DDoS, APT/Фишинг, Ransomware, Утечки данных.
Регуляторные требования: 187-ФЗ (КИИ/ГосСОПКА), 149-ФЗ (РКН/ПДн)
"""

import os
import json
import yaml
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("iris-pipeline")

# ─── Загрузка конфига ───────────────────────────────────────────────────────

def load_config(path: str = "config/pipeline_config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    # Переменные окружения перекрывают файл
    cfg["iris"]["url"] = os.getenv("IRIS_URL", cfg["iris"]["url"])
    cfg["iris"]["api_key"] = os.getenv("IRIS_API_KEY", cfg["iris"]["api_key"])
    if os.getenv("VT_API_KEY"):
        cfg["enrichment"]["virustotal"]["api_key"] = os.getenv("VT_API_KEY")
    if os.getenv("TG_BOT_TOKEN"):
        cfg["notifications"]["telegram"]["bot_token"] = os.getenv("TG_BOT_TOKEN")
    if os.getenv("TG_CHAT_ID"):
        cfg["notifications"]["telegram"]["chat_id"] = os.getenv("TG_CHAT_ID")
    return cfg


# ─── IRIS API Client ────────────────────────────────────────────────────────

class IrisClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        self.base = url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        self.verify = verify_ssl

    def _get(self, path: str) -> dict:
        r = requests.get(f"{self.base}{path}", headers=self.headers, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict) -> dict:
        r = requests.post(f"{self.base}{path}", headers=self.headers,
                          json=data, verify=self.verify)
        r.raise_for_status()
        return r.json()

    def get_template_id(self, template_name: str) -> Optional[int]:
        """Получить ID шаблона кейса по имени."""
        resp = self._get("/manage/case-templates/list")
        for t in resp.get("data", []):
            if t.get("name") == template_name:
                return t["id"]
        return None

    def create_case(self, title: str, description: str,
                    template_name: str, tags: list, severity: int) -> dict:
        """Создать кейс из шаблона."""
        template_id = self.get_template_id(template_name)
        payload = {
            "case_name": title,
            "case_description": description,
            "case_customer": 1,
            "case_severity_id": severity,
            "case_template_fname": template_name,
            "case_tags": ",".join(tags)
        }
        if template_id:
            payload["case_template_id"] = template_id
        return self._post("/manage/cases/add", payload)

    def add_ioc(self, case_id: int, value: str, ioc_type: str,
                description: str = "", tlp: int = 2) -> dict:
        """Добавить IOC в кейс."""
        payload = {
            "ioc_value": value,
            "ioc_type_id": self._resolve_ioc_type(ioc_type),
            "ioc_description": description,
            "ioc_tlp_id": tlp,
            "ioc_tags": "auto-pipeline",
            "cid": case_id
        }
        return self._post(f"/case/ioc/add?cid={case_id}", payload)

    def add_note(self, case_id: int, directory_name: str,
                 title: str, content: str) -> dict:
        """Добавить заметку в директорию."""
        # Получить или создать директорию
        dirs = self._get(f"/case/notes/directories/filter?cid={case_id}").get("data", [])
        dir_id = None
        for d in dirs:
            if d.get("name") == directory_name:
                dir_id = d["id"]
                break
        if not dir_id:
            resp = self._post("/case/notes/directories/add",
                              {"name": directory_name, "cid": case_id})
            dir_id = resp["data"]["id"]
        payload = {
            "note_title": title,
            "note_content": content,
            "note_directory_id": dir_id,
            "cid": case_id
        }
        return self._post(f"/case/notes/add?cid={case_id}", payload)

    def _resolve_ioc_type(self, ioc_type: str) -> int:
        """Маппинг типов IOC."""
        mapping = {
            "ip": 76, "ip-dst": 76, "ip-src": 76,
            "domain": 20, "hostname": 12,
            "url": 141, "uri": 141,
            "md5": 95, "sha1": 114, "sha256": 113,
            "email": 24, "filename": 28
        }
        return mapping.get(ioc_type.lower(), 76)


# ─── Классификатор инцидентов ────────────────────────────────────────────────

class IncidentClassifier:
    def __init__(self, classification_cfg: dict):
        self.cfg = classification_cfg

    def classify(self, alert_title: str, alert_desc: str = "") -> str:
        """Определить тип инцидента по тексту алерта."""
        text = (alert_title + " " + alert_desc).lower()
        # Приоритет: ransomware > data_breach > apt_phishing > ddos
        priority_order = ["ransomware", "data_breach", "apt_phishing", "ddos"]
        for incident_type in priority_order:
            cfg = self.cfg.get(incident_type, {})
            if any(kw.lower() in text for kw in cfg.get("keywords", [])):
                return incident_type
        return "ddos"  # fallback


# ─── Обогащение IOC через VirusTotal ────────────────────────────────────────

class IOCEnricher:
    def __init__(self, vt_api_key: str):
        self.vt_key = vt_api_key
        self.vt_base = "https://www.virustotal.com/api/v3"

    def check_hash(self, file_hash: str) -> dict:
        headers = {"x-apikey": self.vt_key}
        r = requests.get(f"{self.vt_base}/files/{file_hash}",
                         headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "name": data.get("meaningful_name", "unknown")
            }
        return {}

    def check_ip(self, ip: str) -> dict:
        headers = {"x-apikey": self.vt_key}
        r = requests.get(f"{self.vt_base}/ip_addresses/{ip}",
                         headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "country": data.get("country", "unknown"),
                "asn": data.get("asn", 0)
            }
        return {}


# ─── Уведомления Telegram ───────────────────────────────────────────────────

class TelegramNotifier:
    def __init__(self, bot_token: str, chat_id: str):
        self.token = bot_token
        self.chat_id = chat_id
        self.base = f"https://api.telegram.org/bot{bot_token}"

    def send(self, message: str) -> bool:
        try:
            r = requests.post(f"{self.base}/sendMessage", json={
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "HTML"
            }, timeout=10)
            return r.status_code == 200
        except Exception as e:
            log.error(f"Telegram error: {e}")
            return False

    def notify_case_created(self, case_id: int, case_name: str,
                            incident_type: str, iris_url: str):
        emoji = {"ddos": "🌊", "apt_phishing": "🎣", "ransomware": "🔐", "data_breach": "💾"}
        severity = {"ddos": "HIGH", "apt_phishing": "CRITICAL", "ransomware": "CRITICAL", "data_breach": "HIGH"}
        icon = emoji.get(incident_type, "🚨")
        sev = severity.get(incident_type, "HIGH")
        msg = (
            f"{icon} <b>Новый инцидент создан в DFIR-IRIS</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"📋 <b>Кейс:</b> #{case_id} — {case_name}\n"
            f"🔴 <b>Тип:</b> {incident_type.upper()}\n"
            f"⚠️ <b>Severity:</b> {sev}\n"
            f"🔗 <a href='{iris_url}/case?cid={case_id}'>Открыть в IRIS</a>\n"
            f"⏰ <b>Время:</b> {datetime.now().strftime('%d.%m.%Y %H:%M')} MSK"
        )
        return self.send(msg)

    def notify_compliance_deadline(self, case_id: int, case_name: str,
                                    regulator: str, deadline_dt: datetime,
                                    iris_url: str):
        time_left = deadline_dt - datetime.now()
        hours_left = int(time_left.total_seconds() / 3600)
        msg = (
            f"⏳ <b>ДЕДЛАЙН РЕГУЛЯТОРА — {regulator}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"📋 <b>Кейс:</b> #{case_id} — {case_name}\n"
            f"⚠️ <b>Осталось:</b> {hours_left} ч.\n"
            f"📅 <b>Дедлайн:</b> {deadline_dt.strftime('%d.%m.%Y %H:%M')} MSK\n"
            f"🔗 <a href='{iris_url}/case?cid={case_id}'>Открыть в IRIS</a>"
        )
        return self.send(msg)


# ─── Таймер регуляторных дедлайнов ──────────────────────────────────────────

class ComplianceTimer:
    def __init__(self, config: dict, notifier: TelegramNotifier, iris_url: str):
        self.cfg = config
        self.notifier = notifier
        self.iris_url = iris_url

    def schedule(self, case_id: int, case_name: str, incident_type: str):
        """Запустить таймеры дедлайнов в зависимости от типа инцидента."""
        now = datetime.now()
        deadlines = []

        if incident_type in ("apt_phishing", "ransomware", "data_breach", "ddos"):
            # 187-ФЗ: ГосСОПКА/НКЦКИ — 3 часа (для КИИ)
            gossopka_dl = now + timedelta(hours=self.cfg["gossopka_kii_notify_hours"])
            deadlines.append(("ГосСОПКА/НКЦКИ (187-ФЗ)", gossopka_dl))

        if incident_type == "data_breach":
            # 149-ФЗ: РКН — 24 и 72 часа
            rkn_primary = now + timedelta(hours=self.cfg["rkn_pdн_primary_hours"])
            rkn_extended = now + timedelta(hours=self.cfg["rkn_pdн_extended_hours"])
            deadlines.append(("РКН первичное (149-ФЗ)", rkn_primary))
            deadlines.append(("РКН расширенное (149-ФЗ)", rkn_extended))

        for regulator, deadline in deadlines:
            # Напомнить за 30 минут до дедлайна
            remind_at = deadline - timedelta(minutes=30)
            delay = max(0, (remind_at - datetime.now()).total_seconds())
            t = threading.Timer(
                delay,
                self.notifier.notify_compliance_deadline,
                args=[case_id, case_name, regulator, deadline, self.iris_url]
            )
            t.daemon = True
            t.start()
            log.info(f"⏰ Таймер {regulator} → {deadline.strftime('%H:%M %d.%m')} (кейс #{case_id})")


# ─── Основной обработчик алертов ─────────────────────────────────────────────

class AlertPipeline:
    def __init__(self, config_path: str = "config/pipeline_config.yaml"):
        self.cfg = load_config(config_path)
        self.iris = IrisClient(
            self.cfg["iris"]["url"],
            self.cfg["iris"]["api_key"],
            self.cfg["iris"].get("verify_ssl", True)
        )
        self.classifier = IncidentClassifier(self.cfg["classification"])

        self.enricher = None
        vt_cfg = self.cfg["enrichment"]["virustotal"]
        if vt_cfg.get("enabled") and vt_cfg.get("api_key"):
            self.enricher = IOCEnricher(vt_cfg["api_key"])

        self.notifier = None
        tg_cfg = self.cfg["notifications"]["telegram"]
        if tg_cfg.get("enabled") and tg_cfg.get("bot_token"):
            self.notifier = TelegramNotifier(tg_cfg["bot_token"], tg_cfg["chat_id"])

        self.compliance_timer = None
        if self.notifier and self.cfg["compliance"].get("auto_remind"):
            self.compliance_timer = ComplianceTimer(
                self.cfg["compliance"], self.notifier, self.cfg["iris"]["url"]
            )

    def process_alert(self, alert: dict):
        """Основной метод обработки входящего алерта."""
        title = alert.get("alert_title", "Unknown Incident")
        desc = alert.get("alert_description", "")
        source = alert.get("alert_source", "unknown")
        iocs = alert.get("alert_iocs", [])
        if isinstance(iocs, str):
            try:
                iocs = json.loads(iocs)
            except Exception:
                iocs = []

        log.info(f"📥 Алерт получен: '{title}' (источник: {source})")

        # 1. Классификация
        incident_type = self.classifier.classify(title, desc)
        inc_cfg = self.cfg["classification"][incident_type]
        template = inc_cfg["template"]
        severity = inc_cfg["severity"]
        log.info(f"🔍 Тип: {incident_type.upper()}, шаблон: {template}")

        # 2. Создание кейса
        tags = [incident_type, source, "pipeline-auto"]
        try:
            case_resp = self.iris.create_case(
                title=f"[AUTO] {title}",
                description=f"Автоматически создан pipeline из алерта.\n\n**Источник:** {source}\n\n{desc}",
                template_name=template,
                tags=tags,
                severity=severity
            )
            case_id = case_resp.get("data", {}).get("case_id") or case_resp.get("case_id")
            log.info(f"✅ Кейс создан: #{case_id}")
        except Exception as e:
            log.error(f"❌ Ошибка создания кейса: {e}")
            return

        # 3. Добавление IOC
        if iocs and case_id:
            for ioc in iocs[:20]:  # максимум 20 IOC за раз
                try:
                    ioc_val = ioc.get("value") or ioc.get("ioc_value", "")
                    ioc_type = ioc.get("type") or ioc.get("ioc_type", "ip")
                    if ioc_val:
                        # Обогащение VT
                        ioc_desc = ""
                        if self.enricher and ioc_type in ("md5", "sha256", "sha1"):
                            vt_result = self.enricher.check_hash(ioc_val)
                            if vt_result:
                                ioc_desc = f"VT: {vt_result.get('malicious', 0)}/{vt_result.get('total', 0)} malicious"
                        elif self.enricher and ioc_type == "ip":
                            vt_result = self.enricher.check_ip(ioc_val)
                            if vt_result:
                                ioc_desc = f"VT malicious: {vt_result.get('malicious', 0)}, Country: {vt_result.get('country', '?')}"

                        self.iris.add_ioc(case_id, ioc_val, ioc_type, ioc_desc)
                        log.info(f"  IOC добавлен: {ioc_val} ({ioc_type})")
                except Exception as e:
                    log.warning(f"  ⚠️ IOC ошибка: {e}")

        # 4. Уведомление SOC
        if self.notifier and case_id:
            self.notifier.notify_case_created(
                case_id, title, incident_type, self.cfg["iris"]["url"]
            )

        # 5. Таймеры регуляторных дедлайнов
        if self.compliance_timer and case_id:
            self.compliance_timer.schedule(case_id, title, incident_type)

        return case_id


# ─── Webhook-сервер ──────────────────────────────────────────────────────────

class WebhookHandler(BaseHTTPRequestHandler):
    pipeline: AlertPipeline = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        if self.path == "/webhook/alert":
            try:
                case_id = self.pipeline.process_alert(data)
                response = json.dumps({"status": "ok", "case_id": case_id}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(response)
            except Exception as e:
                log.error(f"Pipeline error: {e}")
                self.send_response(500)
                self.end_headers()
        elif self.path == "/webhook/ioc":
            # IOC из кейса — авто-обогащение
            log.info(f"IOC webhook: {data.get('ioc_value')}")
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        log.info(f"HTTP {args[0]} {args[1]}")


def run_webhook_server(pipeline: AlertPipeline, host: str = "0.0.0.0", port: int = 8000):
    WebhookHandler.pipeline = pipeline
    server = HTTPServer((host, port), WebhookHandler)
    log.info(f"🚀 Pipeline webhook-сервер запущен на {host}:{port}")
    server.serve_forever()


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DFIR-IRIS Incident Response Pipeline")
    parser.add_argument("--config", default="config/pipeline_config.yaml")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--test", action="store_true", help="Отправить тестовый алерт")
    args = parser.parse_args()

    pipeline = AlertPipeline(args.config)

    if args.test:
        test_alert = {
            "alert_title": "Ransomware detected on WORKSTATION-42",
            "alert_description": "EDR обнаружил процесс шифрования файлов. Расширение: .locked. Patient Zero: 192.168.10.42",
            "alert_source": "EDR-Test",
            "alert_iocs": [
                {"value": "192.168.10.42", "type": "ip"},
                {"value": "a3f1b2c4d5e6f7890123456789abcdef", "type": "md5"}
            ]
        }
        log.info("🧪 Запуск тестового алерта...")
        pipeline.process_alert(test_alert)
    else:
        run_webhook_server(pipeline, args.host, args.port)
