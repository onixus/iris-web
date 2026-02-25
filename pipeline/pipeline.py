#!/usr/bin/env python3
"""
DFIR-IRIS Incident Response Pipeline (RU)
Автоматизированный pipeline реагирования на инциденты.
Поддерживает: DDoS, APT/Фишинг, Ransomware, Утечки данных.
Регуляторные требования: 187-ФЗ (КИИ/ГосСОПКА), 149-ФЗ (РКН/ПДн)

Changelog:
  v1.4: FIX формат case_soc_id → ALRTX-DD.MM.YYYY-ID
  v1.3: FIX добавлен case_soc_id с автогенерацией
  v1.2: ADD debug logging для IRIS API errors
  v1.2: FIX suppress SSL warnings
  v1.1: FIX кириллица в ключах конфига rkn_pdн_* → rkn_pdn_*
  v1.1: FIX Content-Type на /webhook/ioc
  v1.1: FIX проверка case_id на None + логирование
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
import urllib3
from dotenv import load_dotenv

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        """POST request with detailed error logging."""
        r = requests.post(f"{self.base}{path}", headers=self.headers,
                          json=data, verify=self.verify)
        # Log detailed error info if status >= 400
        if r.status_code >= 400:
            log.error(f"❌ IRIS API {r.status_code} {path}")
            log.error(f"📤 Request payload: {json.dumps(data, indent=2)}")
            try:
                error_detail = r.json()
                log.error(f"📥 Response: {json.dumps(error_detail, indent=2)}")
            except:
                log.error(f"📥 Response text: {r.text[:500]}")
        r.raise_for_status()
        return r.json()

    def get_template_id(self, template_name: str) -> Optional[int]:
        """Get case template ID by name."""
        resp = self._get("/manage/case-templates/list")
        for t in resp.get("data", []):
            if t.get("name") == template_name:
                return t["id"]
        return None

    def create_case(self, title: str, description: str,
                    template_name: str, tags: list, severity: int) -> dict:
        """Create a case from template."""
        template_id = self.get_template_id(template_name)
        
        # Generate unique case_soc_id in format: ALRTX-DD.MM.YYYY-ID
        # ID = last 4 digits of unix timestamp (semi-sequential within same day)
        now = datetime.now()
        date_part = now.strftime('%d.%m.%Y')
        id_part = int(now.timestamp()) % 10000
        case_soc_id = f"ALRTX-{date_part}-{id_part:04d}"
        
        payload = {
            "case_name": title,
            "case_description": description,
            "case_customer": 1,
            "case_severity_id": severity,
            "case_soc_id": case_soc_id,
            "case_template_fname": template_name,
            "case_tags": ",".join(tags)
        }
        if template_id:
            payload["case_template_id"] = template_id
        return self._post("/manage/cases/add", payload)

    def add_ioc(self, case_id: int, value: str, ioc_type: str,
                description: str = "", tlp: int = 2) -> dict:
        """Add IOC to a case."""
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
        """Add note to a directory in a case."""
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
        """Map IOC type string to IRIS type ID."""
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
        """Classify incident type by alert text."""
        text = (alert_title + " " + alert_desc).lower()
        # Priority: ransomware > data_breach > apt_phishing > ddos
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
        severity = {"ddos": "HIGH", "apt_phishing": "CRITICAL",
                    "ransomware": "CRITICAL", "data_breach": "HIGH"}
        icon = emoji.get(incident_type, "🚨")
        sev = severity.get(incident_type, "HIGH")
        msg = (
            f"{icon} <b>Новый инцидент в DFIR-IRIS</b>\n"
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
        hours_left = max(0, int(time_left.total_seconds() / 3600))
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
        """Schedule regulatory deadline reminders."""
        now = datetime.now()
        deadlines = []

        if incident_type in ("apt_phishing", "ransomware", "data_breach", "ddos"):
            # 187-ФЗ: ГосСОПКА/НКЦКИ — 3 часа
            gossopka_dl = now + timedelta(hours=self.cfg["gossopka_kii_notify_hours"])
            deadlines.append(("ГосСОПКА/НКЦКИ (187-ФЗ)", gossopka_dl))

        if incident_type == "data_breach":
            # 149-ФЗ: РКН — 24 и 72 часа
            # FIX: исправлена кириллица в ключах (rkn_pdн_* → rkn_pdn_*)
            rkn_primary = now + timedelta(hours=self.cfg["rkn_pdn_primary_hours"])
            rkn_extended = now + timedelta(hours=self.cfg["rkn_pdn_extended_hours"])
            deadlines.append(("РКН первичное (149-ФЗ)", rkn_primary))
            deadlines.append(("РКН расширенное (149-ФЗ)", rkn_extended))

        for regulator, deadline in deadlines:
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
        """Main alert processing method."""
        title = alert.get("alert_title", "Unknown Incident")
        desc = alert.get("alert_description", "")
        source = alert.get("alert_source", "unknown")
        iocs = alert.get("alert_iocs", [])
        if isinstance(iocs, str):
            try:
                iocs = json.loads(iocs)
            except Exception:
                iocs = []

        log.info(f"📥 Алерт: '{title}' (источник: {source})")

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
                description=(
                    f"Автоматически создан pipeline из алерта."
                    f"\n\n**Источник:** {source}\n\n{desc}"
                ),
                template_name=template,
                tags=tags,
                severity=severity
            )
            # FIX: явная проверка case_id из разных путей ответа IRIS API
            case_id = (
                case_resp.get("data", {}).get("case_id")
                or case_resp.get("case_id")
                or case_resp.get("data", {}).get("case_soc_id")
            )
            if not case_id:
                log.error(f"❌ case_id не найден в ответе: {case_resp}")
                return None
            log.info(f"✅ Кейс создан: #{case_id}")
        except Exception as e:
            log.error(f"❌ Ошибка создания кейса: {e}")
            return None

        # 3. Добавление IOC
        if iocs:
            for ioc in iocs[:20]:
                try:
                    ioc_val = ioc.get("value") or ioc.get("ioc_value", "")
                    ioc_type = ioc.get("type") or ioc.get("ioc_type", "ip")
                    if not ioc_val:
                        continue
                    ioc_desc = ""
                    if self.enricher and ioc_type in ("md5", "sha256", "sha1"):
                        vt_result = self.enricher.check_hash(ioc_val)
                        if vt_result:
                            ioc_desc = f"VT: {vt_result.get('malicious', 0)}/{vt_result.get('total', 0)} malicious"
                    elif self.enricher and ioc_type == "ip":
                        vt_result = self.enricher.check_ip(ioc_val)
                        if vt_result:
                            ioc_desc = (
                                f"VT malicious: {vt_result.get('malicious', 0)}, "
                                f"Country: {vt_result.get('country', '?')}"
                            )
                    self.iris.add_ioc(case_id, ioc_val, ioc_type, ioc_desc)
                    log.info(f"  ✔ IOC: {ioc_val} ({ioc_type}) {ioc_desc}")
                except Exception as e:
                    log.warning(f"  ⚠️ IOC ошибка: {e}")

        # 4. Уведомление SOC
        if self.notifier:
            self.notifier.notify_case_created(
                case_id, title, incident_type, self.cfg["iris"]["url"]
            )

        # 5. Таймеры регуляторных дедлайнов
        if self.compliance_timer:
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
            self._respond(400, {"status": "error", "msg": "invalid JSON"})
            return

        if self.path == "/webhook/alert":
            try:
                case_id = self.pipeline.process_alert(data)
                if case_id:
                    self._respond(200, {"status": "ok", "case_id": case_id})
                else:
                    self._respond(500, {"status": "error", "msg": "case_id not returned"})
            except Exception as e:
                log.error(f"Pipeline error: {e}")
                self._respond(500, {"status": "error", "msg": str(e)})

        elif self.path == "/webhook/ioc":
            log.info(f"IOC webhook: {data.get('ioc_value')} ({data.get('ioc_type')})")
            # FIX: добавлен Content-Type header
            self._respond(200, {"status": "ok"})

        elif self.path == "/webhook/case":
            log.info(f"Case webhook: #{data.get('case_id')} {data.get('case_name')}")
            self._respond(200, {"status": "ok"})

        elif self.path == "/health":
            self._respond(200, {"status": "ok", "service": "iris-pipeline"})

        else:
            self._respond(404, {"status": "error", "msg": "not found"})

    def _respond(self, code: int, body: dict):
        """Helper: send JSON response with correct headers."""
        response = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        log.info(f"HTTP {args[0]} {args[1]}")


def run_webhook_server(pipeline: AlertPipeline, host: str = "0.0.0.0", port: int = 8000):
    WebhookHandler.pipeline = pipeline
    server = HTTPServer((host, port), WebhookHandler)
    log.info(f"🚀 Pipeline webhook-сервер запущен: http://{host}:{port}")
    log.info(f"   /webhook/alert  — принимает алерты из IRIS")
    log.info(f"   /webhook/ioc    — новые IOC из IRIS")
    log.info(f"   /webhook/case   — новые кейсы из IRIS")
    log.info(f"   /health         — healthcheck")
    server.serve_forever()


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DFIR-IRIS Incident Response Pipeline RU")
    parser.add_argument("--config", default="config/pipeline_config.yaml")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--test", action="store_true",
                        help="Отправить тестовый алерт (Ransomware)")
    parser.add_argument("--test-type",
                        choices=["ransomware", "ddos", "apt_phishing", "data_breach"],
                        default="ransomware",
                        help="Тип тестового алерта")
    args = parser.parse_args()

    pipeline = AlertPipeline(args.config)

    if args.test:
        test_alerts = {
            "ransomware": {
                "alert_title": "Ransomware detected on WORKSTATION-42",
                "alert_description": "EDR обнаружил процесс шифрования. Extension: .locked",
                "alert_source": "EDR-Test",
                "alert_iocs": [
                    {"value": "192.168.10.42", "type": "ip"},
                    {"value": "a3f1b2c4d5e6f7890123456789abcdef", "type": "md5"}
                ]
            },
            "ddos": {
                "alert_title": "DDoS SYN flood detected on border router",
                "alert_description": "Anti-DDoS: SYN flood 40Gbps from botnet",
                "alert_source": "Anti-DDoS",
                "alert_iocs": [{"value": "1.2.3.4", "type": "ip"}]
            },
            "apt_phishing": {
                "alert_title": "Malicious attachment opened by user",
                "alert_description": "Sandbox: phishing email with Lumma Stealer payload",
                "alert_source": "PT-Sandbox",
                "alert_iocs": [{"value": "evil.domain.ru", "type": "domain"}]
            },
            "data_breach": {
                "alert_title": "Exfiltration of personal data detected",
                "alert_description": "DLP: large upload to external cloud, PDn suspected, data leak",
                "alert_source": "DLP",
                "alert_iocs": []
            }
        }
        test_alert = test_alerts[args.test_type]
        log.info(f"🧪 Тест: {args.test_type.upper()}")
        result = pipeline.process_alert(test_alert)
        log.info(f"🏁 Результат: case_id={result}")
    else:
        run_webhook_server(pipeline, args.host, args.port)
