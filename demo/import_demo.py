#!/usr/bin/env python3
"""
iris_demo_import.py
-------------------
Скрипт для автоматической загрузки демо-датасетов в платформу DFIR IRIS.
Загружает последовательно: клиентов, кейсы, IOC, активы, алерты,
таймлайн, задачи, доказательства и заметки.

Использование:
    python3 import_demo.py --url https://iris-host --token YOUR_API_TOKEN
    python3 import_demo.py --url https://iris-host --token TOKEN --dry-run

Требования:
    pip install requests
"""

import argparse
import csv
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("iris-import")

# ---------------------------------------------------------------------------
# TLP и severity маппинги
# ---------------------------------------------------------------------------
TLP_MAP = {"TLP:WHITE": 1, "TLP:GREEN": 2, "TLP:AMBER": 3, "TLP:RED": 4}
SEVERITY_MAP = {"Informational": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
COMPROMISE_MAP = {
    "Не скомпрометирован": 1,
    "Подозрение": 2,
    "Под угрозой": 3,
    "Скомпрометирован": 4,
}
CASE_STATUS_MAP = {"В работе": 0, "Закрыт": 1}
ALERT_STATUS_MAP = {"Открыт": 1, "В работе": 2, "Эскалирован": 3, "Закрыт": 4}
TASK_STATUS_MAP = {"Не начата": 1, "В работе": 2, "Завершена": 3}


# ---------------------------------------------------------------------------
# Клиент IRIS API
# ---------------------------------------------------------------------------
class IrisClient:
    def __init__(self, base_url: str, token: str, dry_run: bool = False, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl
        self.dry_run = dry_run
        self._rate_delay = 0.15  # секунд между запросами

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str) -> dict:
        r = self.session.get(self._url(path))
        r.raise_for_status()
        return r.json()

    def post(self, path: str, payload: dict) -> Optional[dict]:
        if self.dry_run:
            log.info("[DRY-RUN] POST %s  %s", path, json.dumps(payload, ensure_ascii=False)[:120])
            return {"status": "success", "data": {"id": 0}}
        time.sleep(self._rate_delay)
        try:
            r = self.session.post(self._url(path), json=payload)
            resp = r.json()
            if not r.ok or resp.get("status") == "error":
                log.warning("  WARN [%s] %s → %s", r.status_code, path, str(resp)[:160])
                return None
            return resp
        except Exception as exc:
            log.error("  ERROR %s: %s", path, exc)
            return None

    def check_connection(self) -> bool:
        try:
            r = self.get("/api/v2/users/me")
            log.info("Подключено к IRIS: пользователь '%s'", r.get("data", {}).get("user_login", "?"))
            return True
        except Exception as e:
            log.error("Не удалось подключиться к IRIS: %s", e)
            return False


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
def load_csv(filepath: str) -> list[dict]:
    path = Path(filepath)
    if not path.exists():
        log.warning("Файл не найден: %s — пропуск", filepath)
        return []
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    log.info("Загружено %d строк из %s", len(rows), path.name)
    return rows


def extract_id(resp: Optional[dict], *keys: str) -> Optional[int]:
    """Извлекает числовой ID из вложенного ответа API."""
    if not resp:
        return None
    data = resp.get("data", {})
    for key in keys:
        if key in data:
            return data[key]
    return None


# ---------------------------------------------------------------------------
# Загрузчики по типам объектов
# ---------------------------------------------------------------------------
def import_clients(api: IrisClient) -> dict[str, int]:
    """Возвращает маппинг customer_id -> числовой ID IRIS."""
    log.info("\n=== Клиенты ===")
    client_map: dict[str, int] = {}
    rows = load_csv("demo/clients.csv")
    for row in rows:
        resp = api.post("/api/v2/clients", {
            "customer_name":        row["client_name"],
            "customer_description": row.get("client_description", ""),
            "customer_sla":         row.get("sla_hours", "8"),
        })
        iris_id = extract_id(resp, "customer_id", "id")
        if iris_id:
            client_map[row["customer_id"]] = iris_id
            log.info("  + Клиент '%s' → IRIS ID %d", row["client_name"], iris_id)
    return client_map


def import_cases(api: IrisClient, client_map: dict[str, int]) -> dict[str, int]:
    """Возвращает маппинг case_name -> числовой ID кейса в IRIS."""
    log.info("\n=== Кейсы ===")
    case_map: dict[str, int] = {}
    rows = load_csv("demo/cases.csv")
    for row in rows:
        customer_iris_id = client_map.get(row.get("client_id", ""), 1)
        resp = api.post("/api/v2/cases", {
            "case_name":        row["case_name"],
            "case_description": row.get("case_description", ""),
            "case_customer":    customer_iris_id,
            "case_soc_id":      row["case_name"],
            "case_severity_id": SEVERITY_MAP.get(row.get("severity", "Medium"), 3),
        })
        case_id = extract_id(resp, "case_id", "id")
        if case_id:
            case_map[row["case_name"]] = case_id
            log.info("  + Кейс '%s' → IRIS ID %d", row["case_name"][:60], case_id)
    return case_map


def import_iocs(api: IrisClient, case_map: dict[str, int]) -> None:
    log.info("\n=== IOC ===")
    rows = load_csv("demo/iocs.csv")
    for row in rows:
        case_id = case_map.get(row.get("case_id", ""), next(iter(case_map.values()), 1))
        resp = api.post(f"/api/v2/cases/{case_id}/iocs", {
            "ioc_value":       row["ioc_value"],
            "ioc_type_id":     1,
            "ioc_description": row.get("ioc_description", ""),
            "ioc_tlp_id":      TLP_MAP.get(row.get("tlp", "TLP:AMBER"), 3),
            "ioc_tags":        row.get("tags", "").replace(";", ","),
        })
        if resp:
            log.info("  + IOC '%s' (%s)", row["ioc_value"][:50], row.get("ioc_type", ""))


def import_assets(api: IrisClient, case_map: dict[str, int]) -> None:
    log.info("\n=== Активы ===")
    rows = load_csv("demo/assets.csv")
    for row in rows:
        case_id = case_map.get(row.get("case_id", ""), next(iter(case_map.values()), 1))
        resp = api.post(f"/api/v2/cases/{case_id}/assets", {
            "asset_name":                 row["asset_name"],
            "asset_type_id":              1,
            "asset_ip":                   row.get("asset_ip", ""),
            "asset_description":          row.get("asset_os", ""),
            "asset_domain":               row.get("domain", ""),
            "asset_compromise_status_id": COMPROMISE_MAP.get(row.get("compromise_status", ""), 1),
        })
        if resp:
            log.info("  + Актив '%s' (%s)", row["asset_name"], row.get("asset_ip", ""))


def import_alerts(api: IrisClient, case_map: dict[str, int]) -> None:
    log.info("\n=== Алерты ===")
    rows = load_csv("demo/alerts.csv")
    for row in rows:
        resp = api.post("/api/v2/alerts", {
            "alert_title":       row["alert_title"],
            "alert_source":      row.get("alert_source", "Unknown"),
            "alert_severity_id": SEVERITY_MAP.get(row.get("alert_severity", "Medium"), 3),
            "alert_status_id":   ALERT_STATUS_MAP.get(row.get("alert_status", "Открыт"), 1),
            "alert_customer_id": 1,
            "alert_description": row.get("description", ""),
            "alert_source_content": {
                "ioc":            row.get("ioc_value", ""),
                "classification": row.get("classification", ""),
                "case_id":        row.get("case_id", ""),
            },
        })
        if resp:
            log.info("  + Алерт '%s'", row["alert_title"][:60])


def import_timeline(api: IrisClient, case_map: dict[str, int]) -> None:
    log.info("\n=== Таймлайн ===")
    rows = load_csv("demo/timeline.csv")
    for row in rows:
        case_id = case_map.get(row.get("case_id", ""), next(iter(case_map.values()), 1))
        resp = api.post(f"/api/v2/cases/{case_id}/timeline/events", {
            "event_date":          row["event_date"],
            "event_title":         row["event_title"],
            "event_content":       row.get("event_content", ""),
            "event_source":        row.get("event_source", ""),
            "event_category_id":   1,
            "event_raw":           json.dumps({
                "mitre_tactic":    row.get("mitre_tactic", ""),
                "mitre_technique": row.get("mitre_technique", ""),
            }, ensure_ascii=False),
            "event_tags":          row.get("event_category", ""),
        })
        if resp:
            log.info("  + Событие '%s' [%s]", row["event_title"][:50], row["event_date"])


def import_tasks(api: IrisClient, case_map: dict[str, int]) -> None:
    log.info("\n=== Задачи ===")
    rows = load_csv("demo/tasks.csv")
    for row in rows:
        case_id = case_map.get(row.get("case_id", ""), next(iter(case_map.values()), 1))
        resp = api.post(f"/api/v2/cases/{case_id}/tasks", {
            "task_title":       row["task_title"],
            "task_description": row.get("task_description", ""),
            "task_status_id":   TASK_STATUS_MAP.get(row.get("task_status", "Не начата"), 1),
            "task_assignees":   [],
        })
        if resp:
            log.info("  + Задача '%s'", row["task_title"][:60])


def import_notes(api: IrisClient, case_map: dict[str, int]) -> None:
    log.info("\n=== Заметки ===")
    rows = load_csv("demo/notes.csv")
    for row in rows:
        case_id = case_map.get(row.get("case_id", ""), next(iter(case_map.values()), 1))
        # Сначала создаём группу заметок
        grp = api.post(f"/api/v2/cases/{case_id}/notes/groups", {
            "group_title": "Демо-заметки"
        })
        group_id = extract_id(grp, "group_id", "id") or 1
        resp = api.post(f"/api/v2/cases/{case_id}/notes", {
            "note_title":    row["note_title"],
            "note_content":  row.get("note_content", ""),
            "group_id":      group_id,
        })
        if resp:
            log.info("  + Заметка '%s'", row["note_title"][:60])


def import_evidence(api: IrisClient, case_map: dict[str, int]) -> None:
    log.info("\n=== Доказательства ===")
    rows = load_csv("demo/evidence.csv")
    for row in rows:
        case_id = case_map.get(row.get("case_id", ""), next(iter(case_map.values()), 1))
        resp = api.post(f"/api/v2/cases/{case_id}/evidences", {
            "filename":          row["evidence_name"],
            "file_description":  row.get("evidence_description", ""),
            "file_hash":         row.get("evidence_hash_sha256", ""),
            "file_size":         0,
        })
        if resp:
            log.info("  + Улика '%s'", row["evidence_name"][:60])


# ---------------------------------------------------------------------------
# ELK bulk import helper
# ---------------------------------------------------------------------------
def import_elk_logs(es_url: str, logs_dir: str = "demo/logs") -> None:
    """Отдельная функция для загрузки NDJSON-логов в Elasticsearch."""
    import glob

    log.info("\n=== ELK Logs → Elasticsearch ===")
    files = sorted(glob.glob(f"{logs_dir}/*.ndjson"))
    if not files:
        log.warning("Файлы *.ndjson не найдены в %s", logs_dir)
        return

    for fpath in files:
        fname = Path(fpath).name
        with open(fpath, "rb") as f:
            data = f.read()
        try:
            r = requests.post(
                f"{es_url.rstrip('/')}/_bulk",
                data=data,
                headers={"Content-Type": "application/x-ndjson"},
                timeout=30,
            )
            result = r.json()
            errors = result.get("errors", True)
            items  = len(result.get("items", []))
            status = "ERR" if errors else "OK "
            log.info("  %s %s → %d документов", status, fname, items)
        except Exception as exc:
            log.error("  ERROR %s: %s", fname, exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Загрузка демо-датасетов в DFIR IRIS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Загрузить всё в IRIS
  python3 import_demo.py --url https://iris.company.ru --token abc123

  # Только посмотреть запросы без реальной отправки
  python3 import_demo.py --url https://iris.company.ru --token abc123 --dry-run

  # Загрузить логи ELK дополнительно
  python3 import_demo.py --url https://iris.company.ru --token abc123 \\
                         --elk-url http://localhost:9200

  # Пропустить проверку SSL-сертификата
  python3 import_demo.py --url https://iris.company.ru --token abc123 --no-verify
    """,
    )
    p.add_argument("--url",       required=True,  help="Базовый URL IRIS, например https://iris.company.ru")
    p.add_argument("--token",     required=True,  help="API-токен IRIS (Settings → API Keys)")
    p.add_argument("--dry-run",   action="store_true", help="Не отправлять запросы, только вывести в лог")
    p.add_argument("--no-verify", action="store_true", help="Отключить проверку SSL-сертификата")
    p.add_argument("--elk-url",   default=None,   help="URL Elasticsearch для загрузки NDJSON-логов")
    p.add_argument("--skip",      nargs="*",       default=[],
                   help="Пропустить шаги: clients cases iocs assets alerts timeline tasks notes evidence elk")
    p.add_argument("--demo-dir",  default=".",     help="Корневая директория с папкой demo/ (по умолчанию: .)")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Переходим в рабочую директорию
    import os
    os.chdir(args.demo_dir)

    api = IrisClient(
        base_url=args.url,
        token=args.token,
        dry_run=args.dry_run,
        verify_ssl=not args.no_verify,
    )

    if not args.dry_run and not api.check_connection():
        sys.exit(1)

    skip = set(args.skip or [])

    # --- Загрузка объектов ---
    client_map: dict[str, int] = {}
    case_map:   dict[str, int] = {}

    if "clients" not in skip:
        client_map = import_clients(api)

    if "cases" not in skip:
        case_map = import_cases(api, client_map)

    if not case_map and not args.dry_run:
        log.warning("Кейсы не созданы — дальнейшие объекты требуют case_id. Используем ID=1.")
        case_map = {"CASE-2025-001: Шифровальщик LockBit": 1}

    if "alerts"   not in skip: import_alerts(api, case_map)
    if "iocs"     not in skip: import_iocs(api, case_map)
    if "assets"   not in skip: import_assets(api, case_map)
    if "timeline" not in skip: import_timeline(api, case_map)
    if "tasks"    not in skip: import_tasks(api, case_map)
    if "evidence" not in skip: import_evidence(api, case_map)
    if "notes"    not in skip: import_notes(api, case_map)

    # --- ELK ---
    if "elk" not in skip and args.elk_url:
        import_elk_logs(args.elk_url)
    elif args.elk_url is None and "elk" not in skip:
        log.info("\nПодсказка: укажите --elk-url http://localhost:9200 для загрузки NDJSON-логов в Elasticsearch")

    log.info("\n✓ Импорт завершён")


if __name__ == "__main__":
    main()
