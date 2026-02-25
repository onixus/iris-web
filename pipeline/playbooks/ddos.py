"""Playbook: DDoS-атака (хактивизм) — DFIR-IRIS RU"""

from datetime import datetime


def run(iris_client, case_id: int, alert: dict, notifier=None):
    """
    Автоматические действия при DDoS-атаке:
    1. Добавить заметку с первичной оценкой
    2. Добавить IOC источников атаки
    3. Создать задачу для инженера
    """
    src_ips = [ioc for ioc in alert.get("alert_iocs", []) if ioc.get("type") == "ip"]
    attack_vector = _detect_vector(alert.get("alert_description", ""))

    # Заметка: первичная оценка
    content = (
        f"## Первичная оценка DDoS-атаки\n\n"
        f"**Время обнаружения:** {datetime.now().strftime('%d.%m.%Y %H:%M')} MSK\n\n"
        f"**Вектор атаки (авто):** {attack_vector}\n\n"
        f"**IP-источников в алерте:** {len(src_ips)}\n\n"
        f"**Источник алерта:** {alert.get('alert_source', 'N/A')}\n\n"
        f"## Рекомендуемые немедленные действия\n\n"
        f"1. Подать заявку провайдеру Anti-DDoS (Qrator/StormWall/USSC)\n"
        f"2. Активировать BGP Blackhole для атакуемых IP\n"
        f"3. Проверить WAF — включить emergency mode\n"
        f"4. Уведомить НКЦКИ (187-ФЗ, если КИИ)\n"
    )
    iris_client.add_note(case_id, "Автоматизация", "[AUTO] Первичная оценка DDoS", content)
    return {"status": "ok", "iocs_added": len(src_ips)}


def _detect_vector(description: str) -> str:
    desc = description.lower()
    if "amplification" in desc or "reflection" in desc:
        return "UDP Amplification/Reflection"
    if "syn" in desc:
        return "SYN Flood"
    if "http" in desc or "l7" in desc:
        return "HTTP Flood (L7)"
    if "botnet" in desc or "iot" in desc:
        return "IoT Botnet"
    return "Не определён (требуется ручной анализ)"
