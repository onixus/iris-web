"""Playbook: APT Целевой фишинг — DFIR-IRIS RU"""

from datetime import datetime


APT_GROUPS_RU = {
    "lumma": "Sticky Werewolf",
    "cloudatlas": "Cloud Atlas",
    "cloud atlas": "Cloud Atlas",
    "hta": "Cloud Atlas (HTA implant)",
    "vbs": "Cloud Atlas (VBS implant)",
    "bo team": "BO Team",
    "konni": "Konni",
}


def run(iris_client, case_id: int, alert: dict, notifier=None):
    """
    Автоматические действия при APT-фишинге:
    1. Атрибуция группировки по ключевым словам
    2. Заметка с рекомендациями по сбору артефактов
    3. Чеклист MITRE ATT&CK TTPs
    """
    desc = alert.get("alert_description", "").lower()
    title = alert.get("alert_title", "").lower()
    apt_group = _attribute_apt(desc + " " + title)

    # Заметка: атрибуция и TTPs
    content = (
        f"## Первичная атрибуция APT-атаки\n\n"
        f"**Время:** {datetime.now().strftime('%d.%m.%Y %H:%M')} MSK\n\n"
        f"**Предполагаемая группировка:** {apt_group}\n\n"
        f"## MITRE ATT&CK TTPs для проверки\n\n"
        f"| ID | Technique | Статус |\n"
        f"|---|---|---|\n"
        f"| T1566 | Phishing | ⬜ Проверить |\n"
        f"| T1059.001 | PowerShell Execution | ⬜ Проверить |\n"
        f"| T1053 | Scheduled Task | ⬜ Проверить |\n"
        f"| T1547 | Boot/Logon Autostart | ⬜ Проверить |\n"
        f"| T1550.002 | Pass-the-Hash | ⬜ Проверить |\n"
        f"| T1071 | C2 via HTTP/DNS | ⬜ Проверить |\n"
        f"| T1048 | Exfiltration | ⬜ Проверить |\n\n"
        f"## Артефакты для сбора (Velociraptor/OSQuery)\n\n"
        f"- [ ] EventLog: 4624, 4625, 4688, 7045\n"
        f"- [ ] PowerShell ScriptBlock logs\n"
        f"- [ ] Prefetch файлы\n"
        f"- [ ] ASEP (автозапуск)\n"
        f"- [ ] Сетевые соединения (netstat)\n"
        f"- [ ] Задачи планировщика\n"
    )
    iris_client.add_note(case_id, "Автоматизация", "[AUTO] APT Атрибуция и TTPs", content)

    # Заметка: уведомление регулятора
    compliance_note = (
        f"## Регуляторные требования\n\n"
        f"| Регулятор | Срок | Статус |\n"
        f"|---|---|---|\n"
        f"| НКЦКИ (187-ФЗ/КИИ) | ≤ 3 часов | ⬜ Ожидает |\n"
        f"| ФСТЭК | По запросу | ⬜ Ожидает |\n\n"
        f"**Инициировано:** {datetime.now().strftime('%d.%m.%Y %H:%M')} MSK\n"
    )
    iris_client.add_note(case_id, "Регуляторная отчётность", "[AUTO] Дедлайны уведомлений", compliance_note)
    return {"status": "ok", "apt_group": apt_group}


def _attribute_apt(text: str) -> str:
    for keyword, group in APT_GROUPS_RU.items():
        if keyword in text:
            return group
    return "Не определена (требуется TI-анализ: PT TI / BI.ZONE / F.A.C.C.T.)"
