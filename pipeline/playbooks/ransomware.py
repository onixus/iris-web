"""Playbook: Ransomware — DFIR-IRIS RU"""

from datetime import datetime


KNOWN_RANSOMWARE = {
    ".locked": "Generic/Unknown",
    ".enc": "Generic Encrypted",
    ".crypt": "CryptXXX",
    ".ryuk": "Ryuk",
    ".conti": "Conti",
    ".lockbit": "LockBit",
    ".blackcat": "BlackCat/ALPHV",
    ".hive": "Hive",
    ".cuba": "Cuba Ransomware",
}


def run(iris_client, case_id: int, alert: dict, notifier=None):
    """
    Автоматические действия при Ransomware:
    1. Идентификация семейства по расширению
    2. Чеклист немедленного реагирования
    3. Статус дедлайнов регуляторов
    """
    desc = alert.get("alert_description", "")
    family = _identify_family(desc)
    decryptor_available = _check_decryptor(family)

    content = (
        f"## Автоматическая оценка Ransomware\n\n"
        f"**Время:** {datetime.now().strftime('%d.%m.%Y %H:%M')} MSK\n\n"
        f"**Предполагаемое семейство:** {family}\n\n"
        f"**Публичный дешифратор:** {'✅ Возможно доступен (No More Ransom)' if decryptor_available else '❌ Не обнаружен'}\n\n"
        f"⚠️ **ВНИМАНИЕ:** Для политически-мотивированных атак дешифратор может отсутствовать даже при выплате.\n\n"
        f"## Немедленные действия (CHECKLIST)\n\n"
        f"- [ ] Изолировать ВСЕ заражённые хосты от сети\n"
        f"- [ ] ОСТАНОВИТЬ задания резервного копирования\n"
        f"- [ ] Отключить VPN-доступ\n"
        f"- [ ] Сохранить RAM-дамп Patient Zero\n"
        f"- [ ] Проверить целостность offline-бэкапов\n"
        f"- [ ] НЕ перезагружать системы без согласования с IR-командой\n\n"
        f"## Вектор входа (для проверки)\n\n"
        f"- [ ] RDP brute-force (EventID 4625 — >10 неудач с внешнего IP)\n"
        f"- [ ] Фишинговое письмо (проверить почтовые логи)\n"
        f"- [ ] Уязвимость VPN/периметра (проверить патч-статус)\n"
        f"- [ ] Скомпрометированные credentials (Dark Web мониторинг)\n"
    )
    iris_client.add_note(case_id, "Автоматизация", "[AUTO] Оценка Ransomware", content)

    compliance_content = (
        f"## Регуляторные дедлайны (КИИ — 187-ФЗ)\n\n"
        f"| Регулятор | Срок | Инициировано | Статус |\n"
        f"|---|---|---|---|\n"
        f"| НКЦКИ | ≤ 3 ч. | {datetime.now().strftime('%H:%M %d.%m')} | ⬜ Ожидает |\n"
        f"| ФСТЭК | По запросу | — | ⬜ Ожидает |\n"
        f"| ФСБ (при необходимости) | По запросу | — | ⬜ Ожидает |\n"
    )
    iris_client.add_note(case_id, "Регуляторная отчётность", "[AUTO] Дедлайны 187-ФЗ", compliance_content)
    return {"status": "ok", "family": family, "decryptor": decryptor_available}


def _identify_family(description: str) -> str:
    for ext, name in KNOWN_RANSOMWARE.items():
        if ext in description.lower():
            return name
    return "Не определено — отправить в ID-Ransomware.malwarehunterteam.com"


def _check_decryptor(family: str) -> bool:
    no_decryptor = {"Generic/Unknown", "Не определено"}
    return family not in no_decryptor and not family.startswith("Не ")
