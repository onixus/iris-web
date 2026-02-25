"""Playbook: Утечка данных / Data Breach — DFIR-IRIS RU"""

from datetime import datetime, timedelta


def run(iris_client, case_id: int, alert: dict, notifier=None):
    """
    Автоматические действия при утечке данных:
    1. Классификация типа данных
    2. Таблица регуляторных дедлайнов
    3. Чеклист первичных действий
    """
    desc = alert.get("alert_description", "")
    data_category = _classify_data(desc)
    now = datetime.now()
    rkn_primary = now + timedelta(hours=24)
    rkn_extended = now + timedelta(hours=72)

    content = (
        f"## Автоматическая оценка утечки данных\n\n"
        f"**Время:** {now.strftime('%d.%m.%Y %H:%M')} MSK\n\n"
        f"**Категория данных (авто):** {data_category}\n\n"
        f"## Регуляторные дедлайны\n\n"
        f"| Регулятор | Тип уведомления | Дедлайн | Статус |\n"
        f"|---|---|---|---|\n"
        f"| НКЦКИ (187-ФЗ/КИИ) | Первичное | {now + timedelta(hours=3):%H:%M %d.%m} | ⬜ |\n"
        f"| РКН (149-ФЗ/ПДн) | Первичное | {rkn_primary:%H:%M %d.%m} | ⬜ |\n"
        f"| РКН (149-ФЗ/ПДн) | Расширенное | {rkn_extended:%H:%M %d.%m} | ⬜ |\n\n"
        f"## Первичный чеклист\n\n"
        f"- [ ] Подтвердить факт утечки (DLP / SIEM / TI мониторинг)\n"
        f"- [ ] Определить объём и категорию данных\n"
        f"- [ ] Локализовать источник утечки (инсайдер / внешняя атака / misconfiguration)\n"
        f"- [ ] Отозвать скомпрометированные доступы\n"
        f"- [ ] Задействовать DPO (ответственного за ПДн)\n"
        f"- [ ] Проверить публикации в Telegram/даркнет (F.A.C.C.T. / BI.ZONE)\n\n"
        f"## Контакты регуляторов\n\n"
        f"- **НКЦКИ:** https://cert.gov.ru | +7 (499) 245-06-54\n"
        f"- **РКН:** https://rkn.gov.ru/personal-data/p1/\n"
    )
    iris_client.add_note(case_id, "Автоматизация", "[AUTO] Оценка утечки данных", content)
    return {"status": "ok", "data_category": data_category}


def _classify_data(description: str) -> str:
    desc = description.lower()
    if any(k in desc for k in ["персональн", "пдн", "personal", "паспорт", "снилс", "инн"]):
        return "Персональные данные (ПДн) — уведомление РКН обязательно"
    if any(k in desc for k in ["гос", "секрет", "конфиденц", "дсп"]):
        return "Государственная тайна / ДСП — привлечь ФСБ/ФСТЭК"
    if any(k in desc for k in ["финанс", "карт", "payment", "банк"]):
        return "Финансовые данные — уведомить ЦБ РФ при необходимости"
    if any(k in desc for k in ["коммерч", "trade secret", "ноу-хау"]):
        return "Коммерческая тайна"
    return "Не определена (требуется ручная классификация)"
