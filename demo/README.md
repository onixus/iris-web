# Демо-датасеты для DFIR IRIS

Набор тестовых данных на русском языке для демонстрации возможностей платформы [DFIR IRIS](https://github.com/dfir-iris/iris-web).

## Структура

| Файл | Описание |
|---|---|
| `clients.csv` | Клиенты / организации |
| `cases.csv` | Кейсы (дела) |
| `alerts.csv` | Алерты из источников |
| `iocs.csv` | Индикаторы компрометации (IOC) |
| `assets.csv` | Активы (хосты) |
| `timeline.csv` | События таймлайна |
| `tasks.csv` | Задачи по кейсу |
| `evidence.csv` | Доказательства (улики) |
| `notes.csv` | Заметки по кейсам |

## Как использовать

### Через REST API (Python)
```python
import requests, csv

BASE_URL = "https://<your-iris-host>"
HEADERS = {"Authorization": "Bearer <API_TOKEN>", "Content-Type": "application/json"}

# Пример: создать кейс
with open('demo/cases.csv') as f:
    for row in csv.DictReader(f):
        requests.post(f"{BASE_URL}/api/v2/cases", json=row, headers=HEADERS)
```

### Через IRIS Web UI
1. Перейти в `Advanced → Import`
2. Выбрать CSV-файл нужного типа
3. Сопоставить поля и импортировать

## Сценарий демо

Сценарий основан на атаке шифровальщика **LockBit 3.0** на промышленное предприятие «РосТехПром»:
- Первоначальный доступ через фишинговое письмо
- Кража учётных данных (Mimikatz / LSASS dump)
- Боковое перемещение через PsExec
- Закрепление через реестр (Cobalt Strike)
- Шифрование 47 хостов
- Параллельный кейс: компрометация учётной записи топ-менеджера

## Регуляторный контекст
- **187-ФЗ** (КИИ): уведомление НКЦКИ в течение 24 ч
- **152-ФЗ** (ПДн): уведомление Роскомнадзора в течение 72 ч при утечке
