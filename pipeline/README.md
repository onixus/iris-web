# Pipeline реагирования на инциденты — DFIR-IRIS RU

Автоматизированный pipeline обработки инцидентов для DFIR-IRIS с поддержкой российских регуляторных требований.

## Архитектура

```
 SIEM/EDR/WAF
     │
     ▼
 [Alert Ingest]  ◄──── Wazuh / PT MaxPatrol / QRadar
     │
     ▼
 [pipeline.py]   ◄──── DFIR-IRIS Webhook Events
     │
     ├─► Classify    (DDoS / APT / Ransomware / Breach)
     ├─► Enrich      (VirusTotal / PT TI / BI.ZONE / ANY.RUN)
     ├─► Create Case (DFIR-IRIS API — нужный шаблон RU)
     ├─► Add IOCs    (автоматически из алерта)
     ├─► Notify      (Telegram SOC-бот / Mattermost)
     └─► Report      (ГосСОПКА / РКН таймер)
```

## Файлы

| Файл | Назначение |
|---|---|
| `pipeline.py` | Основной скрипт pipeline |
| `playbooks/ddos.py` | Playbook: DDoS-атака |
| `playbooks/apt_phishing.py` | Playbook: APT фишинг |
| `playbooks/ransomware.py` | Playbook: Шифровальщик |
| `playbooks/data_breach.py` | Playbook: Утечка данных |
| `config/webhook_iris.json` | Конфиг Webhook-модуля IRIS |
| `config/pipeline_config.yaml` | Конфигурация pipeline |

## Быстрый старт

```bash
pip install -r requirements.txt
cp config/pipeline_config.yaml.example config/pipeline_config.yaml
# Заполнить IRIS_URL, IRIS_API_KEY, TG_BOT_TOKEN
python pipeline.py
```

## Переменные окружения

```bash
export IRIS_URL="https://your-iris-instance"
export IRIS_API_KEY="your-api-key"
export VT_API_KEY="virustotal-key"          # опционально
export TG_BOT_TOKEN="telegram-bot-token"    # для уведомлений
export TG_CHAT_ID="-100xxxxxxxxx"           # SOC чат
```
