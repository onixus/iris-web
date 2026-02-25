# ELK-логи для демо IRIS

Файлы в формате **NDJSON** (Newline Delimited JSON) — каждая строка является самостоятельным JSON-документом, совместимым с форматом Elasticsearch / ECS (Elastic Common Schema).

## Структура

| Файл | Источник | Индекс ELK | Событий |
|---|---|---|---|
| `sysmon.ndjson` | Sysmon (Windows) | `winlogbeat-*` | 15 |
| `windows_security.ndjson` | Windows Security EventLog | `winlogbeat-*` | 10 |
| `ngfw_paloalto.ndjson` | Palo Alto NGFW | `filebeat-*` | 8 |
| `powershell.ndjson` | PowerShell ScriptBlock | `winlogbeat-*` | 6 |
| `edr_crowdstrike.ndjson` | CrowdStrike Falcon (симулированный) | `filebeat-*` | 7 |

## Как импортировать в ELK

### Через Kibana Dev Tools
```bash
# Bulk import
curl -X POST "http://localhost:9200/_bulk" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @demo/logs/sysmon.ndjson
```

### Через elasticdump
```bash
elasticdump \
  --input=demo/logs/sysmon.ndjson \
  --output=http://localhost:9200/winlogbeat-demo-2025.11.14 \
  --type=data
```

### Через Logstash
Используй `input { file { path => "demo/logs/*.ndjson" codec => "json_lines" } }`

## Связь с IRIS-датасетом

Все события привязаны к кейсу `CASE-2025-001` (LockBit 3.0) и содержат те же IOC, активы и временны́е метки, что и файлы в `demo/*.csv`.
