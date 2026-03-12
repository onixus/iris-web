#!/usr/bin/env bash
# ============================================================
# import_elk.sh — загрузка NDJSON-логов в Elasticsearch
# ============================================================
# Использование:
#   chmod +x demo/import_elk.sh
#   ./demo/import_elk.sh http://localhost:9200
# ============================================================

ES_URL=${1:-"http://localhost:9200"}
LOGS_DIR="$(dirname "$0")/logs"

if [ ! -d "$LOGS_DIR" ]; then
  echo "[ERR] Директория $LOGS_DIR не найдена"
  exit 1
fi

echo "================================================"
echo " IRIS Demo — Bulk import ELK logs"
echo " Elasticsearch: $ES_URL"
echo "================================================"

for f in "$LOGS_DIR"/*.ndjson; do
  fname=$(basename "$f")
  echo -n "→ $fname ... "
  result=$(curl -s -o /tmp/elk_resp.json -w "%{http_code}" \
    -X POST "$ES_URL/_bulk" \
    -H "Content-Type: application/x-ndjson" \
    --data-binary @"$f")
  errors=$(python3 -c "import json,sys; d=json.load(open('/tmp/elk_resp.json')); print(d.get('errors','?'))" 2>/dev/null)
  items=$(python3 -c  "import json,sys; d=json.load(open('/tmp/elk_resp.json')); print(len(d.get('items',[])))" 2>/dev/null)
  echo "HTTP $result | errors=$errors | docs=$items"
done

echo ""
echo "Проверить индексы:"
echo "  curl $ES_URL/_cat/indices?v"
echo ""
echo "Открыть в Kibana:"
echo "  Management → Stack Management → Index Patterns → Create"
echo "  Паттерны: winlogbeat-demo-*, filebeat-ngfw-*, filebeat-edr-*"
