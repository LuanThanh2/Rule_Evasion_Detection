#!/usr/bin/env bash
set -euo pipefail

# Lightweight terminal monitor for RED demo indices.
#
# Usage:
#   cd ~/KLTN/KLTN/Rule_Evasion_Detection/rule_evasion_detection
#   ./demo/monitor.sh
#   ./demo/monitor.sh 5

INTERVAL="${1:-10}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

ES_HOST="${ES_HOST:-http://10.10.20.100:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASSWORD="${ES_PASSWORD:-}"
ES_RED_INDEX="${ES_RED_INDEX:-red-alerts}"
ES_AI_INDEX="${ES_AI_INDEX:-ai-investigations}"

if [[ -z "$ES_PASSWORD" ]]; then
  echo "ES_PASSWORD is empty. Set it in .env first." >&2
  exit 1
fi

RED=$'\033[31m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BLUE=$'\033[34m'
RESET=$'\033[0m'

es_post() {
  local index="$1"
  local body="$2"
  curl -s -u "${ES_USER}:${ES_PASSWORD}" \
    -H "Content-Type: application/json" \
    "${ES_HOST%/}/${index}/_search" \
    -d "$body"
}

count_index() {
  local index="$1"
  curl -s -u "${ES_USER}:${ES_PASSWORD}" "${ES_HOST%/}/${index}/_count" \
    | jq -r '.count // 0'
}

show_latest_red() {
  local body='{
    "size": 5,
    "sort": [{"@timestamp": "desc"}],
    "_source": ["@timestamp", "host.name", "red.detection_score", "red.top_rule", "red.command_line"]
  }'
  es_post "$ES_RED_INDEX" "$body" | jq -r '
    .hits.hits[]._source
    | [
        ."@timestamp",
        (."host.name" // "unknown"),
        (."red.detection_score" // "n/a"),
        (."red.top_rule" // "n/a"),
        ((."red.command_line" // "") | gsub("[\r\n\t]+"; " ") | .[0:110])
      ]
    | @tsv'
}

show_latest_ai() {
  local body='{
    "size": 5,
    "sort": [{"timestamp": "desc"}],
    "_source": ["timestamp", "triage.severity", "triage.confidence", "trigger_alert.host.name", "report.title_vi", "estimated_cost_usd"]
  }'
  es_post "$ES_AI_INDEX" "$body" | jq -r '
    .hits.hits[]._source
    | [
        (.timestamp // "n/a"),
        (.triage.severity // "n/a"),
        (.triage.confidence // "n/a"),
        (.trigger_alert.host.name // "unknown"),
        (.estimated_cost_usd // "n/a"),
        ((.report.title_vi // "") | gsub("[\r\n\t]+"; " ") | .[0:100])
      ]
    | @tsv'
}

while true; do
  clear
  echo "${BLUE}RED-AI SOC demo monitor${RESET}  $(date -Is)"
  echo "ES: ${ES_HOST} | red=${ES_RED_INDEX} | ai=${ES_AI_INDEX}"
  echo

  red_count="$(count_index "$ES_RED_INDEX" 2>/dev/null || echo 0)"
  ai_count="$(count_index "$ES_AI_INDEX" 2>/dev/null || echo 0)"
  echo "${GREEN}Counts${RESET}: red-alerts=${red_count}  ai-investigations=${ai_count}"
  echo

  echo "${YELLOW}Latest RED alerts${RESET}"
  printf "timestamp\thost\tscore\ttop_rule\tcommand\n"
  show_latest_red 2>/dev/null || true
  echo

  echo "${YELLOW}Latest AI investigations${RESET}"
  printf "timestamp\tseverity\tconfidence\thost\tcost_usd\ttitle\n"
  show_latest_ai 2>/dev/null || true
  echo

  echo "Refresh every ${INTERVAL}s. Ctrl+C to stop."
  sleep "$INTERVAL"
done
