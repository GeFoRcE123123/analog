#!/bin/bash
# Демонстрация работы API сервиса через HTTP запросы

echo "=========================================="
echo "Демонстрация Security API"
echo "=========================================="
echo ""

API_URL="http://localhost:8000"

# Проверка доступности API
echo "1. Проверка доступности API..."
curl -s "$API_URL/health" | jq '.' || echo "API недоступен. Убедитесь, что сервер запущен."
echo ""

# Получение статуса GPU
echo "2. Статус GPU..."
curl -s "$API_URL/gpu/status" | jq '.'
echo ""

# AI анализ уязвимости
echo "3. AI анализ уязвимости (TensorFlow)..."
curl -s -X POST "$API_URL/security/ai/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-DEMO-001",
    "description": "TensorFlow contains a vulnerability that allows remote code execution through malicious model files. This affects TensorFlow versions 2.0 through 2.15.",
    "cwe_ids": ["CWE-502"],
    "cvss_score": 9.8
  }' | jq '.'
echo ""

# AI анализ уязвимости PyTorch
echo "4. AI анализ уязвимости (PyTorch)..."
curl -s -X POST "$API_URL/security/ai/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-DEMO-002",
    "description": "PyTorch machine learning framework vulnerable to deserialization attack. An attacker can execute arbitrary code by providing a malicious pickle file.",
    "cwe_ids": ["CWE-502"],
    "cvss_score": 8.8
  }' | jq '.'
echo ""

# Пакетный анализ
echo "5. Пакетный AI анализ..."
curl -s -X POST "$API_URL/security/ai/batch-analyze" \
  -H "Content-Type: application/json" \
  -d '["CVE-2024-DEMO-001", "CVE-2024-DEMO-002"]' | jq '.'
echo ""

# Статистика AI анализа
echo "6. Статистика AI анализа..."
curl -s "$API_URL/security/ai/stats" | jq '.'
echo ""

echo "=========================================="
echo "Демонстрация завершена"
echo "=========================================="
