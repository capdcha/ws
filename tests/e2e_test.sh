#!/bin/bash
set -euo pipefail

echo "Starting E2E test..."

cd "$(dirname "$0")/.."

# Запуск
docker-compose up -d
trap "docker-compose down -v" EXIT

# Ожидание готовности
for i in {1..30}; do
  if curl -sf http://localhost:8080/health > /dev/null; then
    echo "API ready"
    break
  fi
  sleep 2
done

# Ждём появления identity (воркер должен зарегистрировать)
sleep 60

# Запрос конфига
curl -f http://localhost:8080/config -o /tmp/test_warp.conf
grep -q "PrivateKey" /tmp/test_warp.conf
grep -q "Endpoint" /tmp/test_warp.conf

echo "✓ E2E test passed"
