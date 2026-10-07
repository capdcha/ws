# WARP Server (upd 03-09-2026)

Автономный сервер для генерации WARP/AmneziaWG конфигураций.

## Архитектура

Сервис состоит из 4 компонентов:

| Компонент | Описание | Порт/Интервал |
|-----------|----------|---------------|
| **API Server** | HTTP API для получения конфигов | :8080 |
| **Worker Register** | Регистрация WARP identity в Cloudflare | каждые 5 мин |
| **Worker Scanner** | Сканирование WARP endpoints (UDP + WG handshake, RTT) | каждые 10 мин |
| **Worker Prober** | Проверка живости endpoints (реальный WG handshake) | каждые 2 мин |

Все компоненты используют общую SQLite БД (`warp.db`).

---

## Быстрый старт (Docker Compose)

### Предварительные требования

- Docker 20.10+
- Docker Compose 2.0+

### Запуск

```bash
# 1. Клонировать репозиторий
git clone https://github.com/deepinpoop/test.git
cd test

# 2. Запустить все сервисы
docker-compose up -d

# 3. Проверить статус
curl http://localhost:8080/health
# {"status":"ok"}

# 4. Получить готовый AmneziaWG конфиг
curl http://localhost:8080/config > warp.conf

# 5. Использовать конфиг в AmneziaWG / WireGuard клиенте
```

### Проверка работы воркеров

```bash
# Логи всех сервисов
docker-compose logs -f

# Только API
docker-compose logs -f api

# Только worker register
docker-compose logs -f worker-register

# Только worker scanner
docker-compose logs -f worker-scanner

# Только worker prober
docker-compose logs -f worker-prober
```

### Остановка

```bash
docker-compose down

# С удалением данных (БД)
docker-compose down -v
```

---

## Локальная разработка (без Docker)

### Предварительные требования

- Go 1.25+
- SQLite3

### Установка зависимостей

```bash
# В корне репозитория
go mod tidy
```

### Инициализация БД

```bash
# Создать таблицы
sqlite3 warp.db < schema.sql

# Проверить
sqlite3 warp.db ".tables"
# identities  endpoints  configs
```

### Сборка и запуск

```bash
# Сборка
go build ./cmd/server
go build ./cmd/worker

# Запуск API сервера (терминал 1)
./server

# Запуск worker register (терминал 2)
./worker register

# Запуск worker scanner (терминал 3)
./worker scan

# Запуск worker prober (терминал 4)
./worker probe
```

### Проверка работы

```bash
# Health check
curl http://localhost:8080/health

# Получить конфиг
curl http://localhost:8080/config > warp.conf

# Список identity
curl http://localhost:8080/api/identities

# Список живых endpoints
curl "http://localhost:8080/api/endpoints?alive=true"
```

---

## Переменные окружения

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| `DB_PATH` | Путь к SQLite БД | `warp.db` |
| `TARGET_COUNT` | Целевое кол-во identity в пуле | `10` |
| `INTERVAL` | Интервал запуска воркера | см. ниже |

Интервалы по умолчанию:
- `worker register`: 5m
- `worker scan`: 10m  
- `worker probe`: 2m

Переопределение через docker-compose.yml или при локальном запуске:
```bash
TARGET_COUNT=20 INTERVAL=2m ./worker register
```

---

## API Reference

### GET /health

Проверка состояния сервиса.

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

### GET /config

Получить готовый AmneziaWG конфиг.

Возвращает случайную identity + лучший по RTT endpoint.

```bash
curl http://localhost:8080/config
# [Interface]
# PrivateKey = ...
# Address = 10.2.0.x/32, 2606:4700:110::/128
# DNS = 1.1.1.1, 1.0.0.1
# Jc = 4
# Jmin = 40
# Jmax = 70
# H1 = 123456789
# H2 = 987654321
# H3 = 111222333
# H4 = 444555666
#
# [Peer]
# PublicKey = ...
# Endpoint = 162.159.192.1:500
# AllowedIPs = 0.0.0.0/0, ::/0
```

**Коды ответа:**
- `200` — конфиг в теле ответа (`text/plain`)
- `503` — нет доступных identity или endpoints

### GET /api/identities

Список всех зарегистрированных identity.

```bash
curl http://localhost:8080/api/identities
```

### GET /api/endpoints

Список endpoints, отсортированный по RTT (возрастание). Пустой ответ — `[]`, а не `null`.

- Без параметра — возвращаются **все** endpoints.
- С `alive=true` — только живые (успех-rate >= 50% или ещё не пробованные).

```bash
# все endpoints
curl http://localhost:8080/api/endpoints

# только живые
curl "http://localhost:8080/api/endpoints?alive=true"
```

---

## Принцип работы

### Протокол: почему UDP, а не TCP

WARP/WireGuard работает по **UDP**. WARP-эндпоинты ничего не слушают по TCP, поэтому TCP-соединения к ним всегда отбрасываются. Сканер и пробер используют реальный WireGuard handshake:

1. **Сканер** строит валидную датаграмму *handshake-initiation* из ключей identity и рассылает её по UDP на каждый кандидат (IP × порт). Ответ *handshake-response* или *cookie-reply* доказывает, что эндпоинт — живой WARP-сервер.
2. **Пробер** выполняет полный handshake: отправляет initiation, ждёт response и **криптографически проверяет** его (receiver index + MAC1). Это подтверждает живость endpoint, а не просто факт ICMP/UDP-ответа.
3. RTT замеряется от отправки initiation до получения валидного ответа.

Сканирование укладывается в ~60 секунд: вместо 141k долгих TCP-соединений с таймаутом endpoint-кандидаты быстро «забрасываются» initiation-датаграммами с пула из 256 UDP-сокетов, а ответы собираются асинхронно в коротком окне ожидания.

### Источники endpoints

1. **Статические сиды** (50 конфигов) — встроенные AmneziaWG конфиги WARP
2. **Динамический скан** — UDP ipscanner по префиксам Cloudflare (162.159.192.0/24, 188.114.96.0/24 и др.) × ~55 портов (WG handshake вместо TCP)
3. **Свежая регистрация** — X25519 keypair → POST https://api.cloudflareclient.com/v0a4471/reg → новый endpoint на каждую регистрацию
4. **Neighbor expansion** — расширение найденных IP соседями ±1..5

### Жизненный цикл

```
Worker Register:
  1. Проверяет кол-во identity в БД
  2. Если < TARGET_COUNT → регистрирует новую через Cloudflare API
  3. Сохраняет identity в БД

Worker Scanner:
  1. Берёт префиксы WARP + список портов + первую identity (ключи WARP-пира)
  2. Строит WireGuard handshake-initiation датаграмму
  3. Рассылает её по UDP (IP × порт) через пул из 256 сокетов (blast-send)
  4. Собирает ответы в окне ожидания: handshake-response / cookie-reply → endpoint жив
  5. Фиксирует RTT и сохраняет живые endpoints с RTT в БД

Worker Prober:
  1. Берёт alive endpoints из БД (успех-rate >= 50% или ещё не пробованные)
  2. Выполняет реальный WG handshake с первой доступной identity
  3. Обновляет метрики в БД (RTT при успехе, success/fail count)
  4. Удаляет endpoints с fail_count > 10
```

---

## Использование конфига

Полученный `warp.conf` — стандартный AmneziaWG конфиг.

### AmneziaVPN (Android / Windows / macOS / Linux)

1. Откройте AmneziaVPN
2. Импорт → Файл конфигурации → выберите `warp.conf`
3. Подключитесь

### WireGuard (native)

```bash
# Linux
sudo wg-quick up warp.conf

# Или через systemd
sudo cp warp.conf /etc/wireguard/warp.conf
sudo systemctl enable --now wg-quick@warp
```

### WireGuard App (iOS / Android)

1. Откройте приложение WireGuard
2. "+" → Импорт из файла → `warp.conf`
3. Включите туннель

---

## Troubleshooting

### 503 при получении /config

**Причина:** Нет identity или нет живых endpoints.

**Решение:**
```bash
# Проверить identity
curl http://localhost:8080/api/identities

# Проверить endpoints
curl "http://localhost:8080/api/endpoints?alive=true"

# Если пусто — подождите 1-2 минуты, пока worker register создаст identity
# и worker scanner найдёт endpoints
```

### Cloudflare возвращает 429 (Too Many Requests)

**Причина:** Слишком частые регистрации с одного IP.

**Решение:**
- Увеличьте интервал worker register: `INTERVAL=10m`
- Используйте прокси / другой IP для регистрации
- Worker register автоматически делает паузу между попытками

### Endpoints не находятся

**Причина:** WARP/WireGuard endpoints слушают только **UDP**, поэтому скан идёт по UDP датаграммами WG handshake, а не TCP-соединениями. Пустой результат — это сеть/файрвол, блокирующие исходящий UDP на WARP-порты, либо в БД нет ни одной identity (без ключей пира невозможно построить валидный handshake).

**Решение:**
- Проверьте, что скан-воркер завершает цикл: `docker-compose logs -f worker-scanner` (должна появиться строка `Scan complete: N endpoints found`), а также что есть identity (`curl http://localhost:8080/api/identities`)
- Пустой ответ `/api/endpoints` — это `[]` (эндпоинты ещё не найдены)
- Проверьте исходящий **UDP** на порты 500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886
  - `nc -uz 162.159.192.5 2408` (UDP) — должен проходить; TCP-тесты к WARP-портам ожидаемо «дропаются», это нормально
- Проверьте доступность api.cloudflareclient.com:443 (https)

### Конфиг не подключается

**Причина:** Endpoint недоступен / ключи не совпадают.

**Решение:**
- Получите новый конфиг: `curl http://localhost:8080/config > warp.conf`
- Проверьте, что endpoint жив: `curl "http://localhost:8080/api/endpoints?alive=true"`

---

## Тестирование

```bash
# Unit тесты (включая полноценный WireGuard handshake round-trip)
go test ./...

# E2E тест (требует Docker)
./tests/e2e_test.sh
```

E2E тест:
1. Поднимает docker-compose
2. Ждёт готовности API
3. Ждёт появления identity
4. Запрашивает /config
5. Проверяет наличие обязательных полей

---

## Структура проекта

```
.
├── cmd/
│   ├── server/          # HTTP API сервер
│   └── worker/          # Воркеры (register, scan, probe)
├── internal/
│   ├── api/             # HTTP handlers
│   ├── crypto/          # X25519 keypair генерация
│   ├── db/              # SQLite операции
│   ├── scanner/         # IP scanner (UDP), WireGuard handshake, WG probe
│   └── warp/            # WARP регистрация, конфиг генерация
├── tests/
│   └── e2e_test.sh      # E2E тест
├── schema.sql           # Схема БД
├── Dockerfile           # Мультистадия сборка
├── docker-compose.yml   # 4 сервиса
├── tasks-bash.sh        # Bash-скрипт задач
├── tasks-prompts.md     # Промпты для агентов
└── warp-server-plan.md  # План задач
```

---

## Лицензия

MIT
