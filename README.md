# CheckVPN

CheckVPN — это self-hosted веб-сервис для хранения конфигов VPN/Proxy и запуска проверок доступности по протоколам.

## Что уже умеет MVP

- web UI на FastAPI
- авторизация через SQLite (`users` + `user_sessions`)
- хранение целей в SQLite
- ручной запуск проверки
- отображение последнего результата
- парсинг:
  - WireGuard
  - AmneziaWG
  - VLESS URI
  - Telegram proxy URI
- проверки:
  - `vless` — deep-check через временный local `xray`: реальный outbound HTTP/IP через proxy
  - `tg-proxy` — TCP reachability до endpoint
  - `wireguard` — реальный temporary tunnel probe: handshake + DNS + внешний HTTP/IP через tunnel
  - `amneziawg` — реальный temporary tunnel probe: handshake + DNS + внешний HTTP/IP через tunnel

## Ограничения текущей версии

- Для `wireguard` / `amneziawg` сервису нужны контейнерные привилегии `NET_ADMIN`.
- Для `amneziawg` контейнеру также нужен доступ к `/dev/net/tun`.
- Для `vless` deep-check внутри контейнера должен быть доступен `xray`.
- `vless` deep-check сейчас ориентирован на реальные outbound-проверки через временный local SOCKS proxy от `xray`; на практике это даёт полезную проверку для `reality/tcp`, `tls/tcp` и базовых `ws`-конфигов.
- Проверка отражает **реальную пригодность конфига**: если handshake проходит, но внешний HTTP через tunnel/proxy не работает, статус будет `OFFLINE` на соответствующей стадии, а не ложный `ONLINE`.
- Внешние VPN-серверы сервис сам не меняет — он только проверяет доступность и пригодность конфигов.

## Локальный запуск

```bash
cp .env.example .env
# задай свои CHECKVPN_ADMIN_USERNAME / CHECKVPN_ADMIN_PASSWORD
uv run uvicorn app.main:app --reload --port 8098
```

## Тесты

```bash
uv run --group dev pytest -q
```

## Docker

```bash
cp .env.example .env
# поменяй пароль администратора
docker compose up -d --build
```

Открыть:
- `http://127.0.0.1:8099/`
- `http://127.0.0.1:8099/health`

## Авторизация

При старте приложение берёт bootstrap-учётку из переменных:

- `CHECKVPN_ADMIN_USERNAME`
- `CHECKVPN_ADMIN_PASSWORD`

Пользователь хранится в SQLite в виде password hash, а сессии — в таблице `user_sessions`.

## Структура

- `app/main.py` — FastAPI app + login/session flow
- `app/models.py` — SQLModel entities
- `app/auth.py` — password hashing + session token helpers
- `app/parsers.py` — protocol parsers
- `app/checkers/` — protocol-specific checkers
- `app/services.py` — orchestration/service layer

## Источники и основы

При реализации использовались и/или проверялись официальные и upstream-источники по WireGuard, Xray/VLESS, AmneziaWG и Telegram MTProto transport semantics. Следующим шагом добавим более глубокие runtime-checks на основе реальных конфигов.
