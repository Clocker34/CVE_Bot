# CVE Monitor Bot

Telegram-бот для мониторинга новых уязвимостей из базы NVD. Один из первых моих проектов в направлении ИБ.

Идея простая — вместо того чтобы вручную заходить на nvd.nist.gov, бот сам забирает свежие CVE и присылает сводку в Telegram. Можно фильтровать по критичности или ключевому слову.

## Команды

- `/scan` — свежие уязвимости за последние 24 часа
- `/critical` — только CVSS ≥ 9.0
- `/filter <слово>` — поиск по названию (например `/filter apache`)
- `/status` — когда был последний запрос

## Запуск

Через Docker:

```bash
cp .env.example .env
docker-compose up -d
```

Или напрямую:

```bash
pip install -r requirements.txt
python cve_bot.py
```

## Настройка .env

TELEGRAM_TOKEN=токен от @BotFather

TELEGRAM_CHAT_ID=твой ID от @userinfobot

CVSS_THRESHOLD=7.0

HOURS_BACK=24