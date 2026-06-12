# CVE Monitor Bot

![CI](https://github.com/Clocker34/CVE_Bot/actions/workflows/ci.yml/badge.svg)

Telegram-бот для мониторинга новых уязвимостей из базы NVD. Один из первых моих проектов в направлении ИБ.

Идея простая — вместо того чтобы вручную заходить на nvd.nist.gov, бот сам забирает свежие CVE и присылает сводку в Telegram. Можно фильтровать по критичности или ключевому слову, а также включить авто-уведомления — тогда бот сам пришлёт новые критичные CVE без всяких команд.

Каждая CVE дополнительно обогащается:
- 🚨 **CISA KEV** — пометка, если уязвимость в каталоге активно эксплуатируемых;
- 📈 **EPSS** — вероятность эксплуатации в ближайшие 30 дней.

KEV-уязвимости всегда показываются первыми.

## Команды

- `/scan` — свежие уязвимости за последние 24 часа (CVSS ≥ порога)
- `/critical` — только CVSS ≥ 9.0
- `/filter <слово>` — поиск по всей базе NVD (например `/filter apache`)
- `/cve <id>` — карточка по идентификатору (например `/cve CVE-2021-44228`)
- `/status` — порог, интервал авто-проверки и время последнего запроса

## Авто-уведомления

Если в `.env` задать `TELEGRAM_CHAT_ID` и `CHECK_INTERVAL_MIN > 0`, бот будет
периодически проверять NVD и сам присылать **только новые** критичные CVE
(дедупликация по `seen_cves.json`, чтобы не слать одно и то же дважды).

## Запуск

Через Docker:

```bash
cp .env.example .env   # заполни TELEGRAM_TOKEN
docker-compose up -d
```

Или напрямую:

```bash
pip install -r requirements.txt
python cve_bot.py
```

## Настройка .env

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `TELEGRAM_TOKEN` | токен от [@BotFather](https://t.me/BotFather) | — (обязательно) |
| `TELEGRAM_CHAT_ID` | твой ID от [@userinfobot](https://t.me/userinfobot), для авто-уведомлений | — |
| `CVSS_THRESHOLD` | порог критичности для `/scan` и авто-уведомлений | `7.0` |
| `HOURS_BACK` | глубина поиска свежих CVE, часов | `24` |
| `CHECK_INTERVAL_MIN` | интервал авто-проверки, минут (`0` — выключено) | `0` |
| `NVD_API_KEY` | [ключ NVD](https://nvd.nist.gov/developers/request-an-api-key) — лимит 5→50 запросов/30с | — |

Полный пример — в `.env.example`.

## Тесты

```bash
pip install -r requirements-dev.txt
pytest -q
```

Те же проверки гоняются в GitHub Actions на каждый push и pull request
(см. `.github/workflows/ci.yml`).
