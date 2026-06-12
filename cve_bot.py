"""
CVE Monitor Bot — интерактивный Telegram-бот для мониторинга уязвимостей.

Команды:
  /start   — приветствие
  /help    — список команд
  /scan    — свежие CVE за последние 24ч
  /critical — только CVSS ≥ 9.0
  /filter <keyword> — CVE по ключевому слову (напр. /filter apache)
  /status  — информация о боте

Авто-уведомления: если в .env заданы TELEGRAM_CHAT_ID и CHECK_INTERVAL_MIN > 0,
бот периодически проверяет NVD и сам присылает новые критичные CVE.

Требования: pip install "python-telegram-bot[job-queue]" requests python-dotenv
"""

import os
import re
import html
import json
import time
import logging
import asyncio
from pathlib import Path
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes
)
from telegram.constants import ParseMode

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
CVSS_THRESHOLD = float(os.getenv("CVSS_THRESHOLD", "7.0"))
HOURS_BACK = int(os.getenv("HOURS_BACK", "24"))
NVD_API_KEY = os.getenv("NVD_API_KEY")
# Интервал авто-проверки в минутах (0 — выключить авто-уведомления).
CHECK_INTERVAL_MIN = int(os.getenv("CHECK_INTERVAL_MIN", "0"))

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# CISA «Known Exploited Vulnerabilities» — каталог активно эксплуатируемых CVE.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# EPSS — вероятность эксплуатации CVE в ближайшие 30 дней.
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Файл с уже отправленными CVE — чтобы не слать одно и то же дважды.
SEEN_FILE = Path(os.getenv("SEEN_FILE", "seen_cves.json"))
SEEN_LIMIT = 10000  # сколько id храним, чтобы файл не рос бесконечно

# Кэш каталога KEV (обновляем не чаще раза в 6ч).
_kev_cache: dict = {"ids": set(), "ts": 0.0}
KEV_TTL = 6 * 3600

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cve_bot")

# Время последнего сканирования
last_scan_time: datetime | None = None


# ── NVD ────────────────────────────────────────────────────────────────────────

def _nvd_get(params: dict) -> list[dict]:
    """Запрос к NVD с API-ключом, retry-бэкоффом и пагинацией по totalResults."""
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    results: list[dict] = []
    start_index = 0

    while True:
        page_params = {**params, "startIndex": start_index, "resultsPerPage": 2000}
        data = None
        for attempt in range(1, 4):
            try:
                resp = requests.get(
                    NVD_API_URL, params=page_params, headers=headers, timeout=30
                )
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.RequestException as e:
                wait = 6 * attempt
                logger.warning("NVD попытка %d/3 не удалась: %s; повтор через %dс", attempt, e, wait)
                time.sleep(wait)
        if data is None:
            logger.error("NVD: запрос провалился после 3 попыток (startIndex=%d)", start_index)
            break

        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)
        total = data.get("totalResults", 0)
        start_index += len(vulns)
        if not vulns or start_index >= total:
            break

    return results


def fetch_recent_cves(hours: int = 24) -> list[dict]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    return _nvd_get({
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
    })


def fetch_cves_by_keyword(keyword: str) -> list[dict]:
    """Поиск по всей базе NVD (а не только за HOURS_BACK) через keywordSearch."""
    return _nvd_get({"keywordSearch": keyword})


def fetch_cve_by_id(cve_id: str) -> list[dict]:
    """Одна конкретная CVE по идентификатору."""
    return _nvd_get({"cveId": cve_id})


# ── Обогащение: CISA KEV + EPSS ─────────────────────────────────────────────────

def get_kev_ids() -> set[str]:
    """Множество CVE из каталога CISA KEV (с кэшем на KEV_TTL секунд)."""
    now = time.time()
    if _kev_cache["ids"] and now - _kev_cache["ts"] < KEV_TTL:
        return _kev_cache["ids"]
    try:
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        ids = {v["cveID"] for v in resp.json().get("vulnerabilities", [])}
        _kev_cache["ids"], _kev_cache["ts"] = ids, now
        logger.info("KEV-каталог обновлён: %d записей", len(ids))
    except (requests.RequestException, ValueError, KeyError) as e:
        logger.warning("KEV: не удалось загрузить каталог: %s", e)
    return _kev_cache["ids"]


def get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """EPSS-вероятности для списка CVE (батчами по 100)."""
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i:i + 100]
        try:
            resp = requests.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                scores[row["cve"]] = float(row["epss"])
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.warning("EPSS: ошибка запроса: %s", e)
    return scores


def enrich_cves(cves: list[dict]) -> None:
    """Помечает CVE флагом KEV и EPSS-вероятностью (in-place)."""
    if not cves:
        return
    kev = get_kev_ids()
    epss = get_epss_scores([c["id"] for c in cves])
    for c in cves:
        c["kev"] = c["id"] in kev
        c["epss"] = epss.get(c["id"])


def parse_cve(item: dict) -> dict | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "N/A")

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description"
    )

    metrics = cve.get("metrics", {})
    score = None
    severity = "оценка ожидается"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "N/A")
            break

    # CVE без CVSS (статус Awaiting Analysis) не отбрасываем — это самые свежие.
    return {
        "id": cve_id,
        "score": score,
        "severity": severity,
        "description": description[:250] + ("..." if len(description) > 250 else ""),
        "published": cve.get("published", "")[:10],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "raw_description": description.lower(),
    }


# ── Дедупликация для авто-уведомлений ───────────────────────────────────────────

def load_seen() -> set[str]:
    """Множество уже отправленных CVE-id (из JSON-файла)."""
    try:
        return set(json.loads(SEEN_FILE.read_text(encoding="utf-8")))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def save_seen(ids: set[str]) -> None:
    # сортировка по id ≈ хронологическая (CVE-ГОД-НОМЕР), храним последние SEEN_LIMIT.
    trimmed = sorted(ids)[-SEEN_LIMIT:]
    SEEN_FILE.write_text(json.dumps(trimmed), encoding="utf-8")


# ── Форматирование ─────────────────────────────────────────────────────────────

def format_cve_list(cves: list[dict], title: str, max_items: int = 8) -> list[str]:
    """Возвращает список сообщений (разбитых по 4000 символов)."""
    if not cves:
        return [f"✅ <b>{title}</b>\n\nУязвимостей не найдено."]

    # Сортировка: сначала активно эксплуатируемые (KEV), потом по CVSS, потом по EPSS.
    cves = sorted(
        cves,
        key=lambda x: (
            x.get("kev", False),
            x["score"] if x["score"] is not None else -1.0,
            x.get("epss") or 0.0,
        ),
        reverse=True,
    )
    lines = [f"🔎 <b>{title}</b>\nНайдено: <b>{len(cves)}</b>\n"]

    for cve in cves[:max_items]:
        score = cve["score"]
        if score is None:
            emoji, score_text = "⚪", "оценка ожидается"
        else:
            emoji = "🔴" if score >= 9.0 else "🟠"
            score_text = f"<b>{score}</b> ({cve['severity']})"
        # Описание из NVD может содержать <, >, & — экранируем, иначе Telegram не распарсит HTML.
        description = html.escape(cve["description"])
        badges = ""
        if cve.get("kev"):
            badges += "🚨 <b>CISA KEV</b> — активно эксплуатируется\n"
        if cve.get("epss") is not None:
            badges += f"📈 EPSS: {cve['epss']:.1%}\n"
        lines.append(
            f"{emoji} <b>{cve['id']}</b> | CVSS: {score_text}\n"
            f"{badges}"
            f"📅 {cve['published']}\n"
            f"📝 {description}\n"
            f"🔗 <a href='{cve['url']}'>Подробнее</a>\n"
        )

    if len(cves) > max_items:
        lines.append(f"<i>...и ещё {len(cves) - max_items} уязвимостей</i>")

    full = "\n".join(lines)
    # Разбиваем на части если > 4000 символов
    parts, current = [], ""
    for line in full.split("\n"):
        if len(current) + len(line) + 1 > 4000:
            parts.append(current.rstrip())
            current = line + "\n"
        else:
            current += line + "\n"
    if current.strip():
        parts.append(current.rstrip())
    return parts


async def send_parts(update: Update, parts: list[str]) -> None:
    """Отправляем все части сообщения."""
    for part in parts:
        await update.message.reply_text(
            part,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )


# ── Команды ────────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [
            InlineKeyboardButton("🔍 Сканировать", callback_data="scan"),
            InlineKeyboardButton("🔴 Только CRITICAL", callback_data="critical"),
        ],
        [
            InlineKeyboardButton("📊 Статус", callback_data="status"),
            InlineKeyboardButton("❓ Помощь", callback_data="help"),
        ],
    ]
    await update.message.reply_text(
        "👋 <b>CVE Monitor Bot</b>\n\n"
        "Мониторинг критических уязвимостей из базы NVD.\n\n"
        "Выбери действие или используй команды:",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "📋 <b>Команды бота:</b>\n\n"
        "/scan — свежие CVE за последние 24ч (CVSS ≥ 7.0)\n"
        "/critical — только CVSS ≥ 9.0\n"
        "/filter &lt;слово&gt; — поиск по всей базе NVD\n"
        "  пример: <code>/filter apache</code>\n"
        "/cve &lt;id&gt; — карточка по идентификатору\n"
        "  пример: <code>/cve CVE-2021-44228</code>\n"
        "/status — статистика и время последнего скана\n"
        "/help — эта справка\n\n"
        "🚨 — активно эксплуатируется (CISA KEV), 📈 — EPSS-вероятность"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global last_scan_time
    await update.message.reply_text("⏳ Запрашиваю CVE за последние 24ч...")

    raw = await asyncio.to_thread(fetch_recent_cves, HOURS_BACK)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    # Показываем свежие CVE выше порога + ещё не оценённые (самые новые).
    critical = [c for c in parsed if c["score"] is None or c["score"] >= CVSS_THRESHOLD]
    await asyncio.to_thread(enrich_cves, critical)

    last_scan_time = datetime.now(timezone.utc)
    parts = format_cve_list(critical, f"CVE за 24ч — CVSS ≥ {CVSS_THRESHOLD}")
    await send_parts(update, parts)


async def cmd_critical(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global last_scan_time
    await update.message.reply_text("⏳ Ищу только CRITICAL (CVSS ≥ 9.0)...")

    raw = await asyncio.to_thread(fetch_recent_cves, HOURS_BACK)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    critical = [c for c in parsed if c["score"] is not None and c["score"] >= 9.0]
    await asyncio.to_thread(enrich_cves, critical)

    last_scan_time = datetime.now(timezone.utc)
    parts = format_cve_list(critical, "CRITICAL уязвимости (CVSS ≥ 9.0)")
    await send_parts(update, parts)


async def cmd_filter(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global last_scan_time

    if not context.args:
        await update.message.reply_text(
            "⚠️ Укажи ключевое слово. Пример: <code>/filter apache</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    keyword = " ".join(context.args)
    safe_keyword = html.escape(keyword)
    await update.message.reply_text(
        f"⏳ Ищу CVE по запросу: <code>{safe_keyword}</code>...", parse_mode=ParseMode.HTML
    )

    raw = await asyncio.to_thread(fetch_cves_by_keyword, keyword)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    filtered = [c for c in parsed if c["score"] is None or c["score"] >= CVSS_THRESHOLD]
    await asyncio.to_thread(enrich_cves, filtered)

    last_scan_time = datetime.now(timezone.utc)
    parts = format_cve_list(filtered, f"CVE по запросу «{safe_keyword}»")
    await send_parts(update, parts)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if last_scan_time:
        delta = datetime.now(timezone.utc) - last_scan_time
        minutes = int(delta.total_seconds() // 60)
        last = f"{minutes} мин назад" if minutes < 60 else last_scan_time.strftime("%H:%M %d.%m.%Y")
    else:
        last = "ещё не запускался"

    auto = (
        f"каждые {CHECK_INTERVAL_MIN} мин"
        if CHECK_INTERVAL_MIN > 0 and TELEGRAM_CHAT_ID
        else "выключены"
    )
    text = (
        "📊 <b>Статус бота</b>\n\n"
        f"🕐 Последний скан: {last}\n"
        f"⚙️ Порог CVSS: {CVSS_THRESHOLD}\n"
        f"🕰 Глубина поиска: {HOURS_BACK}ч\n"
        f"🔔 Авто-уведомления: {auto}\n"
        f"🔑 NVD API-ключ: {'есть' if NVD_API_KEY else 'нет'}\n"
        f"📡 Источник: NVD (nvd.nist.gov)"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_cve(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text(
            "⚠️ Укажи идентификатор. Пример: <code>/cve CVE-2021-44228</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    cve_id = context.args[0].upper()
    if not CVE_ID_RE.match(cve_id):
        await update.message.reply_text(
            f"⚠️ Не похоже на CVE-id: <code>{html.escape(cve_id)}</code>\n"
            "Формат: <code>CVE-2021-44228</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    await update.message.reply_text(
        f"⏳ Запрашиваю <code>{cve_id}</code>...", parse_mode=ParseMode.HTML
    )

    raw = await asyncio.to_thread(fetch_cve_by_id, cve_id)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    if not parsed:
        await update.message.reply_text(f"🤷 {cve_id} не найдена в базе NVD.")
        return

    await asyncio.to_thread(enrich_cves, parsed)
    parts = format_cve_list(parsed, f"Карточка {cve_id}", max_items=1)
    await send_parts(update, parts)


# ── Авто-уведомления (JobQueue) ─────────────────────────────────────────────────

async def check_new_cves(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Периодически: тянем свежие CVE и шлём только новые (по дедупликации)."""
    logger.info("Авто-проверка новых CVE...")
    raw = await asyncio.to_thread(fetch_recent_cves, HOURS_BACK)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    fresh = [c for c in parsed if c["score"] is None or c["score"] >= CVSS_THRESHOLD]

    seen = load_seen()
    new = [c for c in fresh if c["id"] not in seen]
    if not new:
        logger.info("Новых CVE нет.")
        return

    await asyncio.to_thread(enrich_cves, new)
    parts = format_cve_list(new, f"🆕 Новые CVE (CVSS ≥ {CVSS_THRESHOLD})")
    for part in parts:
        await context.bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=part,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
        )

    seen.update(c["id"] for c in new)
    save_seen(seen)
    logger.info("Отправлено новых CVE: %d", len(new))


# ── Inline кнопки ──────────────────────────────────────────────────────────────

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    # Эмулируем update.message для переиспользования команд
    class FakeMessage:
        async def reply_text(self, *args, **kwargs):
            await query.message.reply_text(*args, **kwargs)

    update.message = FakeMessage()

    if query.data == "scan":
        await cmd_scan(update, context)
    elif query.data == "critical":
        await cmd_critical(update, context)
    elif query.data == "status":
        await cmd_status(update, context)
    elif query.data == "help":
        await cmd_help(update, context)


# ── Запуск ─────────────────────────────────────────────────────────────────────

def main() -> None:
    if not TELEGRAM_TOKEN:
        raise SystemExit(
            "[FATAL] Не задан TELEGRAM_TOKEN. Создай .env (см. .env.example) "
            "и впиши токен от @BotFather."
        )

    logger.info("Запускаю CVE Monitor Bot...")
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("critical", cmd_critical))
    app.add_handler(CommandHandler("filter", cmd_filter))
    app.add_handler(CommandHandler("cve", cmd_cve))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CallbackQueryHandler(button_handler))

    # Авто-уведомления через JobQueue
    if CHECK_INTERVAL_MIN > 0 and TELEGRAM_CHAT_ID:
        if app.job_queue is None:
            logger.warning(
                "JobQueue недоступен — установи 'python-telegram-bot[job-queue]'. "
                "Авто-уведомления выключены."
            )
        else:
            app.job_queue.run_repeating(
                check_new_cves, interval=CHECK_INTERVAL_MIN * 60, first=10
            )
            logger.info(
                "Авто-уведомления включены: каждые %d мин → chat %s",
                CHECK_INTERVAL_MIN, TELEGRAM_CHAT_ID,
            )
    elif CHECK_INTERVAL_MIN > 0:
        logger.warning("CHECK_INTERVAL_MIN задан, но TELEGRAM_CHAT_ID пуст — авто-уведомления выключены.")

    logger.info("Бот запущен. Нажми Ctrl+C для остановки.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
