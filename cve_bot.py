"""
CVE Monitor Bot — интерактивный Telegram-бот для мониторинга уязвимостей.

Команды:
  /start   — приветствие
  /help    — список команд
  /scan    — свежие CVE за последние 24ч
  /critical — только CVSS ≥ 9.0
  /filter <keyword> — CVE по ключевому слову (напр. /filter apache)
  /status  — информация о боте

Требования: pip install requests python-telegram-bot python-dotenv
"""

import os
import requests
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes
)
from telegram.constants import ParseMode

load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CVSS_THRESHOLD = float(os.getenv("CVSS_THRESHOLD", "7.0"))
HOURS_BACK = int(os.getenv("HOURS_BACK", "24"))

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Время последнего сканирования
last_scan_time: datetime | None = None


# ── NVD ────────────────────────────────────────────────────────────────────────

def fetch_recent_cves(hours: int = 24) -> list[dict]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"[ERROR] NVD API: {e}")
        return []


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
    severity = "N/A"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "N/A")
            break

    if score is None:
        return None

    return {
        "id": cve_id,
        "score": score,
        "severity": severity,
        "description": description[:250] + ("..." if len(description) > 250 else ""),
        "published": cve.get("published", "")[:10],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "raw_description": description.lower(),
    }


# ── Форматирование ─────────────────────────────────────────────────────────────

def format_cve_list(cves: list[dict], title: str, max_items: int = 8) -> list[str]:
    """Возвращает список сообщений (разбитых по 4000 символов)."""
    if not cves:
        return [f"✅ <b>{title}</b>\n\nУязвимостей не найдено."]

    cves = sorted(cves, key=lambda x: x["score"], reverse=True)
    lines = [f"🔎 <b>{title}</b>\nНайдено: <b>{len(cves)}</b>\n"]

    for cve in cves[:max_items]:
        emoji = "🔴" if cve["score"] >= 9.0 else "🟠"
        lines.append(
            f"{emoji} <b>{cve['id']}</b> | CVSS: <b>{cve['score']}</b> ({cve['severity']})\n"
            f"📅 {cve['published']}\n"
            f"📝 {cve['description']}\n"
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
        "/filter &lt;слово&gt; — поиск по ключевому слову\n"
        "  пример: <code>/filter apache</code>\n"
        "  пример: <code>/filter windows</code>\n"
        "/status — статистика и время последнего скана\n"
        "/help — эта справка"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global last_scan_time
    await update.message.reply_text("⏳ Запрашиваю CVE за последние 24ч...")

    raw = fetch_recent_cves(hours=HOURS_BACK)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    critical = [c for c in parsed if c["score"] >= CVSS_THRESHOLD]

    last_scan_time = datetime.now(timezone.utc)
    parts = format_cve_list(critical, f"CVE за 24ч — CVSS ≥ {CVSS_THRESHOLD}")
    await send_parts(update, parts)


async def cmd_critical(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    global last_scan_time
    await update.message.reply_text("⏳ Ищу только CRITICAL (CVSS ≥ 9.0)...")

    raw = fetch_recent_cves(hours=HOURS_BACK)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    critical = [c for c in parsed if c["score"] >= 9.0]

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

    keyword = " ".join(context.args).lower()
    await update.message.reply_text(f"⏳ Ищу CVE по запросу: <code>{keyword}</code>...", parse_mode=ParseMode.HTML)

    raw = fetch_recent_cves(hours=HOURS_BACK)
    parsed = [p for item in raw if (p := parse_cve(item)) is not None]
    filtered = [c for c in parsed if keyword in c["raw_description"] and c["score"] >= CVSS_THRESHOLD]

    last_scan_time = datetime.now(timezone.utc)
    parts = format_cve_list(filtered, f"CVE по запросу «{keyword}»")
    await send_parts(update, parts)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if last_scan_time:
        delta = datetime.now(timezone.utc) - last_scan_time
        minutes = int(delta.total_seconds() // 60)
        last = f"{minutes} мин назад" if minutes < 60 else last_scan_time.strftime("%H:%M %d.%m.%Y")
    else:
        last = "ещё не запускался"

    text = (
        "📊 <b>Статус бота</b>\n\n"
        f"🕐 Последний скан: {last}\n"
        f"⚙️ Порог CVSS: {CVSS_THRESHOLD}\n"
        f"🕰 Глубина поиска: {HOURS_BACK}ч\n"
        f"📡 Источник: NVD (nvd.nist.gov)"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


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
    print("[*] Запускаю CVE Monitor Bot...")
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("critical", cmd_critical))
    app.add_handler(CommandHandler("filter", cmd_filter))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CallbackQueryHandler(button_handler))

    print("[*] Бот запущен. Нажми Ctrl+C для остановки.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
