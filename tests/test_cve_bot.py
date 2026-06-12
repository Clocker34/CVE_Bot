"""Юнит-тесты CVE Monitor Bot (без обращения к сети)."""

import asyncio
import json

import pytest

import cve_bot as b


# ── parse_cve ───────────────────────────────────────────────────────────────────

def _item(cve_id="CVE-2026-0001", desc="Some bug", score=9.8, severity="CRITICAL",
          metric_key="cvssMetricV31"):
    cve = {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": desc}],
        "published": "2026-06-12T00:00:00",
        "metrics": {},
    }
    if score is not None:
        cve["metrics"] = {metric_key: [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]}
    return {"cve": cve}


def test_parse_cve_basic():
    p = b.parse_cve(_item())
    assert p["id"] == "CVE-2026-0001"
    assert p["score"] == 9.8
    assert p["severity"] == "CRITICAL"
    assert p["published"] == "2026-06-12"
    assert p["url"].endswith("CVE-2026-0001")


def test_parse_cve_without_score_is_kept():
    p = b.parse_cve(_item(score=None))
    assert p is not None
    assert p["score"] is None
    assert p["severity"] == "оценка ожидается"


def test_parse_cve_prefers_english_description():
    item = _item()
    item["cve"]["descriptions"] = [
        {"lang": "es", "value": "español"},
        {"lang": "en", "value": "english text"},
    ]
    assert b.parse_cve(item)["raw_description"] == "english text"


def test_parse_cve_truncates_long_description():
    p = b.parse_cve(_item(desc="A" * 500))
    assert p["description"].endswith("...")
    assert len(p["description"]) <= 254


# ── format_cve_list ─────────────────────────────────────────────────────────────

def _cve(cve_id, score, kev=False, epss=None, desc="desc"):
    return {
        "id": cve_id, "score": score, "severity": "HIGH", "description": desc,
        "published": "2026-06-12", "url": f"https://x/{cve_id}", "kev": kev, "epss": epss,
    }


def test_format_empty():
    out = b.format_cve_list([], "Заголовок")
    assert len(out) == 1
    assert "не найдено" in out[0]


def test_format_escapes_html():
    out = "\n".join(b.format_cve_list([_cve("CVE-1", 9.0, desc="<script> & a>b")], "T"))
    assert "&lt;script&gt;" in out and "a&gt;b" in out
    assert "<script>" not in out


def test_format_pending_label():
    out = "\n".join(b.format_cve_list([_cve("CVE-1", None)], "T"))
    assert "оценка ожидается" in out


def test_format_kev_and_epss_badges():
    out = "\n".join(b.format_cve_list([_cve("CVE-1", 8.0, kev=True, epss=0.9)], "T"))
    assert "CISA KEV" in out
    assert "EPSS: 90.0%" in out


def test_format_sorts_kev_first_then_score():
    cves = [_cve("CVE-LOW", 5.0, kev=True), _cve("CVE-HIGH", 9.9, kev=False)]
    out = "\n".join(b.format_cve_list(cves, "T"))
    assert out.index("CVE-LOW") < out.index("CVE-HIGH")  # KEV выигрывает у CVSS


def test_format_splits_long_messages():
    cves = [_cve(f"CVE-{i:04d}", 9.0, desc="D" * 240) for i in range(40)]
    parts = b.format_cve_list(cves, "T", max_items=40)
    assert len(parts) > 1
    assert all(len(p) <= 4000 for p in parts)


# ── load_seen / save_seen ───────────────────────────────────────────────────────

def test_seen_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(b, "SEEN_FILE", tmp_path / "seen.json")
    assert b.load_seen() == set()  # файла ещё нет
    b.save_seen({"CVE-2026-0001", "CVE-2026-0002"})
    assert b.load_seen() == {"CVE-2026-0001", "CVE-2026-0002"}


def test_seen_handles_corrupt_file(tmp_path, monkeypatch):
    f = tmp_path / "seen.json"
    f.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(b, "SEEN_FILE", f)
    assert b.load_seen() == set()


def test_seen_trims_to_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(b, "SEEN_FILE", tmp_path / "seen.json")
    monkeypatch.setattr(b, "SEEN_LIMIT", 5)
    b.save_seen({f"CVE-2026-{i:04d}" for i in range(20)})
    assert len(b.load_seen()) == 5


# ── CVE_ID_RE ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cve_id,ok", [
    ("CVE-2021-44228", True),
    ("cve-2021-44228", True),
    ("CVE-2021-4", False),
    ("CVE-21-4444", False),
    ("apache", False),
])
def test_cve_id_regex(cve_id, ok):
    assert bool(b.CVE_ID_RE.match(cve_id)) is ok


# ── Обогащение (с подменой сети) ────────────────────────────────────────────────

class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_get_kev_ids_cached(monkeypatch):
    calls = {"n": 0}

    def fake_get(url, **kw):
        calls["n"] += 1
        return _Resp({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})

    monkeypatch.setattr(b.requests, "get", fake_get)
    monkeypatch.setattr(b, "_kev_cache", {"ids": set(), "ts": 0.0})

    assert "CVE-2021-44228" in b.get_kev_ids()
    b.get_kev_ids()  # второй вызов — из кэша
    assert calls["n"] == 1


def test_enrich_marks_kev_and_epss(monkeypatch):
    monkeypatch.setattr(b, "get_kev_ids", lambda: {"CVE-2021-44228"})
    monkeypatch.setattr(b, "get_epss_scores", lambda ids: {"CVE-2021-44228": 0.97})

    cves = [_cve("CVE-2021-44228", 10.0), _cve("CVE-2099-0000", 5.0)]
    b.enrich_cves(cves)

    assert cves[0]["kev"] is True and cves[0]["epss"] == 0.97
    assert cves[1]["kev"] is False and cves[1]["epss"] is None


# ── Авто-уведомления (check_new_cves) ───────────────────────────────────────────

class _Bot:
    def __init__(self):
        self.sent = []

    async def send_message(self, chat_id, text, **kw):
        self.sent.append(text)


class _Ctx:
    def __init__(self):
        self.bot = _Bot()


def test_check_new_cves_sends_only_new_and_dedups(tmp_path, monkeypatch):
    monkeypatch.setattr(b, "SEEN_FILE", tmp_path / "seen.json")
    monkeypatch.setattr(b, "TELEGRAM_CHAT_ID", "123")
    monkeypatch.setattr(b, "CVSS_THRESHOLD", 7.0)
    monkeypatch.setattr(b, "enrich_cves", lambda cves: None)  # без сети
    monkeypatch.setattr(
        b, "fetch_recent_cves",
        lambda hours=24: [_item("CVE-2026-1111", score=9.9), _item("CVE-2026-2222", score=4.0)],
    )

    ctx = _Ctx()
    asyncio.run(b.check_new_cves(ctx))
    joined = "\n".join(ctx.bot.sent)
    assert "CVE-2026-1111" in joined          # critical отправлен
    assert "CVE-2026-2222" not in joined      # ниже порога — пропущен

    # Повторный прогон — дубликатов быть не должно
    ctx2 = _Ctx()
    asyncio.run(b.check_new_cves(ctx2))
    assert ctx2.bot.sent == []
