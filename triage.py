"""
triage.py — a first-pass incident triage for application logs.

Point it at a log file and it answers the questions I ask in the first
ten minutes of any investigation:

  * Which errors are actually happening, once the noise is collapsed?
  * When did things go wrong, and is it a real spike or the usual background?
  * What was the earliest *new* signal before the spike — the place to start digging?

It reads plain-text logs (timestamp, level, optional [service] or service:,
message) and JSON-lines logs, using only the Python standard library, so it
runs the same in a terminal or in the browser via Pyodide.

Usage:
    python triage.py app.log
    python triage.py app.log --window 120 --json
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

LEVELS = {
    "TRACE": 0, "DEBUG": 1, "INFO": 2, "NOTICE": 2,
    "WARN": 3, "WARNING": 3,
    "ERROR": 4, "ERR": 4,
    "FATAL": 5, "CRITICAL": 5, "CRIT": 5, "PANIC": 5,
}
CANONICAL_LEVEL = {"WARNING": "WARN", "ERR": "ERROR", "CRITICAL": "FATAL",
                   "CRIT": "FATAL", "PANIC": "FATAL", "NOTICE": "INFO"}
WARN, ERROR = LEVELS["WARN"], LEVELS["ERROR"]

# 2026-03-14T09:12:03.120Z ERROR [payments-svc] message
# 2026-03-14 09:12:03,120 [ERROR] payments-svc: message
TEXT_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+\[?(?P<level>[A-Za-z]+)\]?"
    r"\s+(?:\[(?P<svc_bracket>[^\]\s]+)\]\s*|(?P<svc_colon>[\w.\-/]+):\s+)?"
    r"(?P<msg>.*)$"
)

# Variable parts of a message get masked so that
# "timeout after 3012ms for order 8812" and "timeout after 2950ms for order 1203"
# collapse into one signature. Order matters: most specific patterns first.
MASKS = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<ts>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<email>"),
    (re.compile(r"https?://[^\s\"']+"), "<url>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\"[^\"]*\"|'[^']*'"), "<str>"),
    (re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?:ms|s|m|h|kb|mb|gb|%)?\b", re.I), "<n>"),
]
WHITESPACE = re.compile(r"\s+")

# Lines that record a change to the system. Most incidents follow one, so these are
# surfaced whatever their log level.
CHANGE_HINT = re.compile(
    r"\b(deploy\w*|roll(?:ed)?\s?back|release[ds]?|restart\w*|migrat\w+|feature flag|"
    r"config(?:uration)? (?:change|reload|update)\w*|scal(?:ed|ing) (?:up|down|to))\b",
    re.I,
)


@dataclass
class Entry:
    ts: datetime
    level: str
    severity: int
    service: str
    message: str


@dataclass
class Signature:
    key: str
    level: str
    service: str
    pattern: str
    example: str
    count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class Report:
    lines_total: int = 0
    lines_parsed: int = 0
    level_counts: Counter = field(default_factory=Counter)
    signatures: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    incidents: list = field(default_factory=list)
    changes: list = field(default_factory=list)
    window_seconds: int = 60
    start: Optional[datetime] = None
    end: Optional[datetime] = None


# --------------------------------------------------------------------------- parsing

def parse_timestamp(raw: str) -> Optional[datetime]:
    raw = raw.strip().replace(",", ".")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    # fromisoformat (3.9) is strict about fractional digits; normalise to 6.
    m = re.match(r"^(.*?\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$", raw)
    if not m:
        return None
    base, frac, tz = m.groups()
    frac = (frac or "0")[:6].ljust(6, "0")
    if re.fullmatch(r"[+-]\d{4}", tz or ""):
        tz = tz[:3] + ":" + tz[3:]
    try:
        ts = datetime.fromisoformat(f"{base.replace(' ', 'T')}.{frac}{tz}")
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _first(obj: dict, *keys: str):
    for k in keys:
        cur = obj
        for part in k.split("."):
            if not isinstance(cur, dict) or part not in cur:
                break
            cur = cur[part]
        else:
            if cur is not None and not isinstance(cur, (dict, list)):
                return cur
    return None


def _level(raw) -> Optional[tuple]:
    name = str(raw or "").upper()
    if name not in LEVELS:
        return None
    return CANONICAL_LEVEL.get(name, name), LEVELS[name]


def parse_line(line: str) -> Optional[Entry]:
    line = line.strip()
    if not line:
        return None

    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except ValueError:
            return None
        ts = parse_timestamp(str(_first(obj, "@timestamp", "timestamp", "ts", "time") or ""))
        level = _level(_first(obj, "level", "severity", "log.level", "lvl"))
        msg = _first(obj, "message", "msg", "error.message")
        if not (ts and level and msg):
            return None
        service = _first(obj, "service", "service.name", "app", "logger.name", "logger") or "-"
        return Entry(ts, level[0], level[1], str(service), str(msg))

    m = TEXT_LINE.match(line)
    if not m:
        return None
    ts, level = parse_timestamp(m["ts"]), _level(m["level"])
    if not (ts and level):
        return None
    service = m["svc_bracket"] or m["svc_colon"] or "-"
    return Entry(ts, level[0], level[1], service, m["msg"].strip())


def normalize(message: str) -> str:
    """Mask the variable parts of a log message so similar lines group together."""
    out = message
    for pattern, token in MASKS:
        out = pattern.sub(token, out)
    return WHITESPACE.sub(" ", out).strip()[:240]


# --------------------------------------------------------------------------- analysis

def detect_spikes(counts: list, min_count: int = 3) -> list:
    """Return indexes of buckets that are well above the usual background.

    Uses median + MAD rather than mean + stdev: an outage that lasts a while
    would otherwise drag the baseline up and hide itself.
    """
    if len(counts) < 5:
        return []
    med = statistics.median(counts)
    mad = statistics.median(abs(c - med) for c in counts)
    threshold = med + max(3 * 1.4826 * mad, 3)
    return [i for i, c in enumerate(counts) if c >= min_count and c > threshold]


def _group_runs(indexes: list, max_gap: int = 2) -> list:
    runs = []
    for i in indexes:
        if runs and i - runs[-1][-1] <= max_gap + 1:
            runs[-1].append(i)
        else:
            runs.append([i])
    return runs


def analyze(lines: Iterable[str], window_seconds: int = 60, lookback_minutes: int = 15) -> Report:
    report = Report(window_seconds=window_seconds)
    entries = []
    for line in lines:
        if not line.strip():
            continue
        report.lines_total += 1
        entry = parse_line(line)
        if entry:
            entries.append(entry)
    report.lines_parsed = len(entries)
    if not entries:
        return report

    entries.sort(key=lambda e: e.ts)
    report.start, report.end = entries[0].ts, entries[-1].ts
    report.level_counts = Counter(e.level for e in entries)
    report.changes = [e for e in entries if CHANGE_HINT.search(e.message)]

    # Collapse warnings and errors into signatures.
    sigs: dict = {}
    sig_hits = defaultdict(list)
    for e in entries:
        if e.severity < WARN:
            continue
        pattern = normalize(e.message)
        key = f"{e.service}|{e.level}|{pattern}"
        sig = sigs.get(key)
        if sig is None:
            sig = sigs[key] = Signature(key, e.level, e.service, pattern, e.message, first_seen=e.ts)
        sig.count += 1
        sig.last_seen = e.ts
        sig_hits[key].append(e.ts)
    report.signatures = sorted(sigs.values(), key=lambda s: (-s.count, s.first_seen))

    # Errors per time bucket.
    width = timedelta(seconds=window_seconds)
    n_buckets = int((report.end - report.start) / width) + 1
    errors, totals = [0] * n_buckets, [0] * n_buckets
    for e in entries:
        i = int((e.ts - report.start) / width)
        totals[i] += 1
        if e.severity >= ERROR:
            errors[i] += 1
    report.timeline = [
        {"start": report.start + i * width, "errors": errors[i], "total": totals[i]}
        for i in range(n_buckets)
    ]

    # Spikes → incidents, each with what changed around it.
    lookback = timedelta(minutes=lookback_minutes)
    for run in _group_runs(detect_spikes(errors)):
        start = report.start + run[0] * width
        end = report.start + (run[-1] + 1) * width
        in_window = Counter()
        for key, hits in sig_hits.items():
            n = sum(1 for t in hits if start <= t < end)
            if n:
                in_window[key] = n
        new_signals = sorted(
            (s for s in report.signatures if start - lookback <= s.first_seen < end),
            key=lambda s: s.first_seen,
        )
        report.incidents.append({
            "start": start,
            "end": end,
            "errors": sum(errors[i] for i in range(run[0], run[-1] + 1)),
            "peak_per_window": max(errors[i] for i in run),
            "baseline_per_window": statistics.median(errors),
            "top": [(sigs[k], n) for k, n in in_window.most_common(5)],
            "changes_before": [c for c in report.changes if start - lookback <= c.ts < end],
            "earliest_new_signal": new_signals[0] if new_signals else None,
            "new_signals": new_signals[:8],
        })
    return report


# --------------------------------------------------------------------------- output

def _iso(ts: Optional[datetime]) -> Optional[str]:
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if ts else None


def _sig_dict(s: Signature) -> dict:
    return {"level": s.level, "service": s.service, "pattern": s.pattern, "example": s.example,
            "count": s.count, "first_seen": _iso(s.first_seen), "last_seen": _iso(s.last_seen)}


def _change_dict(e: Entry) -> dict:
    return {"ts": _iso(e.ts), "level": e.level, "service": e.service, "message": e.message}


def to_dict(report: Report, top: int = 15) -> dict:
    return {
        "lines_total": report.lines_total,
        "lines_parsed": report.lines_parsed,
        "start": _iso(report.start),
        "end": _iso(report.end),
        "window_seconds": report.window_seconds,
        "level_counts": dict(report.level_counts),
        "distinct_signatures": len(report.signatures),
        "signatures": [_sig_dict(s) for s in report.signatures[:top]],
        "timeline": [{"start": _iso(b["start"]), "errors": b["errors"], "total": b["total"]}
                     for b in report.timeline],
        "incidents": [{
            "start": _iso(i["start"]),
            "end": _iso(i["end"]),
            "errors": i["errors"],
            "peak_per_window": i["peak_per_window"],
            "baseline_per_window": i["baseline_per_window"],
            "top": [dict(_sig_dict(s), count_in_window=n) for s, n in i["top"]],
            "changes_before": [_change_dict(c) for c in i["changes_before"]],
            "earliest_new_signal": _sig_dict(i["earliest_new_signal"]) if i["earliest_new_signal"] else None,
            "new_signals": [_sig_dict(s) for s in i["new_signals"]],
        } for i in report.incidents],
        "changes": [_change_dict(c) for c in report.changes],
        "summary": summarize(report),
    }


def summarize(report: Report) -> str:
    """A short, plain-English write-up — the first message I'd post in an incident channel."""
    if not report.lines_parsed:
        return "No log lines could be parsed. Expected 'timestamp LEVEL [service] message' or JSON lines."

    n_err = sum(v for k, v in report.level_counts.items() if LEVELS.get(k, 0) >= ERROR)
    span = report.end - report.start
    parts = [
        f"Parsed {report.lines_parsed:,} of {report.lines_total:,} lines covering "
        f"{_fmt_span(span)} ({report.start:%Y-%m-%d %H:%M}–{report.end:%H:%M} UTC). "
        f"{n_err:,} error-level events collapse into "
        f"{sum(1 for s in report.signatures if LEVELS[s.level] >= ERROR)} distinct error signatures."
    ]
    if not report.incidents:
        parts.append("No error spike stands out from the background rate.")
        return " ".join(parts)

    for n, inc in enumerate(report.incidents, 1):
        top_sig, top_n = inc["top"][0] if inc["top"] else (None, 0)
        line = (
            f"Incident {n}: errors spiked {inc['start']:%H:%M}–{inc['end']:%H:%M} UTC "
            f"(peak {inc['peak_per_window']}/{_fmt_window(report.window_seconds)} vs a baseline of "
            f"{inc['baseline_per_window']:g})."
        )
        if top_sig:
            line += f" Dominant error: {top_sig.service} — \"{top_sig.example}\" ({top_n}×)."
        changes = inc["changes_before"]
        if changes:
            c = changes[0]
            line += f" It follows a change: {c.service} at {c.ts:%H:%M:%S} — \"{c.message}\"."
        first = inc["earliest_new_signal"]
        if first:
            line += (
                f" Earliest new signal: {first.level} from {first.service} at {first.first_seen:%H:%M:%S} — "
                f"\"{first.example}\". Start the investigation there."
            )
        parts.append(line)
    return " ".join(parts)


def _fmt_span(span: timedelta) -> str:
    minutes = int(span.total_seconds() // 60)
    return f"{minutes // 60}h {minutes % 60}m" if minutes >= 60 else f"{minutes}m"


def _fmt_window(seconds: int) -> str:
    return "min" if seconds == 60 else f"{seconds}s"


def analyze_text(text: str, window_seconds: int = 60) -> str:
    """Entry point for the browser: takes raw log text, returns the report as JSON."""
    return json.dumps(to_dict(analyze(text.splitlines(), window_seconds)))


def print_report(report: Report, top: int = 10) -> None:
    print(summarize(report), end="\n\n")
    if not report.signatures:
        return
    print(f"Top {min(top, len(report.signatures))} signatures")
    print(f"{'count':>7}  {'level':<5}  {'service':<16}  pattern")
    for s in report.signatures[:top]:
        print(f"{s.count:>7}  {s.level:<5}  {s.service[:16]:<16}  {s.pattern[:90]}")


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="First-pass incident triage for log files.")
    parser.add_argument("logfile", help="path to a log file, or - for stdin")
    parser.add_argument("--window", type=int, default=60, help="bucket size in seconds (default 60)")
    parser.add_argument("--top", type=int, default=10, help="how many signatures to list")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = parser.parse_args(argv)

    stream = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8", errors="replace")
    with stream:
        report = analyze(stream, args.window)
    if args.json:
        print(json.dumps(to_dict(report, args.top), indent=2))
    else:
        print_report(report, args.top)
    return 0 if report.lines_parsed else 1


if __name__ == "__main__":
    sys.exit(main())
