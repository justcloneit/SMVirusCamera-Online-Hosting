"""
SMVirusCamera — Headless Web Launcher
======================================
Run this file instead of SMVirusCamera.py when hosting on Replit / a server.

What it does
------------
1. Imports SMVirusCamera as a module — this automatically:
   - Loads telegram_config.json
   - Starts the Telegram message worker
   - Starts one long-poll bot thread per unique bot token
   All scanning is then controlled entirely via Telegram commands.

2. Starts a lightweight Flask web server (port 5000) with:
   /          → live status dashboard (dark HTML)
   /health    → JSON health-check for deployment uptime monitors
   /status    → JSON scan state (for external integrations)
   /config    → show which bots are connected (tokens masked)
   /commands  → full Telegram command reference

Control the scanner from Telegram
----------------------------------
  /scan BD        — start scanning Bangladesh
  /status         — live progress
  /pause          — pause mid-scan
  /resume         — resume
  /stop           — graceful stop + save progress
  /restart        — resume saved scan without terminal
  /threads 50     — set thread count
  /list           — list result files on disk
  /get <filename> — download a result file
  /heatmap        — camera density by country
  /help           — full command list
"""

import os
import sys
import time
import json
import threading
from datetime import datetime, timedelta

# ── Flask ─────────────────────────────────────────────────────────────────────
try:
    from flask import Flask, jsonify, render_template_string, redirect, url_for
except ImportError:
    print("[!] Flask not found — run: pip install flask")
    sys.exit(1)

# ── Import the scanner (module-level init runs: config load, Telegram start) ──
print("[*] Loading SMVirusCamera module …", flush=True)
try:
    import SMVirusCamera as smv
    print("[✓] SMVirusCamera loaded — Telegram bot threads started.", flush=True)
except Exception as _e:
    print(f"[!] Failed to import SMVirusCamera: {_e}", flush=True)
    smv = None


# ─────────────────────────────────────────────────────────────────────────────
# Helper — pull live state from scanner globals
# ─────────────────────────────────────────────────────────────────────────────

def _uptime() -> str:
    if smv is None:
        return "—"
    elapsed = time.time() - getattr(smv, "start_time", time.time())
    h, rem  = divmod(int(elapsed), 3600)
    m, s    = divmod(rem, 60)
    return f"{h}h {m}m {s}s" if h else f"{m}m {s}s"


def _scan_state() -> dict:
    """Return a JSON-serialisable snapshot of the current scanner state."""
    if smv is None:
        return {"mode": "error", "detail": "SMVirusCamera failed to load"}

    # ── brute-force login check ───────────────────────────────────────────────
    try:
        with smv._brute_active_lock:
            bf_file  = smv._active_brute_file
            bf_idx   = smv._active_brute_index
            bf_total = smv._active_brute_total
            bf_cc    = smv._active_brute_country_code
    except Exception:
        bf_file = None; bf_idx = bf_total = 0; bf_cc = ""

    if bf_file and bf_total > 0:
        elapsed = time.time() - getattr(smv, "start_time", time.time())
        speed   = round(bf_idx / elapsed, 2) if elapsed > 0 else 0
        eta_s   = int((bf_total - bf_idx) / speed) if speed > 0 else 0
        eta_str = str(timedelta(seconds=eta_s))
        return {
            "mode":     "login-check",
            "file":     os.path.basename(bf_file),
            "country":  bf_cc,
            "checked":  bf_idx,
            "total":    bf_total,
            "pct":      round(bf_idx * 100 / bf_total, 1) if bf_total else 0,
            "speed":    f"{speed} cam/s",
            "eta":      eta_str,
            "uptime":   _uptime(),
        }

    # ── IP scan ───────────────────────────────────────────────────────────────
    try:
        with smv.results_lock:
            scanned = smv.scanned_count
            found   = len(smv.valid_results)
        total   = smv.total_ips
    except Exception:
        scanned = found = total = 0

    country = ""
    try:
        if smv.selected_country:
            country = (f"{smv.selected_country.get('name','')} "
                       f"({smv.selected_country.get('code','')})")
        elif smv.current_country_name and smv.current_country_name != "Unknown":
            country = f"{smv.current_country_name} ({smv.current_country_code})"
    except Exception:
        pass

    if total > 0:
        elapsed = time.time() - getattr(smv, "start_time", time.time())
        speed   = round(scanned / elapsed, 2) if elapsed > 0 else 0
        eta_s   = int((total - scanned) / speed) if speed > 0 else 0
        eta_str = str(timedelta(seconds=eta_s))
        return {
            "mode":     "ip-scan",
            "country":  country,
            "scanned":  scanned,
            "total":    total,
            "found":    found,
            "pct":      round(scanned * 100 / total, 1) if total else 0,
            "speed":    f"{speed} IP/s",
            "eta":      eta_str,
            "uptime":   _uptime(),
        }

    return {
        "mode":   "idle",
        "uptime": _uptime(),
        "detail": "No scan running — use /scan <CC> from Telegram to start.",
    }


def _bot_status() -> list:
    """Return list of dicts describing each configured bot/destination."""
    if smv is None:
        return []
    destinations = smv.TELEGRAM_CONFIG.get("destinations", [])
    threads      = getattr(smv, "_telegram_cmd_threads", {})
    result = []
    seen_tokens: set = set()
    for d in destinations:
        tok  = d.get("bot_token", "")
        chat = str(d.get("chat_id", ""))
        is_channel = chat.startswith("-100")
        masked_tok = tok[:10] + "…" + tok[-4:] if len(tok) > 14 else tok
        thread_alive = False
        if tok not in seen_tokens:
            seen_tokens.add(tok)
            t = threads.get(tok)
            thread_alive = t is not None and t.is_alive()
        result.append({
            "name":     d.get("name", "—"),
            "token":    masked_tok,
            "chat_id":  chat,
            "type":     "channel" if is_channel else "private/group",
            "enabled":  d.get("enabled", True),
            "polling":  thread_alive,
        })
    return result


# ─────────────────────────────────────────────────────────────────────────────
# HTML dashboard template
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="10">
  <title>SMVirusCamera — Control Panel</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;font-size:14px;padding:20px}
    h1{color:#58a6ff;font-size:22px;margin-bottom:4px}
    .subtitle{color:#6e7681;font-size:12px;margin-bottom:24px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
    .card h2{font-size:13px;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;border-bottom:1px solid #21262d;padding-bottom:8px}
    .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:bold}
    .badge.green{background:#1a4731;color:#3fb950}
    .badge.yellow{background:#3d2f00;color:#d29922}
    .badge.red{background:#3d1212;color:#f85149}
    .badge.blue{background:#0c2d6b;color:#58a6ff}
    .badge.gray{background:#21262d;color:#8b949e}
    .kv{display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid #21262d}
    .kv:last-child{border-bottom:none}
    .kv .k{color:#8b949e}
    .kv .v{color:#e6edf3;font-weight:bold;max-width:60%;text-align:right;word-break:break-all}
    .progress-bar{background:#21262d;border-radius:4px;height:8px;margin-top:10px;overflow:hidden}
    .progress-bar .fill{height:100%;border-radius:4px;background:linear-gradient(90deg,#238636,#3fb950);transition:width .5s}
    .cmd{display:inline-block;background:#21262d;color:#79c0ff;padding:2px 6px;border-radius:4px;font-size:12px;margin:2px}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th{color:#8b949e;text-align:left;padding:6px 8px;border-bottom:1px solid #21262d}
    td{padding:5px 8px;border-bottom:1px solid #161b22;color:#c9d1d9}
    tr:hover td{background:#1c2128}
    .dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
    .dot.on{background:#3fb950}
    .dot.off{background:#f85149}
    footer{margin-top:24px;color:#6e7681;font-size:11px;text-align:center}
    a{color:#58a6ff;text-decoration:none}
    a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <h1>📹 SMVirusCamera Control Panel</h1>
  <p class="subtitle">Auto-refreshes every 10 s &nbsp;|&nbsp; {{ now }}</p>

  <div class="grid">

    <!-- Scan Status -->
    <div class="card">
      <h2>📡 Scan Status</h2>
      {% if state.mode == 'idle' %}
        <div class="kv"><span class="k">Mode</span><span class="v"><span class="badge gray">IDLE</span></span></div>
        <div class="kv"><span class="k">Uptime</span><span class="v">{{ state.uptime }}</span></div>
        <p style="margin-top:12px;color:#6e7681;font-size:12px">{{ state.detail }}</p>
      {% elif state.mode == 'ip-scan' %}
        <div class="kv"><span class="k">Mode</span><span class="v"><span class="badge green">IP SCAN</span></span></div>
        <div class="kv"><span class="k">Country</span><span class="v">{{ state.country or '—' }}</span></div>
        <div class="kv"><span class="k">Progress</span><span class="v">{{ '{:,}'.format(state.scanned) }} / {{ '{:,}'.format(state.total) }} ({{ state.pct }}%)</span></div>
        <div class="progress-bar"><div class="fill" style="width:{{ state.pct }}%"></div></div>
        <div class="kv" style="margin-top:10px"><span class="k">Cameras Found</span><span class="v">{{ state.found }}</span></div>
        <div class="kv"><span class="k">Speed</span><span class="v">{{ state.speed }}</span></div>
        <div class="kv"><span class="k">ETA</span><span class="v">{{ state.eta }}</span></div>
        <div class="kv"><span class="k">Uptime</span><span class="v">{{ state.uptime }}</span></div>
      {% elif state.mode == 'login-check' %}
        <div class="kv"><span class="k">Mode</span><span class="v"><span class="badge yellow">LOGIN CHECK</span></span></div>
        <div class="kv"><span class="k">File</span><span class="v">{{ state.file }}</span></div>
        {% if state.country %}<div class="kv"><span class="k">Country</span><span class="v">{{ state.country }}</span></div>{% endif %}
        <div class="kv"><span class="k">Progress</span><span class="v">{{ '{:,}'.format(state.checked) }} / {{ '{:,}'.format(state.total) }} ({{ state.pct }}%)</span></div>
        <div class="progress-bar"><div class="fill" style="width:{{ state.pct }}%"></div></div>
        <div class="kv" style="margin-top:10px"><span class="k">Speed</span><span class="v">{{ state.speed }}</span></div>
        <div class="kv"><span class="k">ETA</span><span class="v">{{ state.eta }}</span></div>
        <div class="kv"><span class="k">Uptime</span><span class="v">{{ state.uptime }}</span></div>
      {% else %}
        <div class="kv"><span class="k">Mode</span><span class="v"><span class="badge red">ERROR</span></span></div>
        <div class="kv"><span class="k">Detail</span><span class="v">{{ state.detail }}</span></div>
      {% endif %}
    </div>

    <!-- Bot Status -->
    <div class="card">
      <h2>🤖 Telegram Bots</h2>
      <table>
        <tr><th>Name</th><th>Chat ID</th><th>Type</th><th>Polling</th></tr>
        {% for b in bots %}
        <tr>
          <td>{{ b.name }}</td>
          <td><code>{{ b.chat_id }}</code></td>
          <td>{{ b.type }}</td>
          <td>
            {% if not b.enabled %}
              <span class="badge gray">disabled</span>
            {% elif b.polling %}
              <span class="dot on"></span><span class="badge green">live</span>
            {% else %}
              <span class="dot off"></span><span class="badge red">stopped</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
        {% if not bots %}
        <tr><td colspan="4" style="color:#6e7681">No destinations configured</td></tr>
        {% endif %}
      </table>
      <p style="margin-top:10px;font-size:11px;color:#6e7681">
        Bots sharing a token share one polling thread.<br>
        Channel rows (chat_id -100…) receive outgoing posts only.
      </p>
    </div>

    <!-- Telegram Commands -->
    <div class="card">
      <h2>⌨️ Telegram Commands</h2>
      <div style="line-height:2">
        <span class="cmd">/scan BD</span> start a country scan<br>
        <span class="cmd">/status</span> live progress<br>
        <span class="cmd">/pause</span> pause the scan<br>
        <span class="cmd">/resume</span> resume paused scan<br>
        <span class="cmd">/stop</span> graceful stop + save<br>
        <span class="cmd">/restart</span> resume saved scan<br>
        <span class="cmd">/threads 50</span> set thread count<br>
        <span class="cmd">/list</span> list result files<br>
        <span class="cmd">/get filename.txt</span> download file<br>
        <span class="cmd">/heatmap</span> camera density map<br>
        <span class="cmd">/scanlist</span> all country codes<br>
        <span class="cmd">/help</span> full command list
      </div>
    </div>

    <!-- API Endpoints -->
    <div class="card">
      <h2>🔗 API Endpoints</h2>
      <div class="kv"><span class="k">Status dashboard</span><span class="v"><a href="/">/</a></span></div>
      <div class="kv"><span class="k">Health check</span><span class="v"><a href="/health">/health</a></span></div>
      <div class="kv"><span class="k">JSON scan state</span><span class="v"><a href="/status">/status</a></span></div>
      <div class="kv"><span class="k">Bot config</span><span class="v"><a href="/config">/config</a></span></div>
      <div class="kv"><span class="k">Command list</span><span class="v"><a href="/commands">/commands</a></span></div>
    </div>

  </div>

  <footer>
    SMVirusCamera &nbsp;|&nbsp; hosted on Replit &nbsp;|&nbsp;
    <a href="/health">health</a> &nbsp;·&nbsp;
    <a href="/status">json</a> &nbsp;·&nbsp;
    {{ now }}
  </footer>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Flask routes
# ─────────────────────────────────────────────────────────────────────────────

flask_app = Flask(__name__)


@flask_app.route("/")
def index():
    return render_template_string(
        DASHBOARD_HTML,
        state=_scan_state(),
        bots=_bot_status(),
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@flask_app.route("/health")
def health():
    """Uptime-monitor / deployment health check endpoint."""
    threads = getattr(smv, "_telegram_cmd_threads", {}) if smv else {}
    alive   = sum(1 for t in threads.values() if t and t.is_alive())
    return jsonify({
        "status":          "ok",
        "uptime":          _uptime(),
        "scanner_loaded":  smv is not None,
        "bot_threads":     alive,
        "timestamp":       datetime.utcnow().isoformat() + "Z",
    })


@flask_app.route("/status")
def status_json():
    """Machine-readable current scan state."""
    return jsonify(_scan_state())


@flask_app.route("/config")
def config_json():
    """Bot destinations with tokens masked — safe to share."""
    telegram_enabled = smv.TELEGRAM_CONFIG.get("enabled", False) if smv else False
    return jsonify({
        "telegram_enabled": telegram_enabled,
        "destinations":     _bot_status(),
    })


@flask_app.route("/commands")
def commands():
    """Full Telegram command reference as JSON."""
    return jsonify({
        "commands": [
            {"/scan <CC>":    "Start IP scan for country code (e.g. /scan BD)"},
            {"/status":       "Live progress — mode, country, %, speed, ETA"},
            {"/pause":        "Pause the running scan"},
            {"/resume":       "Resume a paused scan"},
            {"/stop":         "Graceful stop — saves progress"},
            {"/restart":      "Resume saved scan without touching the terminal"},
            {"/threads <n>":  "Set thread count live (0 = adaptive)"},
            {"/list":         "List result files on disk"},
            {"/get <file>":   "Download a result file"},
            {"/heatmap":      "Camera density heatmap by country"},
            {"/offenders":    "Top repeat-offender IPs"},
            {"/m3u":          "Generate & send M3U playlist of all RTSP cameras"},
            {"/csv":          "Export all results to CSV and send"},
            {"/scanlist":     "All 255 country codes grouped by RIR region"},
            {"/stealth":      "Toggle stealth mode (random delays + UA rotation)"},
            {"/setthreshold": "Set error-rate cooldown threshold (0.05–1.0)"},
            {"/help":         "Full command reference"},
        ]
    })


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    # Announce we're running in headless / web-hosted mode
    if smv and smv.TELEGRAM_CONFIG.get("enabled"):
        try:
            smv.send_telegram_message(
                "🌐 <b>SMVirusCamera — Web Mode Started</b>\n"
                "━━━━━━━━━━━━━━━━━━━━━━\n"
                "Bot is online and ready for commands.\n"
                "Send /help to see all available commands.\n"
                f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception:
            pass

    print(f"[*] Starting Flask dashboard on port {port} …", flush=True)
    # Use threaded=True so the bot polling threads can run alongside Flask
    flask_app.run(host="0.0.0.0", port=port, threaded=True, use_reloader=False)
