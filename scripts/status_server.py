#!/usr/bin/env python3
"""
Local status dashboard for the ghidra-rs porting effort.

Dependency-free (stdlib only). Computes metrics LIVE on every request from the
manifest, tick2_results.tsv, tick2.status, PORT_PARKED.tsv and the window-summary
log, so the page is always current. Binds to localhost only.

Run:
    python3 scripts/status_server.py                 # binds 0.0.0.0:8765 (LAN + Tailscale)
    HOST=127.0.0.1 python3 scripts/status_server.py  # loopback only
    HOST=100.x.y.z python3 scripts/status_server.py  # bind a specific (e.g. Tailscale) IP
    PORT=9000 python3 scripts/status_server.py

Endpoints:  /  (HTML dashboard, auto-refresh)   /metrics.json  (raw numbers)

Note: serves read-only porting metrics; 0.0.0.0 exposes it to your LAN/tailnet.
"""

import html
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import portlib  # noqa: E402  (module_for / package_of / layout)

MANIFEST = os.path.join(REPO, "PORT_MANIFEST.tsv")
RESULTS = os.path.join(REPO, "tick2_results.tsv")
STATUS = os.path.join(REPO, "tick2.status")
PARKED = os.path.join(REPO, "PORT_PARKED.tsv")
SUMMARY = os.path.join(os.path.expanduser("~"), "agents", "logs", "ghidra", "port-summary.log")
PORT = int(os.environ.get("PORT", "8765"))
HOST = os.environ.get("HOST", "0.0.0.0")  # all interfaces -> reachable via LAN/Tailscale IP


def compute():
    m = {"generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    # --- manifest: done / todo, in-scope vs excluded, per-module ---
    total = done = todo = inscope_done = inscope_todo = unmapped_todo = 0
    mod_done, mod_total = Counter(), Counter()
    try:
        with open(MANIFEST, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                total += 1
                path, status = parts[0], parts[1]
                mod = portlib.module_for(portlib.package_of(path))
                is_done = status == "DONE"
                if is_done:
                    done += 1
                else:
                    todo += 1
                if mod:  # in-scope (queueable)
                    mod_total[mod] += 1
                    if is_done:
                        inscope_done += 1
                        mod_done[mod] += 1
                    else:
                        inscope_todo += 1
                elif not is_done:
                    unmapped_todo += 1
    except FileNotFoundError:
        pass
    inscope_total = inscope_done + inscope_todo
    m.update(total=total, done=done, todo=todo,
             inscope_done=inscope_done, inscope_todo=inscope_todo,
             inscope_total=inscope_total, unmapped_todo=unmapped_todo,
             pct=round(100 * inscope_done / inscope_total, 1) if inscope_total else 0)
    m["modules"] = sorted(
        ([mod, mod_done[mod], mod_total[mod]] for mod in mod_total),
        key=lambda r: r[2], reverse=True)

    # --- parked ---
    try:
        with open(PARKED, encoding="utf-8", errors="ignore") as fh:
            m["parked"] = len({l.strip() for l in fh if l.strip()})
    except FileNotFoundError:
        m["parked"] = 0

    # --- results: spend, result mix, recent, last-24h ---
    ported = parked = apifail = 0
    spend = 0.0
    recent = []
    cutoff = datetime.now() - timedelta(hours=24)
    d24_ported = 0
    d24_spend = 0.0
    try:
        with open(RESULTS, encoding="utf-8", errors="ignore") as fh:
            next(fh, None)  # header
            for line in fh:
                c = line.rstrip("\n").split("\t")
                if len(c) < 7:
                    continue
                ts, cls, result, tests, dur, cost, srcpath = c[0], c[1], c[2], c[3], c[4], c[5], c[6]
                try:
                    cost_f = float(cost)
                except ValueError:
                    cost_f = 0.0
                spend += cost_f
                if result == "PORTED":
                    ported += 1
                elif result.startswith("PARK"):
                    parked += 1
                elif result == "API-FAIL":
                    apifail += 1
                recent.append((ts, cls, result, dur, cost_f))
                try:
                    if datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S") >= cutoff:
                        if result == "PORTED":
                            d24_ported += 1
                        d24_spend += cost_f
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    m.update(ported=ported, parked_runs=parked, apifail=apifail,
             spend=round(spend, 2), d24_ported=d24_ported, d24_spend=round(d24_spend, 2),
             recent=recent[-15:][::-1])

    # --- current run (tick2.status), considered "active" if updated < 5 min ago ---
    run = {}
    active = False
    if os.path.exists(STATUS):
        active = (time.time() - os.path.getmtime(STATUS)) < 300
        try:
            with open(STATUS, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        run[k.strip()] = v.strip()
        except OSError:
            pass
    m["run"] = run
    m["run_active"] = active

    # --- window summaries (nightly/daytime) ---
    summary = []
    if os.path.exists(SUMMARY):
        try:
            with open(SUMMARY, encoding="utf-8", errors="ignore") as fh:
                summary = [l.rstrip("\n") for l in fh if l.strip()][-8:][::-1]
        except OSError:
            pass
    m["summaries"] = summary

    # dependency-frontier snapshot (periodic, from dep_stats.json; too heavy per request)
    dep = None
    dsp = os.path.join(REPO, "dep_stats.json")
    if os.path.exists(dsp):
        try:
            dep = json.load(open(dsp, encoding="utf-8"))
            dep["_age_min"] = int((time.time() - os.path.getmtime(dsp)) / 60)
        except (OSError, ValueError):
            dep = None
    m["dep"] = dep
    return m


def render(m):
    e = html.escape
    bar = (f"<div class=bar><div class=fill style='width:{m['pct']}%'></div>"
           f"<span class=barlbl>{m['inscope_done']:,} / {m['inscope_total']:,} in-scope &nbsp;({m['pct']}%)</span></div>")

    run_html = ""
    if m["run_active"] and m["run"]:
        r = m["run"]
        cur = e(r.get("current", "?"))
        run_html = (f"<div class='card run'><h2>🟢 Run active</h2>"
                    f"<div class=kv>state: {e(r.get('state','?'))}</div>"
                    f"<div class=kv>current: <code>{cur}</code></div>"
                    f"<div class=kv>this run: {e(r.get('ported(run)','?'))} ported / {e(r.get('parked(run)','?'))} parked &middot; {e(r.get('ports/hr','?'))}/hr</div>"
                    f"<div class=kv>spend: {e(r.get('spend','?'))}</div></div>")
    else:
        run_html = "<div class='card'><h2>⚪ No run active</h2><div class=kv>idle — nightly cron fires 22:00</div></div>"

    cards = f"""
    <div class=cards>
      <div class=card><div class=big>{m['done']:,}</div><div class=lbl>ported (DONE)</div></div>
      <div class=card><div class=big>{m['inscope_todo']:,}</div><div class=lbl>in-scope remaining</div></div>
      <div class=card><div class=big>{m['d24_ported']:,}</div><div class=lbl>ported last 24h</div></div>
      <div class=card><div class=big>${m['spend']:,.0f}</div><div class=lbl>total spend (${m['d24_spend']:,.0f} 24h)</div></div>
      <div class=card><div class=big>{m['parked']:,}</div><div class=lbl>parked</div></div>
      <div class=card><div class=big>{m['unmapped_todo']:,}</div><div class=lbl>excluded (out of scope)</div></div>
    </div>"""

    mod_rows = "".join(
        f"<tr><td>{e(mod)}/</td><td class=num>{d:,}</td><td class=num>{t:,}</td>"
        f"<td><div class=mbar><div style='width:{(100*d/t) if t else 0:.0f}%'></div></div></td>"
        f"<td class=num>{(100*d/t) if t else 0:.0f}%</td></tr>"
        for mod, d, t in m["modules"])

    rec_rows = "".join(
        f"<tr><td>{e(ts)}</td><td>{e(cls)}</td>"
        f"<td class='{('ok' if res=='PORTED' else 'warn')}'>{e(res)}</td>"
        f"<td class=num>{e(dur)}s</td><td class=num>${cost:.2f}</td></tr>"
        for ts, cls, res, dur, cost in m["recent"])

    sums = "".join(f"<div class=sumline>{e(s)}</div>" for s in m["summaries"]) or "<div class=kv>none yet</div>"

    # dependency frontier panel (from dep_stats.json snapshot)
    dep_html = ""
    dp = m.get("dep")
    if dp:
        rows = "".join(
            f"<tr><td>{e(b)}</td><td class=num>{dp['buckets'][b]['nonUI']:,}</td>"
            f"<td class=num>{dp['buckets'][b]['UI']:,}</td>"
            f"<td class=num>{dp['buckets'][b]['nonUI']+dp['buckets'][b]['UI']:,}</td></tr>"
            for b in dp["bucket_order"])
        seam_pct = (100*dp['seam_done']/dp['seam_total']) if dp.get('seam_total') else 0
        dep_html = f"""
        <h2>Dependency frontier <span style='color:#6b7480;font-weight:400'>(snapshot {dp.get('_age_min','?')}m ago)</span></h2>
        <div class=cards>
          <div class=card><div class=big>{dp['nonui']:,}</div><div class=lbl>non-UI remaining</div></div>
          <div class=card><div class=big>{dp['ui']:,}</div><div class=lbl>UI remaining</div></div>
          <div class=card><div class=big>{dp['keystone_scc']:,}</div><div class=lbl>keystone SCC (cyclic cluster)</div></div>
          <div class=card><div class=big>{dp['seam_done']}/{dp['seam_total']}</div><div class=lbl>seam traits done ({seam_pct:.0f}%)</div></div>
        </div>
        <table><tr><th>remaining deps</th><th class=num>non-UI</th><th class=num>UI</th><th class=num>total</th></tr>{rows}</table>"""

    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta http-equiv=refresh content=60>
<title>ghidra-rs porting status</title>
<style>
:root{{color-scheme:dark}}
body{{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0e1116;color:#d7dce3}}
.wrap{{max-width:980px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:14px;margin:0 0 8px;color:#9aa4b2}}
.sub{{color:#6b7480;font-size:12px;margin-bottom:18px}}
.bar{{position:relative;height:30px;background:#1b212b;border-radius:6px;overflow:hidden;margin:10px 0 20px}}
.fill{{height:100%;background:linear-gradient(90deg,#2a7d5f,#3ba875)}}
.barlbl{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-weight:600}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:18px}}
.card{{background:#161b22;border:1px solid #232a34;border-radius:8px;padding:14px}}
.big{{font-size:26px;font-weight:700}} .lbl{{color:#8b95a3;font-size:12px}}
.run{{border-color:#2a7d5f}} .kv{{font-size:13px;color:#b6bfcb}}
table{{width:100%;border-collapse:collapse;margin:6px 0 22px;font-size:13px}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #1f262f}}
th{{color:#8b95a3;font-weight:600}} .num{{text-align:right;font-variant-numeric:tabular-nums}}
.ok{{color:#3ba875}} .warn{{color:#c9a227}}
.mbar{{height:8px;background:#1b212b;border-radius:4px;overflow:hidden;width:160px}}
.mbar div{{height:100%;background:#3ba875}}
code{{background:#1b212b;padding:1px 5px;border-radius:4px;font-size:12px}}
.sumline{{font-family:ui-monospace,monospace;font-size:12px;color:#aeb7c4;padding:2px 0}}
</style></head><body><div class=wrap>
<h1>ghidra-rs &mdash; Java&rarr;Rust porting</h1>
<div class=sub>generated {e(m['generated'])} &middot; auto-refresh 60s &middot; {m['done']:,} of {m['total']:,} total classes</div>
{bar}
{run_html}
{cards}
{dep_html}
<h2>Progress by module</h2>
<table><tr><th>module</th><th class=num>done</th><th class=num>total</th><th>progress</th><th class=num>%</th></tr>{mod_rows}</table>
<h2>Recent ports</h2>
<table><tr><th>time</th><th>class</th><th>result</th><th class=num>dur</th><th class=num>cost</th></tr>{rec_rows}</table>
<h2>Window summaries (nightly / daytime)</h2>
{sums}
</div></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        try:
            m = compute()
        except Exception as ex:  # never crash the server on a transient read
            self.send_response(500); self.end_headers()
            self.wfile.write(f"error: {ex}".encode()); return
        if self.path.startswith("/metrics.json"):
            body = json.dumps(m, default=str).encode()
            ctype = "application/json"
        else:
            body = render(m).encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"ghidra-rs status dashboard on http://{HOST}:{PORT}  (Ctrl-C to stop)")
    srv.serve_forever()
