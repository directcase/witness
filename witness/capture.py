#!/usr/bin/env python3
"""Capture a web page as evidence: screenshot, traffic and a TLSNotary receipt.

Each capture gets its own folder, grouped by domain and page:

  <out>/<domain>/<page or --id>/<UTC time>/
      evidence.zip          the evidence package:
          screenshot.png        full-page screenshot (headless Chromium)
          page.html, page.txt   rendered DOM and visible text
          browser.har.zip       every request/response the browser made (zipped HAR)
          traffic.warc.gz       raw HTTP exchange of the page and its requisites (wget)
          tlsn/                 TLSNotary session with the witness notary:
                                  receipt.json         signed receipt (contains the transcript)
                                  tlsn.json            summary + receipt checks
                                  transcript-*.bin     request / response bytes
                                  notary-*.json        notary identity at capture time
          manifest.json         metadata, step results, phrase checks, sha256 of every file
      report.pdf            readable summary naming the zip's SHA-256
      evidence.zip.ots      with --timestamp: OpenTimestamps proof of evidence.zip
      report_signed.pdf     with --eidas (create.sh, on the host): eIDAS-signed report

Usage:
  capture.py capture URL [--id ID] [--expect TEXT ...] [--timestamp]
  capture.py batch urls.json [--only ID ...] [--timestamp]
  capture.py serve [--port 8080]        # POST /capture {"url": "...", "expect": [...]}
  capture.py pack [--timestamp]          # zip (+ stamp) capture folders not yet packed
  capture.py upgrade                     # fetch Bitcoin confirmations for pending .ots
  capture.py verify DIR|ZIP              # check hashes, TLSNotary receipt, timestamp, signature
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import traceback
import urllib.parse
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

OUT = Path(os.environ.get("WITNESS_OUT", "/out"))
NOTARY = os.environ.get("WITNESS_NOTARY", "https://pavoltravnik.witness.directcase.ai")
PROVER = os.environ.get("WITNESS_PROVER", "witness-prover")
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)
CONSENT = re.compile(
    r"^\s*(souhlas[íi]m|přijmout|přijímám|povolit|rozumím|ok\b|accept|allow|i agree|agree|got it)",
    re.I,
)


def log(msg: str) -> None:
    print(f"[{dt.datetime.now(dt.timezone.utc):%H:%M:%S}] {msg}", file=sys.stderr, flush=True)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def capture_dir(url: str, cid: str | None, stamp: str) -> Path:
    """<out>/<domain>/<page or id>/<stamp>, e.g. captures/example.org/index/2026-09-26T104417Z"""
    p = urllib.parse.urlsplit(url)
    page = cid or re.sub(r"[^a-z0-9]+", "-", urllib.parse.unquote(
        p.path + ("?" + p.query if p.query else "")).lower()).strip("-")[:80] or "index"
    return OUT / (p.hostname or "unknown") / page / stamp


# ---------------------------------------------------------------------------
# Phrase checks
# ---------------------------------------------------------------------------


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("script", "style", "noscript")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(markup: str) -> str:
    p = _Text()
    p.feed(markup)
    return " ".join(p.parts)


def normalize(text: str) -> str:
    text = html.unescape(text).replace(" ", " ")
    return re.sub(r"\s+", " ", text).strip().casefold()


def http_response_text(raw: bytes) -> str:
    """Body text of a raw HTTP/1.1 response (handles chunked encoding)."""
    head, _, body = raw.partition(b"\r\n\r\n")
    if re.search(rb"(?im)^transfer-encoding:\s*chunked", head):
        out, i = bytearray(), 0
        while i < len(body):
            j = body.find(b"\r\n", i)
            size = int(body[i:j].split(b";")[0] or b"0", 16) if j >= 0 else 0
            if size == 0:
                break
            out += body[j + 2 : j + 2 + size]
            i = j + 2 + size + 2
        body = bytes(out)
    m = re.search(rb"(?im)^content-type:.*charset=([\w-]+)", head)
    text = body.decode(m.group(1).decode() if m else "utf-8", errors="replace")
    return html_to_text(text) if b"html" in head.lower() else text


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def step_browser(url: str, d: Path) -> dict:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(
            user_agent=USER_AGENT,
            locale="cs-CZ",
            viewport={"width": 1366, "height": 900},
        )
        page = ctx.new_page()
        # Playwright's built-in HAR recorder can hang forever on close for some
        # sites, so the HAR is assembled from finished/failed requests instead.
        requests: list = []
        page.on("requestfinished", lambda r: requests.append((r, True)))
        page.on("requestfailed", lambda r: requests.append((r, False)))
        try:
            resp = page.goto(url, wait_until="networkidle", timeout=60_000)
        except Exception as e:
            if "Download is starting" in str(e):
                # PDFs and other files are downloaded, not rendered; the WARC
                # and TLSNotary steps hold the file itself.
                ctx.close()
                browser.close()
                return {"status": None, "content_type": "download", "note": "file download, not rendered"}
            # Pages with endless polling never go idle.
            resp = page.goto(url, wait_until="load", timeout=90_000)
            page.wait_for_timeout(5000)
        log("   browser: loaded")
        ctype = (resp.headers.get("content-type") if resp else "") or ""
        result = {"status": resp.status if resp else None, "content_type": ctype, "final_url": page.url}
        if "html" in ctype:
            page.evaluate(
                """async () => { for (let y = 0; y < document.body.scrollHeight; y += 600) {
                     window.scrollTo(0, y); await new Promise(r => setTimeout(r, 120)); }
                   window.scrollTo(0, 0); }"""
            )
            page.wait_for_timeout(1500)
            log("   browser: scrolled")
            result["consent_clicked"] = dismiss_consent(page)
            log(f"   browser: consent {result['consent_clicked']!r}")
            page.screenshot(path=str(d / "screenshot.png"), full_page=True)
            log("   browser: screenshot")
            (d / "page.html").write_text(page.content())
            text = page.evaluate("() => document.body ? document.body.innerText : ''")
            (d / "page.txt").write_text(text)
            result["text"] = text
        log(f"   browser: text done, writing HAR of {len(requests)} requests")
        write_har(requests, d / "browser.har.zip")
        log("   browser: HAR written")
        ctx.close()
        browser.close()
    return result


def write_har(requests: list, path: Path) -> None:
    """Write a HAR 1.2 log (zipped) of the browser's requests, bodies base64."""
    import base64
    import zipfile

    def hdrs(h: dict) -> list:
        return [{"name": k, "value": v} for k, v in h.items()]

    entries = []
    for req, finished in requests:
        t = req.timing
        started = dt.datetime.fromtimestamp(t["startTime"] / 1000, dt.timezone.utc) if t.get("startTime") else None
        entry = {
            "startedDateTime": started.isoformat() if started else None,
            "time": max(t.get("responseEnd", 0), 0),
            "request": {
                "method": req.method, "url": req.url, "httpVersion": "HTTP/1.1",
                "headers": hdrs(req.headers), "queryString": [], "cookies": [],
                "headersSize": -1, "bodySize": len(req.post_data_buffer or b""),
            },
            "cache": {}, "timings": {"send": 0, "wait": max(t.get("responseStart", 0), 0),
                                      "receive": max(t.get("responseEnd", 0) - t.get("responseStart", 0), 0)},
        }
        # response() blocks forever on a failed request, so only ask finished ones.
        resp = safe(req.response) if finished else None
        if resp is None:
            entry["response"] = {"status": 0, "statusText": req.failure or "failed", "httpVersion": "",
                                 "headers": [], "cookies": [], "content": {"size": 0, "mimeType": ""},
                                 "redirectURL": "", "headersSize": -1, "bodySize": -1}
        else:
            body = safe(resp.body, b"") or b""
            # .headers, not all_headers(): the latter never returns for
            # requests made by web workers.
            headers = resp.headers
            addr = safe(resp.server_addr)
            if addr:
                entry["serverIPAddress"] = addr["ipAddress"]
            entry["response"] = {
                "status": resp.status, "statusText": resp.status_text, "httpVersion": "HTTP/1.1",
                "headers": hdrs(headers), "cookies": [],
                "content": {"size": len(body), "mimeType": headers.get("content-type", ""),
                            "text": base64.b64encode(body).decode(), "encoding": "base64"},
                "redirectURL": headers.get("location", ""), "headersSize": -1, "bodySize": len(body),
            }
        entries.append(entry)
    har = {"log": {"version": "1.2", "creator": {"name": "witness capture.py", "version": "1"},
                   "pages": [], "entries": entries}}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("browser.har", json.dumps(har, ensure_ascii=False))


def safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def dismiss_consent(page) -> str | None:
    """Click a cookie 'accept' button so it does not cover the screenshot."""
    for frame in page.frames:
        try:
            loc = (
                frame.get_by_role("button", name=CONSENT)
                .or_(frame.get_by_role("link", name=CONSENT))
                .or_(frame.get_by_text(CONSENT))
            ).filter(visible=True)
            for el in loc.all():
                label = el.inner_text().strip()
                # Real buttons are short; skip paragraphs that merely start with "Souhlasím…".
                if len(label) > 40:
                    continue
                el.click(timeout=3000)
                page.wait_for_timeout(1000)
                return label
        except Exception:
            continue
    return None


def step_warc(url: str, d: Path) -> dict:
    work = d / "_wget"
    work.mkdir()
    cmd = [
        "wget", "--no-verbose", "--page-requisites", "--span-hosts",
        "--timeout=30", "--tries=2",
        f"--user-agent={USER_AGENT}", "--header=Accept-Language: cs-CZ,cs;q=0.9",
        "--warc-file=" + str(d / "traffic"), "--warc-cdx",
        "--warc-header=operator: witness capture.py",
        "--directory-prefix", str(work), url,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    (d / "wget.log").write_text(p.stdout + p.stderr)
    shutil.rmtree(work, ignore_errors=True)
    if not (d / "traffic.warc.gz").exists():
        raise RuntimeError(f"wget produced no WARC (exit {p.returncode})")
    from warcio.archiveiterator import ArchiveIterator

    with (d / "traffic.warc.gz").open("rb") as f:
        responses = sum(r.rec_type == "response" for r in ArchiveIterator(f))
    if not responses:
        # The WARC is kept: it still records the attempted request.
        raise RuntimeError(f"no HTTP response recorded (wget exit {p.returncode}; see wget.log)")
    # wget exits 8 when any requisite 404s; the WARC is still complete.
    return {"wget_exit": p.returncode, "responses": responses,
            "text": warc_main_text(d / "traffic.warc.gz", url)}


def warc_main_text(warc: Path, url: str) -> str:
    from warcio.archiveiterator import ArchiveIterator

    with warc.open("rb") as f:
        for rec in ArchiveIterator(f):
            if rec.rec_type == "response" and rec.rec_headers.get_header("WARC-Target-URI") == url:
                body = rec.content_stream().read()
                ctype = rec.http_headers.get_header("Content-Type") or ""
                if "html" in ctype:
                    return html_to_text(body.decode("utf-8", errors="replace"))
                return body.decode("utf-8", errors="replace")
    return ""


def step_tlsn(url: str, d: Path) -> dict:
    t = d / "tlsn"
    p = subprocess.run(
        [PROVER, "--url", url, "--notary", NOTARY, "--out", str(t)],
        capture_output=True, text=True, timeout=660,
    )
    (t / "prover.log").write_text(p.stdout + p.stderr) if t.exists() else None
    if p.returncode:
        raise RuntimeError(p.stderr.strip().splitlines()[-1] if p.stderr.strip() else f"exit {p.returncode}")
    summary = json.loads((t / "tlsn.json").read_text())
    summary["text"] = http_response_text((t / "transcript-recv.bin").read_bytes())
    return summary


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


def _child(fn, url, d, q) -> None:
    try:
        q.put(("ok", fn(url, d)))
    except Exception as e:
        q.put(("err", f"{type(e).__name__}: {e}\n{traceback.format_exc()}"))


def run_with_timeout(fn, url: str, d: Path, seconds: int) -> dict:
    """Run a step in a child process so a hung browser cannot stall the batch."""
    import multiprocessing as mp

    import queue

    q = mp.Queue()
    p = mp.Process(target=_child, args=(fn, url, d, q))
    p.start()
    # Read before join: a child cannot exit until a large result is drained.
    try:
        kind, value = q.get(timeout=seconds)
    except queue.Empty:
        p.kill()
        p.join()
        raise TimeoutError(f"step exceeded {seconds}s (partial output kept)")
    p.join(30)
    if p.is_alive():
        p.kill()
    if kind == "err":
        raise RuntimeError(value.splitlines()[0])
    return value


def capture(url: str, cid: str | None = None, expect: list[str] | None = None,
            timestamp: bool = False) -> dict:
    expect = expect or []
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    final = capture_dir(url, cid, stamp)
    d = final / "evidence"  # working folder, packed into evidence.zip
    d.mkdir(parents=True)
    log(f"== {url} -> {d}")
    manifest = {
        "url": url,
        "id": str(final.relative_to(OUT)),
        "started_utc": utc_now(),
        "notary": NOTARY,
        "steps": {},
        "phrases": {},
    }
    for name, fn, limit in (("browser", step_browser, 240), ("warc", step_warc, 360), ("tlsn", step_tlsn, 720)):
        try:
            r = run_with_timeout(fn, url, d, limit)
            text = r.pop("text", "")
            manifest["steps"][name] = {"ok": True, **r}
            if expect:
                norm = normalize(text)
                manifest["phrases"][name] = {p: normalize(p) in norm for p in expect}
            log(f"   {name:7s} ok")
        except Exception as e:
            manifest["steps"][name] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            (d / f"{name}.error.txt").write_text(traceback.format_exc())
            log(f"   {name:7s} FAIL {e}")
    manifest["finished_utc"] = utc_now()
    manifest["files"] = {
        str(p.relative_to(d)): sha256_file(p) for p in sorted(d.rglob("*")) if p.is_file()
    }
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    manifest.update(pack(d, timestamp))
    return manifest


# ---------------------------------------------------------------------------
# Packing, OpenTimestamps, verification
# ---------------------------------------------------------------------------


def pack(d: Path, timestamp: bool = False) -> dict:
    """Zip the working folder <capture>/evidence to <capture>/evidence.zip, write
    <capture>/report.pdf, remove the folder and, if asked, OpenTimestamps-stamp the zip."""
    import zipfile

    zpath = d.parent / "evidence.zip"
    rel = d.parent.relative_to(OUT)
    root = "_".join(rel.parts)  # folder name when the zip is extracted
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(d.rglob("*")):
            if f.is_file():
                z.write(f, f"{root}/{f.relative_to(d)}")
    info = {"zip": str(zpath), "zip_sha256": sha256_file(zpath)}
    try:
        info["report"] = str(make_report(d, zpath, info["zip_sha256"], timestamp))
    except Exception as e:
        info["report_error"] = f"{type(e).__name__}: {e}"
    shutil.rmtree(d)
    if timestamp:
        p = subprocess.run(["ots", "stamp", str(zpath)], capture_output=True, text=True, timeout=120)
        if p.returncode == 0:
            info["ots"] = str(zpath) + ".ots"
        else:
            info["ots_error"] = (p.stderr or p.stdout).strip()[-300:]
    ots = "ok" if "ots" in info else ("FAIL" if timestamp else "off")
    log(f"   packed {rel}/{zpath.name} sha256={info['zip_sha256'][:16]}… report={'ok' if 'report' in info else 'FAIL'} ots={ots}")
    return info


def make_report(d: Path, zpath: Path, zip_sha: str, timestamp: bool) -> Path:
    """Human-readable PDF summary of a capture. It names the zip's SHA-256, so
    signing this PDF (e.g. with an eIDAS qualified signature) covers the zip."""
    import base64
    from playwright.sync_api import sync_playwright

    m = json.loads((d / "manifest.json").read_text())
    st = m["steps"]
    t = st.get("tlsn", {})
    b = st.get("browser", {})
    e = html.escape

    def row(k, v):
        return f"<tr><th>{e(k)}</th><td>{v}</td></tr>"

    def ok(step):
        s = st.get(step, {})
        return "✔ ok" if s.get("ok") else f"✘ {e(s.get('error', 'not run'))}"

    tlsn_rows = ""
    if t.get("ok"):
        n = t.get("receipt_notary_check") or {}
        tlsn_rows = "".join([
            row("Server (TLS certificate)", e(n.get("server_name", ""))),
            row("Notary", e(t.get("notary", ""))),
            row("Mode", e(t.get("mode", ""))),
            row("Verified by notary at", e(n.get("verified_at", ""))),
            row("Notary key id", f"<code>{e(n.get('key_id', ''))}</code>"),
            row("HTTP status", e(str(t.get("http_status", "")))),
            row("Response SHA-256", f"<code>{e(t.get('recv_sha256', ''))}</code>"),
            row("Receipt check", e(t.get("receipt_local_check", {}).get("detail", ""))),
        ])
    phrases = ""
    if m.get("phrases"):
        steps = list(m["phrases"])
        texts = list(next(iter(m["phrases"].values())))
        phrases = "<h2>Expected text</h2><table><tr><th>Phrase</th>" + "".join(
            f"<th>{e(s)}</th>" for s in steps) + "</tr>" + "".join(
            "<tr><td>" + e(p) + "</td>" + "".join(
                f"<td>{'✔' if m['phrases'][s].get(p) else '✘'}</td>" for s in steps) + "</tr>"
            for p in texts) + "</table>"
    files = "".join(f"<tr><td>{e(n)}</td><td><code>{h}</code></td></tr>" for n, h in m["files"].items())
    shot = ""
    if (d / "screenshot.png").exists():
        data = base64.b64encode((d / "screenshot.png").read_bytes()).decode()
        shot = f'<h2 class="pb">Screenshot</h2><img src="data:image/png;base64,{data}">'
    doc = f"""<!doctype html><meta charset="utf-8"><style>
      body{{font:10pt/1.4 'DejaVu Sans',sans-serif;margin:0}} h1{{font-size:16pt;margin:0 0 4pt}}
      h2{{font-size:12pt;margin:14pt 0 4pt}} table{{border-collapse:collapse;width:100%}}
      th,td{{text-align:left;vertical-align:top;padding:2pt 6pt;border-bottom:.5pt solid #ccc}}
      th{{width:32%;font-weight:600}} code{{font:8pt 'DejaVu Sans Mono',monospace;word-break:break-all}}
      .hash{{font:10pt 'DejaVu Sans Mono',monospace;word-break:break-all;background:#f2f2f2;padding:4pt}}
      img{{width:100%}} .pb{{page-break-before:always}} .mu{{color:#555}}
    </style>
    <h1>Web page capture report</h1>
    <p class="mu">Generated {e(utc_now())} by witness capture.py</p>
    <table>{row("URL", e(m["url"]))}{row("Capture id", e(m["id"]))}
      {row("Capture started (UTC)", e(m["started_utc"]))}{row("Capture finished (UTC)", e(m["finished_utc"]))}
      {row("Browser screenshot", ok("browser") + (f" · HTTP {b.get('status')}" if b.get("status") else ""))}
      {row("Traffic (WARC)", ok("warc"))}{row("TLSNotary", ok("tlsn"))}</table>
    <h2>Evidence package</h2>
    <table>{row("Capture folder", e(str(zpath.parent.relative_to(OUT))))}{row("File", e(zpath.name))}
      {row("OpenTimestamps", e(zpath.name + ".ots") if timestamp else "not requested")}</table>
    <p>SHA-256 of the evidence package:</p><p class="hash">{zip_sha}</p>
    {"<h2>TLSNotary</h2><table>" + tlsn_rows + "</table>" if tlsn_rows else ""}
    {phrases}
    <h2>Files in the package</h2><table>{files}</table>
    <p class="mu">Check with: <code>./verify.sh captures/{e(str(zpath.parent.relative_to(OUT)))}</code> — recomputes every hash, checks the
    TLSNotary receipt against the notary's published key and the OpenTimestamps proof.</p>
    {shot}"""
    out = zpath.with_name("report.pdf")
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.set_content(doc, wait_until="load")
        page.pdf(path=str(out), format="A4", print_background=True,
                 margin={"top": "14mm", "bottom": "14mm", "left": "14mm", "right": "14mm"})
        browser.close()
    return out


def cmd_pack(a) -> None:
    for m in sorted(OUT.glob("*/*/*/evidence/manifest.json")):
        pack(m.parent, a.timestamp)


def cmd_upgrade(a) -> None:
    for ots in sorted(OUT.rglob("*.ots")):
        p = subprocess.run(["ots", "upgrade", str(ots)], capture_output=True, text=True, timeout=120)
        Path(str(ots) + ".bak").unlink(missing_ok=True)
        state = "confirmed" if p.returncode == 0 else "pending"
        log(f"{state:9s} {ots.relative_to(OUT)}")


def ots_status(zpath: Path) -> dict:
    """Check the .ots proof: digest matches the zip; Bitcoin attestations are
    checked against block headers from a public Esplora API."""
    import requests
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile

    ots = Path(str(zpath) + ".ots")
    if not ots.exists():
        return {"ok": True, "present": False, "state": "not timestamped"}
    # Retrieve the Bitcoin proof from the calendars if it is ready (in place).
    subprocess.run(["ots", "upgrade", str(ots)], capture_output=True, timeout=120)
    Path(str(ots) + ".bak").unlink(missing_ok=True)
    with ots.open("rb") as f:
        dtf = DetachedTimestampFile.deserialize(StreamDeserializationContext(f))
    digest = dtf.file_digest.hex()
    if digest != sha256_file(zpath):
        return {"ok": False, "error": f".ots is for digest {digest}, not this zip"}
    result = {"ok": True, "present": True, "digest": digest, "pending": [], "bitcoin": []}
    for msg, att in dtf.timestamp.all_attestations():
        if isinstance(att, PendingAttestation):
            result["pending"].append(att.uri)
        elif isinstance(att, BitcoinBlockHeaderAttestation):
            api = "https://blockstream.info/api"
            bhash = requests.get(f"{api}/block-height/{att.height}", timeout=30).text.strip()
            block = requests.get(f"{api}/block/{bhash}", timeout=30).json()
            ok = block["merkle_root"] == msg[::-1].hex()
            result["bitcoin"].append({
                "height": att.height, "block": bhash, "merkle_root_matches": ok,
                "block_time_utc": dt.datetime.fromtimestamp(block["timestamp"], dt.timezone.utc).isoformat(),
            })
            result["ok"] &= ok
    result["state"] = "confirmed" if result["bitcoin"] else "pending (Bitcoin confirmation takes 1-6 h)"
    return result


def receipt_status(z, root: str) -> dict:
    """Verify tlsn/receipt.json against the notary's live key history and /verify."""
    import base64
    import ecdsa
    import requests

    try:
        receipt = json.loads(z.read(f"{root}/tlsn/receipt.json"))
    except KeyError:
        return {"ok": False, "error": "no TLSNotary receipt in capture"}
    notary = json.loads(z.read(f"{root}/manifest.json")).get("notary", NOTARY)
    keys = requests.get(f"{notary}/keys.json", timeout=30).json()["keys"]
    key = next((k for k in keys if k["key_id"] == receipt["key_id"]), None)
    out = {"notary": notary, "key_id": receipt["key_id"]}
    if key is None:
        return {**out, "ok": False, "error": "key_id not in the notary's published key history"}
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(key["public_key"]), curve=ecdsa.SECP256k1)
    try:
        vk.verify(bytes.fromhex(receipt["signature"]), receipt["payload"].encode(), hashfunc=hashlib.sha256)
        out["signature"] = True
    except ecdsa.BadSignatureError:
        out["signature"] = False
    body = json.loads(receipt["payload"])
    at = body.get("verified_at")
    out["verified_at"] = at
    out["server_name"] = body.get("server_name")
    out["in_key_window"] = bool(at and at >= key["created_at"] and (not key["retired_at"] or at <= key["retired_at"]))
    out["transcript_matches"] = all(
        base64.b64decode(body[d]["data_b64"]) == z.read(f"{root}/tlsn/transcript-{d}.bin")
        for d in ("sent", "recv")
    )
    r = requests.post(f"{notary}/verify", json=receipt, timeout=60)
    try:
        out["notary_verify"] = r.json()
    except ValueError:
        # e.g. 413 for receipts above the notary's request-body limit
        out["notary_verify"] = {"valid": None, "http_status": r.status_code, "error": r.text[:200]}
    # The local check against the published key is the proof; the notary's own
    # /verify is a second opinion and only counts against us if it says invalid.
    out["ok"] = out["signature"] and out["in_key_window"] and out["transcript_matches"] \
        and out["notary_verify"].get("valid") is not False
    return out


def verify_zip(zpath: Path, require_timestamp: bool = False, require_eidas: bool = False,
               online: bool = False) -> dict:
    import zipfile

    report = {"zip": str(zpath), "zip_sha256": sha256_file(zpath)}
    with zipfile.ZipFile(zpath) as z:
        root = z.namelist()[0].split("/")[0]
        manifest = json.loads(z.read(f"{root}/manifest.json"))
        report["url"] = manifest["url"]
        report["captured_utc"] = manifest["started_utc"]
        bad = [n for n, h in manifest["files"].items()
               if hashlib.sha256(z.read(f"{root}/{n}")).hexdigest() != h]
        extra = sorted(set(n.split("/", 1)[1] for n in z.namelist() if not n.endswith("/"))
                       - set(manifest["files"]) - {"manifest.json"})
        report["files"] = {"ok": not bad and not extra, "checked": len(manifest["files"]),
                           "mismatched": bad, "unlisted": extra}
        report["tlsn_receipt"] = receipt_status(z, root)
        report["phrases"] = manifest.get("phrases", {})
    report["opentimestamps"] = ots_status(zpath)
    report["report_pdf"] = pdf_status(zpath.with_name("report.pdf"), report["zip_sha256"], signed=False)
    report["signed_report_pdf"] = pdf_status(zpath.with_name("report_signed.pdf"),
                                             report["zip_sha256"], signed=True, online=online)
    if require_timestamp and not report["opentimestamps"].get("present"):
        report["opentimestamps"].update(ok=False, error="--timestamp: no evidence.zip.ots in the capture folder")
    if require_eidas and not report["signed_report_pdf"].get("present"):
        report["signed_report_pdf"].update(ok=False, error="--eidas: no report_signed.pdf in the capture folder")
    report["ok"] = all(report[k]["ok"] for k in
                       ("files", "tlsn_receipt", "opentimestamps", "report_pdf", "signed_report_pdf"))
    return report


def pdf_status(pdf: Path, zip_sha: str, signed: bool, online: bool = False) -> dict:
    """The report must name this zip's SHA-256; a signed report must carry an
    intact, valid PAdES signature."""
    if not pdf.exists():
        return {"ok": True, "present": False}
    text = subprocess.run(["pdftotext", str(pdf), "-"], capture_output=True, text=True).stdout
    out = {"present": True, "file": pdf.name, "names_this_zip": zip_sha in re.sub(r"\s+", "", text)}
    if not signed:
        out["ok"] = out["names_this_zip"]
        return out
    import logging

    for name in ("pyhanko", "pyhanko_certvalidator"):
        logging.getLogger(name).setLevel(logging.CRITICAL)  # path-building noise
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    with pdf.open("rb") as f:
        sigs = PdfFileReader(f).embedded_signatures
        if not sigs:
            return {**out, "ok": False, "error": "no signature in PDF"}
        st = validate_pdf_signature(sigs[-1], ValidationContext(allow_fetching=True))
    ts = st.timestamp_validity
    out.update({
        "signer": st.signing_cert.subject.human_friendly,
        "issuer": st.signing_cert.issuer.human_friendly,
        "intact": st.intact,
        "signature_valid": st.valid,
        "covers_whole_file": st.coverage.name,
        "signing_time_claimed": st.signer_reported_dt.isoformat() if st.signer_reported_dt else None,
        "rfc3161_timestamp": ts.timestamp.isoformat() if ts else None,
        "trusted_here": st.trusted,
        "note": "Qualified (eIDAS) status: validate with the EU DSS validator, "
                "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation",
    })
    out["ok"] = out["names_this_zip"] and st.intact and st.valid
    if online:
        out["eu_dss"] = eu_dss_validate(pdf)
        out["ok"] = out["ok"] and out["eu_dss"].get("indication") == "TOTAL_PASSED"
    return out


EU_DSS = "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/validation/validateSignature"


def eu_dss_validate(pdf: Path) -> dict:
    """Validate a signed PDF with the European Commission's DSS demo service
    (EU Trusted Lists). Sends the PDF to the EC."""
    import base64
    import requests

    body = {"signedDocument": {"bytes": base64.b64encode(pdf.read_bytes()).decode(), "name": pdf.name},
            "originalDocuments": [], "policy": None, "signatureId": None}
    try:
        r = requests.post(EU_DSS, json=body, timeout=180)
        sr = r.json()["SimpleReport"]
    except Exception as e:
        return {"error": f"EU DSS unavailable: {type(e).__name__}: {e}"}
    sigs = [x["Signature"] for x in sr.get("signatureOrTimestampOrEvidenceRecord", []) if x.get("Signature")]
    if not sigs:
        return {"error": "EU DSS found no signature"}
    s = sigs[-1]
    return {
        "indication": s.get("Indication"),
        "sub_indication": s.get("SubIndication"),
        "level": (s.get("SignatureLevel") or {}).get("value"),
        "level_description": (s.get("SignatureLevel") or {}).get("description"),
        "signed_by": s.get("SignedBy"),
        "best_signature_time": s.get("BestSignatureTime"),
        "service": "EU DSS (European Commission), validated against EU Trusted Lists",
    }


def cmd_verify(a) -> None:
    target = Path(a.zip)
    r = verify_zip(target / "evidence.zip" if target.is_dir() else target, a.timestamp, a.eidas, a.online)
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print_summary(r)
    sys.exit(0 if r["ok"] else 1)


def print_summary(r: dict) -> None:
    mark = lambda ok: "OK  " if ok else "FAIL"
    f, t, o = r["files"], r["tlsn_receipt"], r["opentimestamps"]
    rp, sp = r["report_pdf"], r["signed_report_pdf"]
    print(f"Capture   {r['url']}")
    print(f"          captured {r['captured_utc']}   zip sha256 {r['zip_sha256']}")
    print(f"[{mark(f['ok'])}] files          {f['checked']} files match manifest.json"
          + (f"; mismatched {f['mismatched']}" if f["mismatched"] else "")
          + (f"; unlisted {f['unlisted']}" if f["unlisted"] else ""))
    if t.get("error"):
        print(f"[{mark(False)}] tlsn receipt   {t['error']}")
    else:
        nv = t["notary_verify"].get("valid")
        print(f"[{mark(t['ok'])}] tlsn receipt   {t['server_name']} verified by {t['notary']} at {t['verified_at']}")
        print(f"                      signature={t['signature']} key-window={t['in_key_window']} "
              f"transcript={t['transcript_matches']} notary /verify={nv if nv is not None else 'unavailable'}")
    if not o.get("present"):
        print(f"[{mark(o['ok']) if o.get('error') else ' -- '}] timestamp      {o.get('error', 'not timestamped (no .ots)')}")
    elif o.get("error"):
        print(f"[{mark(False)}] timestamp      {o['error']}")
    elif o["bitcoin"]:
        b = o["bitcoin"][0]
        print(f"[{mark(o['ok'])}] timestamp      Bitcoin block {b['height']} at {b['block_time_utc']} "
              f"(merkle root {'matches' if b['merkle_root_matches'] else 'MISMATCH'})")
    else:
        print(f"[ .. ] timestamp      pending at {len(o['pending'])} calendars - Bitcoin confirmation takes 1-6 h, "
              f"re-run verify later")
    print(f"[{mark(rp['ok'])}] report.pdf     " + ("names this zip" if rp.get("names_this_zip")
          else ("not present" if not rp.get("present") else "does NOT name this zip")))
    if not sp.get("present"):
        print(f"[{mark(sp['ok']) if sp.get('error') else ' -- '}] eIDAS          {sp.get('error', 'not signed (no report_signed.pdf)')}")
    else:
        print(f"[{mark(sp['ok'])}] eIDAS          signed by {sp.get('signer')}; intact={sp.get('intact')} "
              f"valid={sp.get('signature_valid')} names-zip={sp.get('names_this_zip')}; "
              f"TSA time {sp.get('rfc3161_timestamp')}")
        d = sp.get("eu_dss")
        if d:
            print(f"                      EU DSS: {d.get('indication') or d.get('error')} "
                  f"{d.get('sub_indication') or ''} level={d.get('level')} ({d.get('level_description')})")
        else:
            print("                      qualified status: run with --online (EU DSS) or upload to "
                  "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation")
    for step, res in r.get("phrases", {}).items():
        for ph, ok in res.items():
            print(f"[{mark(ok)}] phrase ({step:7s}) {ph}")
    print("RESULT:", "VALID" if r["ok"] else "NOT VALID")


def cmd_capture(a) -> None:
    m = capture(a.url, a.id, a.expect, a.timestamp)
    print(json.dumps({k: v for k, v in m.items() if k != "files"}, indent=2, ensure_ascii=False))


def cmd_batch(a) -> None:
    targets = json.loads(Path(a.file).read_text())
    if a.only:
        targets = [t for t in targets if t["id"] in a.only]
    failed = 0
    for t in targets:
        m = capture(t["url"], t["id"], t.get("expect"), a.timestamp)
        failed += not all(s.get("ok") for s in m["steps"].values())
    log(f"done: {len(targets)} targets, {failed} with a failed step")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/capture":
            return self._send(404, {"error": "POST /capture"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            m = capture(body["url"], body.get("id"), body.get("expect"), bool(body.get("timestamp")))
            self._send(200, m)
        except Exception as e:
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def _send(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, indent=2, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def cmd_serve(a) -> None:
    log(f"listening on :{a.port}  (POST /capture {{\"url\": ...}})")
    ThreadingHTTPServer(("0.0.0.0", a.port), Handler).serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("url")
    c.add_argument("--id")
    c.add_argument("--expect", nargs="*", default=[])
    c.add_argument("--timestamp", action="store_true", help="OpenTimestamps-stamp the zip")
    c.set_defaults(fn=cmd_capture)
    b = sub.add_parser("batch")
    b.add_argument("file")
    b.add_argument("--only", nargs="*")
    b.add_argument("--timestamp", action="store_true", help="OpenTimestamps-stamp each zip")
    b.set_defaults(fn=cmd_batch)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)
    k = sub.add_parser("pack")
    k.add_argument("--timestamp", action="store_true")
    k.set_defaults(fn=cmd_pack)
    u = sub.add_parser("upgrade")
    u.set_defaults(fn=cmd_upgrade)
    v = sub.add_parser("verify")
    v.add_argument("zip", help="capture folder or its evidence.zip")
    v.add_argument("--timestamp", action="store_true", help="require an OpenTimestamps proof")
    v.add_argument("--eidas", action="store_true", help="require an eIDAS-signed report")
    v.add_argument("--online", action="store_true", help="validate the eIDAS signature with EU DSS (uploads the report to the EC)")
    v.add_argument("--json", action="store_true", help="full JSON instead of the summary")
    v.set_defaults(fn=cmd_verify)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
