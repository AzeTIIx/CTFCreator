#!/usr/bin/env python3
"""Stress-test XSS admin bots under constrained Docker deployments.

Profiles:
  normal — 512m RAM, 64m shm (plugin-like)
  harsh  — 384m RAM, 16m shm (typical crash conditions)

For each challenge: build, run, trigger bot visits (benign + alert XSS + burst),
parse worker logs for chrome ready / done / rc=0 / timeout / fatal.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

import os  # noqa: E402

# Dossier des challenges : CHALLENGES_ROOT=<client>/challenges ; résultats dans le dossier courant
CHALLENGES = Path(os.environ.get("CHALLENGES_ROOT", ".")).resolve()
OUT = Path("xss-bot-stress-results.json").resolve()
REPORT = Path("xss-bot-stress-results.txt").resolve()

XSS = [
    "xss-reflected",
    "xss-dom",
    "xss-csp-2",
    "xss-stored",
    "xss-blind",
    "xss-csp-1",
]

PROFILES = {
    "normal": {"memory": "512m", "shm": "64m"},
    "harsh": {"memory": "384m", "shm": "16m"},
}

FLAG = "CCTF{bot_stress_token}"


@dataclass
class CaseResult:
    challenge: str
    profile: str
    build_ok: bool = False
    ready: bool = False
    triggers: int = 0
    chrome_ready: int = 0
    chrome_start_fail: int = 0
    bot_done: int = 0
    rc0: int = 0
    rc_nonzero: int = 0
    timeouts: int = 0
    fatals: int = 0
    session_recoveries: int = 0
    elapsed_s: float = 0.0
    status: str = "PENDING"
    detail: str = ""
    log_tail: str = ""


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        **kw,
    )


def _http(
    method: str,
    url: str,
    data: Optional[bytes] = None,
    headers: Optional[dict] = None,
    timeout: float = 15,
) -> tuple[int, str]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body


def _wait_ready(base: str, seconds: int = 60) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        for path in ("/healthz", "/"):
            try:
                code, _ = _http("GET", f"{base}{path}", timeout=2)
                if code < 500:
                    return True
            except Exception:
                pass
        time.sleep(0.5)
    return False


def _form_post(url: str, fields: dict) -> int:
    body = urllib.parse.urlencode(fields).encode()
    code, _ = _http(
        "POST",
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return code


def _parse_logs(logs: str) -> dict:
    return {
        "chrome_ready": len(re.findall(r"\[bot\] chrome ready", logs)),
        "chrome_start_fail": len(re.findall(r"\[bot\] chrome start failed", logs)),
        "bot_done": len(re.findall(r"\[bot\] done", logs)),
        "rc0": len(re.findall(r"subprocess rc=0", logs)),
        "rc_nonzero": len(re.findall(r"subprocess rc=(?!0\b)\d+", logs)),
        "timeouts": len(re.findall(r"subprocess timeout", logs)),
        "fatals": len(re.findall(r"\[bot\] fatal", logs)),
        "session_recoveries": len(re.findall(r"re-init|session dead|visit failed", logs)),
        "cookies_ok": len(re.findall(r"cookies after init: \[", logs)),
    }


# --- trigger strategies -------------------------------------------------


def trigger_reflected(base: str, host_port: int) -> int:
    """Queue URLs for the reflected bot (absolute http URLs)."""
    n = 0
    targets = [
        f"http://127.0.0.1:1337/profile?name=benign",
        f"http://127.0.0.1:1337/profile?name="
        + urllib.parse.quote("<script>alert(1)</script>"),
        f"http://127.0.0.1:1337/profile?name="
        + urllib.parse.quote("<img src=x onerror=alert(document.domain)>"),
        f"http://127.0.0.1:1337/profile?name="
        + urllib.parse.quote("<svg/onload=alert(1)>"),
        f"http://127.0.0.1:1337/",
    ]
    for url in targets:
        code = _form_post(f"{base}/send", {"url": url})
        if code == 200:
            n += 1
        time.sleep(0.3)
    # burst of 3 quick alerts
    for i in range(3):
        payload = urllib.parse.quote(f"<script>alert({i})</script>")
        if _form_post(f"{base}/send", {"url": f"http://127.0.0.1:1337/profile?name={payload}"}) == 200:
            n += 1
    return n


def trigger_dom(base: str, host_port: int) -> int:
    n = 0
    targets = [
        "http://127.0.0.1:1337/erreur?error=hello",
        "http://127.0.0.1:1337/erreur?error="
        + urllib.parse.quote("<img src=x onerror=alert(1)>"),
        "http://127.0.0.1:1337/erreur?error="
        + urllib.parse.quote("<svg/onload=alert(2)>"),
        "http://127.0.0.1:1337/erreur?error="
        + urllib.parse.quote("<script>alert(3)</script>"),
    ]
    for url in targets:
        if _form_post(f"{base}/send", {"url": url}) == 200:
            n += 1
        time.sleep(0.3)
    for i in range(3):
        p = urllib.parse.quote(f"<img src=x onerror=alert({i})>")
        if _form_post(f"{base}/send", {"url": f"http://127.0.0.1:1337/erreur?error={p}"}) == 200:
            n += 1
    return n


def trigger_csp2(base: str, host_port: int) -> int:
    n = 0
    paths = [
        "/preview?msg=benign&theme=default",
        "/preview?msg=" + urllib.parse.quote("<script>alert(1)</script>") + "&theme=default",
        "/preview?msg=" + urllib.parse.quote("<img src=x onerror=alert(1)>") + "&theme=x",
        "/preview?msg=burst&theme=default",
        "/preview?msg=" + urllib.parse.quote("<svg/onload=alert(9)>") + "&theme=t",
    ]
    for path in paths:
        if _form_post(f"{base}/visit", {"url": path}) in (200, 302):
            n += 1
        time.sleep(0.3)
    for i in range(3):
        path = "/preview?msg=" + urllib.parse.quote(f"<script>alert({i})</script>") + "&theme=b"
        if _form_post(f"{base}/visit", {"url": path}) in (200, 302):
            n += 1
    return n


def trigger_stored(base: str, host_port: int) -> int:
    n = 0
    payloads = [
        "commentaire benign stress",
        "<script>alert('stored')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(2)>",
    ]
    for p in payloads:
        if _form_post(f"{base}/article/1", {"auteur": "stress", "contenu": p}) in (200, 302):
            n += 1
        time.sleep(0.2)
    return n


def trigger_blind(base: str, host_port: int) -> int:
    n = 0
    payloads = [
        ("benign ticket", "nothing special here"),
        ("alert ticket", "<script>alert(1)</script>"),
        ("img ticket", "<img src=x onerror=alert(document.cookie)>"),
        ("svg ticket", "<svg/onload=alert(2)>"),
    ]
    for titre, desc in payloads:
        code = _form_post(
            f"{base}/tickets/new",
            {
                "email": "stress@example.com",
                "titre": titre,
                "description": desc,
            },
        )
        if code in (200, 302):
            n += 1
        time.sleep(0.2)
    return n


def trigger_csp1(base: str, host_port: int) -> int:
    n = 0
    payloads = [
        "note benign",
        "<script>alert('csp1')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(3)>",
    ]
    for p in payloads:
        if _form_post(f"{base}/notes/1", {"auteur": "stress", "contenu": p}) in (200, 302):
            n += 1
        time.sleep(0.2)
    return n


TRIGGERS: dict[str, Callable[[str, int], int]] = {
    "xss-reflected": trigger_reflected,
    "xss-dom": trigger_dom,
    "xss-csp-2": trigger_csp2,
    "xss-stored": trigger_stored,
    "xss-blind": trigger_blind,
    "xss-csp-1": trigger_csp1,
}

# How long to wait after triggers for bots to finish rounds
WAIT_AFTER: dict[str, float] = {
    "xss-reflected": 55,  # 8 queued visits * ~5-7s
    "xss-dom": 55,
    "xss-csp-2": 55,
    "xss-stored": 45,  # BOT_INTERVAL forced to 8 + visit time
    "xss-blind": 40,
    "xss-csp-1": 40,
}


def test_one(slug: str, profile: str, port: int) -> CaseResult:
    result = CaseResult(challenge=slug, profile=profile)
    t0 = time.time()
    image = f"xss-botstress-{slug}"
    name = f"botstress-{slug}-{profile}"
    chal = CHALLENGES / slug
    cfg = PROFILES[profile]

    _run(["docker", "rm", "-f", name], timeout=30)

    build = _run(["docker", "build", "-t", image, "."], cwd=str(chal), timeout=900)
    if build.returncode != 0:
        result.status = "BUILD_FAIL"
        result.detail = (build.stderr or build.stdout)[-600:]
        result.elapsed_s = time.time() - t0
        return result
    result.build_ok = True

    run = _run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "512",
            "-m",
            cfg["memory"],
            f"--shm-size={cfg['shm']}",
            "--cpus",
            "1",
            "-e",
            f"FLAG={FLAG}",
            "-e",
            "FRESHNESS_TOKEN=SMOKE",
            "-e",
            "BOT_INTERVAL=8",
            "-p",
            f"{port}:1337",
            image,
        ],
        timeout=60,
    )
    if run.returncode != 0:
        result.status = "RUN_FAIL"
        result.detail = (run.stderr or run.stdout)[-600:]
        result.elapsed_s = time.time() - t0
        return result

    base = f"http://127.0.0.1:{port}"
    try:
        if not _wait_ready(base, 90):
            logs = _run(["docker", "logs", name], timeout=30)
            result.status = "NOT_READY"
            result.log_tail = (logs.stdout or "")[-800:]
            result.elapsed_s = time.time() - t0
            return result
        result.ready = True

        # For periodic bots, wait one quiet cycle so first run is clean, then seed
        if slug in ("xss-stored", "xss-blind", "xss-csp-1"):
            time.sleep(3)

        result.triggers = TRIGGERS[slug](base, port)
        time.sleep(WAIT_AFTER[slug])

        logs = _run(["docker", "logs", name], timeout=30)
        blob = (logs.stdout or "") + "\n" + (logs.stderr or "")
        stats = _parse_logs(blob)
        result.chrome_ready = stats["chrome_ready"]
        result.chrome_start_fail = stats["chrome_start_fail"]
        result.bot_done = stats["bot_done"]
        result.rc0 = stats["rc0"]
        result.rc_nonzero = stats["rc_nonzero"]
        result.timeouts = stats["timeouts"]
        result.fatals = stats["fatals"]
        result.session_recoveries = stats["session_recoveries"]
        result.log_tail = "\n".join(blob.strip().splitlines()[-25:])

        # Verdict
        if result.timeouts > 0 or result.fatals > 0:
            result.status = "UNSTABLE"
            result.detail = f"timeouts={result.timeouts} fatals={result.fatals}"
        elif result.rc_nonzero > 0 and result.rc0 == 0:
            result.status = "FAIL"
            result.detail = f"only non-zero rc (rc_nz={result.rc_nonzero})"
        elif result.chrome_ready == 0:
            result.status = "FAIL"
            result.detail = "chrome never became ready"
        elif result.bot_done == 0 and result.rc0 == 0:
            result.status = "FAIL"
            result.detail = "no successful bot completion"
        elif result.chrome_start_fail > 0 and result.rc0 >= 1:
            result.status = "RESILIENT"  # failed starts but recovered
            result.detail = f"start_fail={result.chrome_start_fail} but rc0={result.rc0}"
        elif result.rc0 >= 1 and result.bot_done >= 1:
            result.status = "PASS"
            result.detail = f"rc0={result.rc0} done={result.bot_done} ready={result.chrome_ready}"
        else:
            result.status = "WEAK"
            result.detail = f"partial: {stats}"
    finally:
        _run(["docker", "rm", "-f", name], timeout=30)

    result.elapsed_s = round(time.time() - t0, 1)
    return result


def main() -> int:
    profiles = sys.argv[1:] or ["normal", "harsh"]
    results: list[CaseResult] = []
    port = 24100

    print("=" * 72)
    print("XSS bot solidity stress suite")
    print(f"profiles: {profiles}")
    print("=" * 72)

    # Build once per challenge (shared image tag)
    for slug in XSS:
        print(f"\n[build] {slug} ...", flush=True)
        image = f"xss-botstress-{slug}"
        b = _run(["docker", "build", "-t", image, "."], cwd=str(CHALLENGES / slug), timeout=900)
        if b.returncode != 0:
            print(f"  BUILD FAIL: {(b.stderr or b.stdout)[-400:]}")
        else:
            print("  OK")

    for profile in profiles:
        if profile not in PROFILES:
            print(f"unknown profile {profile}", file=sys.stderr)
            continue
        for slug in XSS:
            port += 1
            print(f"\n>>> {slug} [{profile}] port={port}", flush=True)
            r = test_one(slug, profile, port)
            results.append(r)
            print(
                f"    {r.status}  triggers={r.triggers} ready={r.chrome_ready} "
                f"done={r.bot_done} rc0={r.rc0} rcNZ={r.rc_nonzero} "
                f"to={r.timeouts} fatal={r.fatals} startFail={r.chrome_start_fail} "
                f"({r.elapsed_s}s) {r.detail}",
                flush=True,
            )

    # Summary
    lines = []
    lines.append("XSS BOT STRESS RESULTS")
    lines.append("=" * 72)
    for r in results:
        lines.append(
            f"{r.challenge:16} {r.profile:8} {r.status:10} "
            f"ready={r.chrome_ready} done={r.bot_done} rc0={r.rc0} "
            f"rcNZ={r.rc_nonzero} timeout={r.timeouts} fatal={r.fatals} "
            f"startFail={r.chrome_start_fail} recover={r.session_recoveries} "
            f"trig={r.triggers} {r.elapsed_s}s"
        )
    lines.append("")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    lines.append("SUMMARY: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    hard_fail = sum(1 for r in results if r.status in ("FAIL", "BUILD_FAIL", "RUN_FAIL", "NOT_READY"))
    unstable = sum(1 for r in results if r.status == "UNSTABLE")
    lines.append(f"hard_fail={hard_fail} unstable={unstable}")
    report = "\n".join(lines)
    print("\n" + report)
    REPORT.write_text(report + "\n", encoding="utf-8")
    OUT.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"\nWrote {REPORT}")
    print(f"Wrote {OUT}")

    return 1 if hard_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
