# -*- coding: utf-8 -*-
"""
Bot XSS/admin headless - Chromium + Selenium, durci pour Docker/CTFd.

Usage: bot.py <init_url> <url1> [<url2> ...]

Visite d'abord init_url (Set-Cookie flag/session), puis chaque cible.
Concu pour survivre aux deploiements constrains (peu de RAM, /dev/shm petit,
FS read-only, USER non-root).
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import traceback
from typing import Optional

from selenium import webdriver
from selenium.common.exceptions import (
    InvalidSessionIdException,
    TimeoutException,
    WebDriverException,
)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def _log(msg: str) -> None:
    print(f"[bot] {msg}", flush=True)


def _find_chromium() -> str:
    env = os.environ.get("CHROME_BIN") or os.environ.get("CHROMIUM_PATH")
    candidates = [
        env,
        shutil.which("chromium-browser"),
        shutil.which("chromium"),
        shutil.which("google-chrome"),
        shutil.which("chrome"),
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/usr/lib/chromium/chrome",
        "/usr/lib/chromium/chromium",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise FileNotFoundError(
        "chromium binary not found (set CHROME_BIN). Tried: "
        + ", ".join(p for p in candidates if p)
    )


def _find_chromedriver() -> str:
    env = os.environ.get("CHROMEDRIVER") or os.environ.get("CHROMEDRIVER_PATH")
    candidates = [
        env,
        shutil.which("chromedriver"),
        "/usr/bin/chromedriver",
        "/usr/lib/chromium/chromedriver",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise FileNotFoundError("chromedriver not found (set CHROMEDRIVER)")


def _build_options(profile_dir: str, *, headless_mode: str) -> Options:
    opts = Options()
    if headless_mode == "new":
        opts.add_argument("--headless=new")
    else:
        opts.add_argument("--headless")

    # Docker / CTFd essentials
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--disable-software-rasterizer")

    # Stability: avoid --single-process (crashes often under Alpine/Docker)
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-background-networking")
    opts.add_argument("--disable-background-timer-throttling")
    opts.add_argument("--disable-renderer-backgrounding")
    opts.add_argument("--disable-backgrounding-occluded-windows")
    opts.add_argument("--disable-breakpad")
    opts.add_argument("--disable-component-update")
    opts.add_argument("--disable-default-apps")
    opts.add_argument("--disable-domain-reliability")
    opts.add_argument("--disable-features=TranslateUI,BlinkGenPropertyTrees,IsolateOrigins,site-per-process")
    opts.add_argument("--disable-hang-monitor")
    opts.add_argument("--disable-ipc-flooding-protection")
    opts.add_argument("--disable-popup-blocking")
    opts.add_argument("--disable-prompt-on-repost")
    opts.add_argument("--disable-sync")
    opts.add_argument("--metrics-recording-only")
    opts.add_argument("--no-first-run")
    opts.add_argument("--no-default-browser-check")
    opts.add_argument("--mute-audio")
    opts.add_argument("--window-size=1024,768")
    opts.add_argument("--remote-debugging-port=0")
    opts.add_argument(f"--user-data-dir={profile_dir}")
    opts.add_argument(f"--data-path={os.path.join(profile_dir, 'data')}")
    opts.add_argument(f"--disk-cache-dir={os.path.join(profile_dir, 'cache')}")
    opts.add_argument("--password-store=basic")
    opts.add_argument("--use-mock-keychain")

    opts.set_capability("unhandledPromptBehavior", "dismiss")
    opts.binary_location = _find_chromium()
    opts.page_load_strategy = "eager"
    return opts


def _create_driver(profile_dir: str, headless_mode: str) -> webdriver.Chrome:
    opts = _build_options(profile_dir, headless_mode=headless_mode)
    service = Service(
        executable_path=_find_chromedriver(),
        log_output=os.devnull,
    )
    driver = webdriver.Chrome(service=service, options=opts)
    driver.set_page_load_timeout(20)
    driver.set_script_timeout(15)
    try:
        driver.implicitly_wait(0)
    except Exception:
        pass
    return driver


def _start_driver_with_retries(profile_dir: str, attempts: int = 3) -> webdriver.Chrome:
    last_err: Optional[BaseException] = None
    for mode in ("new", "legacy"):
        for i in range(1, attempts + 1):
            try:
                _log(f"starting chrome (headless={mode}, try={i}/{attempts})")
                driver = _create_driver(profile_dir, headless_mode=mode)
                _log("chrome ready")
                return driver
            except Exception as e:
                last_err = e
                _log(f"chrome start failed: {type(e).__name__}: {e}")
                time.sleep(0.8 * i)
    assert last_err is not None
    raise last_err


def _dismiss_alerts(driver: webdriver.Chrome, rounds: int = 5) -> None:
    for _ in range(rounds):
        try:
            WebDriverWait(driver, 0.3).until(EC.alert_is_present())
            driver.switch_to.alert.dismiss()
        except Exception:
            break


def _safe_get(driver: webdriver.Chrome, url: str, settle: float = 2.0) -> None:
    try:
        driver.get(url)
    except TimeoutException:
        _log(f"page load timeout on {url!r} (continuing)")
        try:
            driver.execute_script("window.stop();")
        except Exception:
            pass
    except InvalidSessionIdException:
        raise
    except WebDriverException as e:
        # Navigation aborted / renderer crash - re-raise session deaths only
        msg = str(e).lower()
        if "invalid session" in msg or "disconnected" in msg or "chrome not reachable" in msg:
            raise
        _log(f"navigation warning: {str(e).splitlines()[0]}")
    time.sleep(settle)
    _dismiss_alerts(driver)


def _session_alive(driver: webdriver.Chrome) -> bool:
    try:
        _ = driver.current_url
        return True
    except Exception:
        return False


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: bot.py <init_url> <url1> [<url2> ...]", flush=True)
        return 2

    # Writable dirs for non-root + read_only rootfs deployments
    os.environ.setdefault("HOME", "/tmp")
    os.environ.setdefault("XDG_CONFIG_HOME", "/tmp/.config")
    os.environ.setdefault("XDG_CACHE_HOME", "/tmp/.cache")
    os.environ.setdefault("XDG_DATA_HOME", "/tmp/.local/share")

    init_url = sys.argv[1]
    targets = sys.argv[2:]

    profile_dir = tempfile.mkdtemp(prefix="chrome-bot-", dir="/tmp")
    driver: Optional[webdriver.Chrome] = None

    try:
        try:
            chromium = _find_chromium()
            chromedriver = _find_chromedriver()
            _log(f"chromium={chromium}")
            _log(f"chromedriver={chromedriver}")
        except FileNotFoundError as e:
            _log(str(e))
            return 1

        driver = _start_driver_with_retries(profile_dir)

        # Init cookie / session
        for attempt in range(1, 4):
            try:
                _log(f"init visit try={attempt} url=<redacted>")
                _safe_get(driver, init_url, settle=1.0)
                cookies = driver.get_cookies()
                _log(f"cookies after init: {[c.get('name') for c in cookies]}")
                break
            except Exception as e:
                _log(f"init failed: {type(e).__name__}: {e}")
                if attempt == 3:
                    return 1
                try:
                    driver.quit()
                except Exception:
                    pass
                driver = _start_driver_with_retries(profile_dir)

        # Visit targets with one session-recovery retry each
        for url in targets:
            _log(f"visit {url!r}")
            for attempt in range(1, 3):
                try:
                    if not _session_alive(driver):
                        raise InvalidSessionIdException("session dead before visit")
                    _safe_get(driver, url, settle=2.5)
                    break
                except (InvalidSessionIdException, WebDriverException) as e:
                    _log(f"visit failed try={attempt}: {type(e).__name__}: {str(e).splitlines()[0]}")
                    if attempt == 2:
                        break
                    try:
                        driver.quit()
                    except Exception:
                        pass
                    driver = _start_driver_with_retries(profile_dir)
                    try:
                        _safe_get(driver, init_url, settle=1.0)
                    except Exception as e2:
                        _log(f"re-init failed: {e2}")
                        return 1

        _log("done")
        return 0
    except Exception as e:
        _log(f"fatal: {type(e).__name__}: {e}")
        traceback.print_exc()
        return 1
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass
        # Best-effort cleanup of profile (ignore errors on busy files)
        try:
            shutil.rmtree(profile_dir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
