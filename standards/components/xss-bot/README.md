# Bot XSS durci (Chromium + Selenium)

Composant partagé des challenges XSS (visite admin headless) : survit aux limites du plugin
(RAM faible, `/dev/shm` réduit, FS read-only, USER non-root).

- `bot_xss_hardened.py` : le bot (`bot.py <init_url> <url1> [...]`), à copier en `src/bot.py`.
- `deploy_hardened_bot.py` : copie le bot dans les challenges listés (`TARGETS`).
  `CHALLENGES_ROOT=<client>/challenges python3 deploy_hardened_bot.py`
- `test_xss_bots.py` : stress-test Docker (profils `normal` 512m/64m shm, `harsh` 384m/16m shm).
  `CHALLENGES_ROOT=<client>/challenges python3 test_xss_bots.py`

Image : `chromium chromium-chromedriver nss freetype harfbuzz ttf-freefont` (alpine),
`CHROME_BIN=/usr/bin/chromium`, `CHROMEDRIVER=/usr/bin/chromedriver`. Prévoir `max_memory_mb` ≥ 384.
