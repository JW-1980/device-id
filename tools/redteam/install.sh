#!/bin/sh
# Installs the red-team tools into a scratch directory (never into the repo):
#   npm run redteam:install -- /path/to/scratch
# Needs node, python3 and network access. The browsers are NOT downloaded here: the Chromium-based
# tools drive the Playwright Chromium (PLAYWRIGHT_BROWSERS_PATH, default /opt/pw-browsers) or REDTEAM_CHROME.
set -eu
DIR="${1:-${REDTEAM_DIR:-$(pwd)/.redteam}}"
mkdir -p "$DIR/node"
cd "$DIR/node"
[ -f package.json ] || npm init -y >/dev/null
npm i --no-audit --no-fund puppeteer-core@24 puppeteer-extra puppeteer-extra-plugin-stealth rebrowser-puppeteer-core patchright-core
cd "$DIR"
[ -d venv ] || python3 -m venv venv
./venv/bin/pip install -q camoufox nodriver undetected-chromedriver playwright-stealth setuptools
# Camoufox's own browser is a separate download from its GitHub releases; skip quietly when that is blocked.
./venv/bin/python -m camoufox fetch || echo "camoufox browser not downloaded; the camoufox run will be reported as not installed"
# A chromedriver of the same version as the Chromium (undetected-chromedriver refuses a mismatch), from Chrome for Testing.
CHROME="${REDTEAM_CHROME:-$(ls -d "${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}"/chromium-*/chrome-linux*/chrome 2>/dev/null | tail -1)}"
if [ -n "$CHROME" ] && [ ! -x "$DIR/chromedriver/chromedriver" ]; then
    VERSION="$("$CHROME" --version | grep -oE '[0-9]+(\.[0-9]+){3}' | head -1)"
    mkdir -p "$DIR/chromedriver" "$DIR/chromedriver.tmp"
    curl -fsSL -o "$DIR/chromedriver.tmp/cd.zip" "https://storage.googleapis.com/chrome-for-testing-public/$VERSION/linux64/chromedriver-linux64.zip" \
        && python3 -I -c "import sys,zipfile;zipfile.ZipFile(sys.argv[1]).extract('chromedriver-linux64/chromedriver', sys.argv[2])" "$DIR/chromedriver.tmp/cd.zip" "$DIR/chromedriver.tmp" \
        && mv "$DIR/chromedriver.tmp/chromedriver-linux64/chromedriver" "$DIR/chromedriver/chromedriver" && chmod +x "$DIR/chromedriver/chromedriver" \
        || echo "no chromedriver $VERSION downloaded; undetected-chromedriver will fail until REDTEAM_CHROMEDRIVER points at one"
    rm -rf "$DIR/chromedriver.tmp"
fi
echo "Installed in $DIR. Run: npm run redteam -- --dir=$DIR"
