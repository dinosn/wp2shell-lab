#!/usr/bin/env bash
# Headless "5-minute install" for the lab WordPress instance (default content, no plugins).
set -euo pipefail
PORT="${WP_PORT:-8093}"
BASE="http://localhost:${PORT}"

echo "[*] waiting for ${BASE} ..."
for _ in $(seq 1 90); do
  curl -sf "${BASE}/wp-admin/install.php" >/dev/null 2>&1 && break
  sleep 1
done

# already installed?
if curl -s "${BASE}/wp-login.php" | grep -q "loginform"; then
  echo "[*] WordPress already installed."
  exit 0
fi

echo "[*] installing WordPress (admin / wp2shell-lab-admin)"
curl -sS "${BASE}/wp-admin/install.php?step=2" \
  --data-urlencode "weblog_title=wp2shell-lab" \
  --data-urlencode "user_name=admin" \
  --data-urlencode "admin_password=wp2shell-lab-admin" \
  --data-urlencode "admin_password2=wp2shell-lab-admin" \
  --data-urlencode "pw_weak=on" \
  --data-urlencode "admin_email=lab@example.com" \
  --data-urlencode "blog_public=0" -o /dev/null -w "[*] install HTTP %{http_code}\n"
echo "[*] ready: ${BASE}"
