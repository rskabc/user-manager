#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v docker >/dev/null 2>&1; then echo "ERROR: Docker belum terpasang." >&2; exit 1; fi
if ! docker compose version >/dev/null 2>&1; then echo "ERROR: Docker Compose plugin tidak tersedia." >&2; exit 1; fi
if [[ ! -f docker-compose.yml ]]; then echo "ERROR: Jalankan script dari direktori repository user-manager." >&2; exit 1; fi

if [[ -d .git ]]; then
  echo "==> Mengambil pembaruan Git..."
  git pull --ff-only
fi

if [[ ! -f .env ]]; then
  echo "==> Membuat konfigurasi awal .env..."
  cp .env.example .env
  JWT_SECRET="$(openssl rand -hex 32)"
  APP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
  ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '\n')"
  sed -i "s|GANTI_DENGAN_SECRET_ACAK_MINIMAL_32_KARAKTER|$JWT_SECRET|" .env
  sed -i "s|GANTI_DENGAN_OUTPUT_OPENSSL_RAND_HEX_32_64_KARAKTER|$APP_ENCRYPTION_KEY|" .env
  sed -i "s|GANTI_DENGAN_PASSWORD_KUAT_MINIMAL_12_KARAKTER|$ADMIN_PASSWORD|" .env
  chmod 600 .env
  echo
  echo "PENTING — simpan kredensial admin awal berikut sekarang:"
  echo "Username : admin"
  echo "Password : $ADMIN_PASSWORD"
  echo "Password ini hanya ditampilkan pada pembuatan .env pertama."
  echo "Simpan dengan aman. Jangan commit file .env ke Git."
  echo
fi

if grep -Eq 'GANTI_DENGAN|^JWT_SECRET=$|^APP_ENCRYPTION_KEY=$|^ADMIN_PASSWORD=$' .env; then
  echo "ERROR: .env masih berisi placeholder. Perbaiki .env sebelum deploy." >&2
  exit 1
fi

echo "==> Build dan jalankan aplikasi..."
docker compose up -d --build --remove-orphans
echo "==> Status container:"
docker compose ps
APP_PORT_VALUE="$(grep '^APP_PORT=' .env | cut -d= -f2 | tr -d '\r' || true)"
APP_PORT_VALUE="${APP_PORT_VALUE:-8224}"
echo
echo "Aplikasi: http://localhost:${APP_PORT_VALUE}"
echo "Untuk log: docker compose logs -f --tail=100"
