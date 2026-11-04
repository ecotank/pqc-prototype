#!/usr/bin/env bash
set -e

echo "===================================================="
echo "  ARSIGN PQC - ONBOARDING TIM PENGEMBANG (DEV SETUP)"
echo "===================================================="
echo ""

echo "[1/3] Memeriksa instalasi Go..."
if ! command -v go &> /dev/null; then
    echo "[ERROR] Golang belum terinstall. Install dari https://go.dev/dl/"
    exit 1
fi
go version

echo ""
echo "[2/3] Mengunduh dependensi Go modules..."
go mod download

echo ""
echo "[3/3] Menjalankan Server ARSign Lokal..."
echo "Portal ARSign aktif di: http://localhost:8080"
echo ""
go run .
