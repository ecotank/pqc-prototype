@echo off
echo ====================================================
echo   ARSIGN PQC - ONBOARDING TIM PENGEMBANG (DEV SETUP)
echo ====================================================
echo.

echo [1/3] Memeriksa instalasi Go...
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Golang belum terinstall di laptop kamu.
    echo Silakan install Golang terlebih dahulu dari: https://go.dev/dl/
    pause
    exit /b 1
)
go version

echo.
echo [2/3] Mengunduh dependensi Go modules...
go mod download
if %errorlevel% neq 0 (
    echo [ERROR] Gagal mengunduh dependensi modul Go.
    pause
    exit /b 1
)

echo.
echo [3/3] Menjalankan Server ARSign Lokal...
echo Portal ARSign akan aktif di: http://localhost:8080
echo.
go run .
pause
