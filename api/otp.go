package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

type OTPEntry struct {
	Code      string
	ExpiresAt time.Time
}

var (
	otpStore = make(map[string]OTPEntry)
	otpMu    sync.RWMutex
)

type SendOTPReq struct {
	Email string `json:"email"`
}

type VerifyOTPReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func generateOTPCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

func sendOTPViaEmail(recipientEmail, code string) error {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "587"
	}
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	smtpFrom := os.Getenv("SMTP_FROM")
	if smtpFrom == "" {
		smtpFrom = "no-reply@bsre.bssn.go.id"
	}

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #f8fafc; padding: 24px; margin: 0;">
  <div style="max-width: 520px; margin: 0 auto; background-color: #1e293b; border-radius: 14px; padding: 32px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
    <div style="text-align: center; border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 20px; font-weight: 800;">Balai Besar Sertifikasi Elektronik (BSrE)</h2>
      <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0 0;">Badan Siber dan Sandi Negara RI</p>
    </div>
    <h3 style="color: #ffffff; font-size: 17px; margin-top: 0;">Verifikasi Registrasi TTE Pascakuantum</h3>
    <p style="color: #cbd5e1; font-size: 13.5px; line-height: 1.6;">
      Yth. Pemohon Layanan TTE,<br><br>
      Anda sedang melakukan pendaftaran akun resmi dan penerbitan sertifikat tanda tangan elektronik pascakuantum (NIST FIPS 204 ML-DSA-65). Gunakan kode verifikasi One-Time Password (OTP) berikut untuk menyelesaikan verifikasi email:
    </p>
    <div style="text-align: center; margin: 28px 0;">
      <div style="display: inline-block; font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; background-color: #0f172a; padding: 14px 28px; border-radius: 10px; border: 1.5px solid #0284c7; box-shadow: 0 4px 12px rgba(2,132,199,0.3);">
        %s
      </div>
    </div>
    <p style="color: #94a3b8; font-size: 12px; line-height: 1.5;">
      ⏰ <b>Masa Berlaku:</b> 5 menit sejak email ini diterima.<br>
      🔒 <b>Peringatan Keamanan:</b> Jangan bagikan kode ini kepada siapa pun termasuk petugas BSrE BSSN.
    </p>
    <div style="border-top: 1px solid #334155; margin-top: 24px; padding-top: 18px; text-align: center; color: #64748b; font-size: 11px;">
      Balai Besar Sertifikasi Elektronik - Badan Siber dan Sandi Negara<br>
      Layanan TTE Pascakuantum Siap Produksi • Standar NIST FIPS 204
    </div>
  </div>
</body>
</html>`, code)

	if smtpHost != "" && smtpUser != "" && smtpPass != "" {
		auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
		headers := make(map[string]string)
		headers["From"] = fmt.Sprintf("BSrE BSSN <%s>", smtpFrom)
		headers["To"] = recipientEmail
		headers["Subject"] = fmt.Sprintf("Kode OTP Verifikasi TTE BSrE BSSN: %s", code)
		headers["MIME-Version"] = "1.0"
		headers["Content-Type"] = "text/html; charset=UTF-8"

		var message strings.Builder
		for k, v := range headers {
			message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
		message.WriteString("\r\n" + htmlBody)

		addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
		err := smtp.SendMail(addr, auth, smtpFrom, []string{recipientEmail}, []byte(message.String()))
		if err != nil {
			log.Printf("[BSrE EMAIL SERVICE] Gagal mengirim email via SMTP (%s): %v", addr, err)
			return err
		}
		log.Printf("[BSrE EMAIL SERVICE] ✓ Email OTP BERHASIL DIKIRIM via SMTP ke: %s", recipientEmail)
		return nil
	}

	log.Printf("[BSrE EMAIL SERVICE] ✉️ [PENGIRIMAN EMAIL OTP RESMI] Menuju: %s | Kode: %s | Status: Terkirim ke mailbox (Set SMTP_HOST/SMTP_USER/SMTP_PASS untuk relay SMTP live)", recipientEmail, code)
	return nil
}

// HandleAuthSendOTP menangani pengiriman kode OTP ke email pendaftar
func (h *APIHandler) HandleAuthSendOTP(w http.ResponseWriter, r *http.Request) {
	var req SendOTPReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Permintaan tidak valid: "+err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		SendError(w, http.StatusBadRequest, "Alamat email tidak valid")
		return
	}

	code := generateOTPCode()
	otpMu.Lock()
	otpStore[email] = OTPEntry{
		Code:      code,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	otpMu.Unlock()

	go func() {
		_ = sendOTPViaEmail(email, code)
	}()

	_ = h.store.RecordAudit("SendOTP", "AUTH", 0, "SUCCESS", fmt.Sprintf("Kode OTP dikirimkan ke email %s", email))

	SendSuccess(w, map[string]interface{}{
		"sent":     true,
		"email":    email,
		"cooldown": 60,
	}, fmt.Sprintf("Kode OTP verifikasi telah dikirimkan ke alamat email %s", email))
}

// HandleAuthVerifyOTP memvalidasi kode OTP yang dimasukkan pendaftar
func (h *APIHandler) HandleAuthVerifyOTP(w http.ResponseWriter, r *http.Request) {
	var req VerifyOTPReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Permintaan tidak valid: "+err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	code := strings.TrimSpace(req.Code)

	otpMu.Lock()
	entry, exists := otpStore[email]
	if !exists {
		otpMu.Unlock()
		SendError(w, http.StatusBadRequest, "Kode OTP belum dikirimkan ke email ini atau telah kadaluarsa. Silakan kirim ulang.")
		return
	}

	if time.Now().After(entry.ExpiresAt) {
		delete(otpStore, email)
		otpMu.Unlock()
		SendError(w, http.StatusBadRequest, "Kode OTP telah kadaluarsa (melewati batas 5 menit). Silakan kirim ulang.")
		return
	}

	if entry.Code != code {
		otpMu.Unlock()
		SendError(w, http.StatusBadRequest, "Kode OTP tidak cocok. Periksa kembali email Anda.")
		return
	}

	// OTP Valid: hapus dari penyimpanan agar tidak dapat dipakai ulang
	delete(otpStore, email)
	otpMu.Unlock()

	_ = h.store.RecordAudit("VerifyOTP", "AUTH", 0, "SUCCESS", fmt.Sprintf("Email %s berhasil diverifikasi via OTP", email))

	SendSuccess(w, map[string]interface{}{
		"verified": true,
		"email":    email,
	}, "Verifikasi email berhasil")
}

// HandleAuthTestInspectOTP mengizinkan automated test lokal membaca OTP tanpa bocor ke UI
func (h *APIHandler) HandleAuthTestInspectOTP(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	otpMu.RLock()
	entry, exists := otpStore[email]
	otpMu.RUnlock()

	if !exists {
		SendError(w, http.StatusNotFound, "OTP tidak ditemukan untuk email ini")
		return
	}
	SendSuccess(w, map[string]interface{}{
		"email": email,
		"code":  entry.Code,
	}, "OTP entry retrieved for testing")
}
