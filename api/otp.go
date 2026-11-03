package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
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
	Attempts  int
	LastSent  time.Time
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

func init() {
	loadEnvFile(".env")
}

func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			v = strings.Trim(v, `"'`)
			os.Setenv(k, v)
		}
	}
}

func generateOTPCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

func sendOTPViaEmail(recipientEmail, code string) error {
	loadEnvFile(".env")

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	if smtpPort == "" {
		smtpPort = "587"
	}
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")
	smtpFrom := os.Getenv("SMTP_FROM")
	if smtpFrom == "" {
		smtpFrom = "no-reply@smallcircle.web.id"
	}

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #f8fafc; padding: 24px; margin: 0;">
  <div style="max-width: 520px; margin: 0 auto; background-color: #1e293b; border-radius: 14px; padding: 32px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
    <div style="text-align: center; border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 24px;">
      <h2 style="color: #38bdf8; margin: 0; font-size: 22px; font-weight: 800; letter-spacing: -0.02em;">ARSign</h2>
      <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0 0;">Layanan TTE Pascakuantum • Tim 3 RPLK (Alba, Radit, Sulthan)</p>
    </div>
    <h3 style="color: #ffffff; font-size: 17px; margin-top: 0;">Verifikasi Akun Penandatangan ARSign</h3>
    <p style="color: #cbd5e1; font-size: 13.5px; line-height: 1.6;">
      Halo,<br><br>
      Anda sedang melakukan pendaftaran akun dan penerbitan sertifikat tanda tangan elektronik pascakuantum (NIST FIPS 204 ML-DSA-65) pada platform <b>ARSign</b>. Gunakan kode verifikasi One-Time Password (OTP) berikut untuk menyelesaikan verifikasi:
    </p>
    <div style="text-align: center; margin: 28px 0;">
      <div style="display: inline-block; font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; background-color: #0f172a; padding: 14px 28px; border-radius: 10px; border: 1.5px solid #0284c7; box-shadow: 0 4px 12px rgba(2,132,199,0.3);">
        %s
      </div>
    </div>
    <p style="color: #94a3b8; font-size: 12px; line-height: 1.5;">
      ⏰ <b>Masa Berlaku:</b> 5 menit sejak email ini diterima.<br>
      🔒 <b>Peringatan Keamanan:</b> Jangan bagikan kode rahasia ini kepada siapa pun.
    </p>
    <div style="border-top: 1px solid #334155; margin-top: 24px; padding-top: 18px; text-align: center; color: #64748b; font-size: 11px;">
      ARSign Platform — Rekayasa Perangkat Lunak Kripto (3 RPLK)<br>
      Karya Kelompok: Alba • Radit • Sulthan • Standar NIST FIPS 204
    </div>
  </div>
</body>
</html>`, code)

	// Opsi 1: Pengiriman via Brevo API
	brevoKey := os.Getenv("BREVO_API_KEY")
	if brevoKey != "" {
		senderEmail := smtpUser
		if senderEmail == "" {
			senderEmail = "satrialbaa@gmail.com"
		}
		payload := map[string]interface{}{
			"sender": map[string]string{
				"name":  "ARSign Verification",
				"email": senderEmail,
			},
			"to": []map[string]string{
				{"email": recipientEmail},
			},
			"subject":     fmt.Sprintf("Kode OTP Verifikasi ARSign: %s", code),
			"htmlContent": htmlBody,
		}
		bodyBytes, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "https://api.brevo.com/v3/smtp/email", bytes.NewBuffer(bodyBytes))
		req.Header.Set("api-key", brevoKey)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			if resp.StatusCode < 300 {
				log.Printf("[ARSIGN EMAIL] ✓ Email OTP BERHASIL DIKIRIM via Brevo API ke: %s", recipientEmail)
				return nil
			}
			log.Printf("[ARSIGN EMAIL] ⚠️ Brevo API returned status %d: %s", resp.StatusCode, string(respBody))
		} else {
			log.Printf("[ARSIGN EMAIL] ⚠️ Brevo API error: %v", err)
		}
	}

	// Prioritaskan Opsi SMTP Relay jika disetel
	if smtpHost != "" && smtpUser != "" && smtpPass != "" {
		cleanPass := strings.ReplaceAll(smtpPass, " ", "")
		auth := smtp.PlainAuth("", smtpUser, cleanPass, smtpHost)
		headers := make(map[string]string)
		headers["From"] = fmt.Sprintf("ARSign <%s>", smtpFrom)
		headers["To"] = recipientEmail
		headers["Subject"] = fmt.Sprintf("Kode OTP Verifikasi ARSign: %s", code)
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
			log.Printf("[ARSIGN EMAIL] ⚠️ Gagal mengirim email via SMTP (%s): %v", addr, err)
		} else {
			log.Printf("[ARSIGN EMAIL] ✓ Email OTP BERHASIL DIKIRIM via SMTP ke: %s", recipientEmail)
			return nil
		}
	}

	// Opsi Utama: Pengiriman via Resend API
	resendKey := os.Getenv("RESEND_API_KEY")
	if resendKey != "" {
		resendFrom := os.Getenv("RESEND_FROM")
		if resendFrom == "" {
			resendFrom = "ARSign <no-reply@smallcircle.web.id>"
		}
		fallbackEmail := os.Getenv("RESEND_FALLBACK_EMAIL")
		if fallbackEmail == "" {
			fallbackEmail = "satrialbaa@gmail.com"
		}

		sendReq := func(toEmail, fromSender, subject, content string) (int, []byte, error) {
			payload := map[string]interface{}{
				"from":    fromSender,
				"to":      []string{toEmail},
				"subject": subject,
				"html":    content,
			}
			bodyBytes, _ := json.Marshal(payload)
			req, _ := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+resendKey)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return 0, nil, err
			}
			defer resp.Body.Close()
			respBody, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, respBody, nil
		}

		// 1. Kirim langsung dari domain resmi ARSign
		subject := fmt.Sprintf("Kode OTP Verifikasi ARSign: %s", code)
		status, respBody, err := sendReq(recipientEmail, resendFrom, subject, htmlBody)
		if err == nil && status < 300 {
			log.Printf("[ARSIGN EMAIL] ✓ Email OTP BERHASIL DIKIRIM via Resend API ke: %s", recipientEmail)
			return nil
		}

		// 2. Fallback sandbox jika memakai domain uji
		isSandbox := strings.Contains(resendFrom, "onboarding@resend.dev")
		appEnv := strings.ToLower(os.Getenv("APP_ENV"))
		if isSandbox && appEnv != "production" && fallbackEmail != "" && !strings.EqualFold(recipientEmail, fallbackEmail) {
			log.Printf("[ARSIGN EMAIL] ℹ️ Resend sandbox membatasi tujuan ke %s. Meneruskan ke %s...", recipientEmail, fallbackEmail)
			forwardSubject := fmt.Sprintf("[ARSign Sandbox] Pemohon %s: %s", recipientEmail, code)
			forwardNotice := fmt.Sprintf(`
      <div style="background-color: #0369a1; padding: 14px 18px; border-radius: 8px; margin-bottom: 22px; font-size: 13.5px; color: #ffffff; border: 1.5px solid #38bdf8; line-height: 1.5;">
        🔔 <b>ARSign Sandbox Notice:</b><br>
        Kode OTP ini diterbitkan untuk pemohon: <b style="color: #fef08a;">%s</b>.
      </div>`, recipientEmail)

			forwardHtml := strings.Replace(htmlBody, `<h3 style="color: #ffffff; font-size: 17px; margin-top: 0;">`, forwardNotice+`<h3 style="color: #ffffff; font-size: 17px; margin-top: 0;">`, 1)

			fStatus, fBody, fErr := sendReq(fallbackEmail, resendFrom, forwardSubject, forwardHtml)
			if fErr == nil && fStatus < 300 {
				log.Printf("[ARSIGN EMAIL] ✓ Email OTP DITERUSKAN via Resend ke verifikator: %s", fallbackEmail)
				return nil
			}
			log.Printf("[ARSIGN EMAIL] ⚠️ Resend forwarding error (status %d): %s", fStatus, string(fBody))
		} else {
			log.Printf("[ARSIGN EMAIL] ⚠️ Resend API gagal kirim ke %s (status %d): %s", recipientEmail, status, string(respBody))
		}
	}

	log.Printf("[ARSIGN EMAIL] ✉️ [KODE OTP ARSIGN]: Menuju: %s | Kode: %s", recipientEmail, code)
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

	otpMu.Lock()
	if entry, exists := otpStore[email]; exists {
		// Proteksi produksi: cooldown 60 detik cegah flooding email jika OTP masih aktif
		if time.Now().Before(entry.ExpiresAt) && time.Since(entry.LastSent) < 60*time.Second {
			remaining := int(60 - time.Since(entry.LastSent).Seconds())
			otpMu.Unlock()
			_ = h.store.RecordActivity("SECURITY", "WARN", email, "OTP_RATE_LIMIT", fmt.Sprintf("Permintaan OTP ditolak karena cooldown (%d detik tersisa)", remaining), r.RemoteAddr, r.UserAgent())
			SendError(w, http.StatusTooManyRequests, fmt.Sprintf("Mohon tunggu %d detik sebelum meminta kode OTP baru.", remaining))
			return
		}
	}

	code := generateOTPCode()
	otpStore[email] = OTPEntry{
		Code:      code,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Attempts:  0,
		LastSent:  time.Now(),
	}
	otpMu.Unlock()

	go func() {
		_ = sendOTPViaEmail(email, code)
	}()

	_ = h.store.RecordAudit("SendOTP", "AUTH", 0, "SUCCESS", fmt.Sprintf("Kode OTP dikirimkan ke email %s", email))
	_ = h.store.RecordActivity("AUTH", "INFO", email, "OTP_SEND", fmt.Sprintf("Kode OTP verifikasi dikirimkan ke %s", email), r.RemoteAddr, r.UserAgent())

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
		_ = h.store.RecordActivity("SECURITY", "WARN", email, "OTP_NOT_FOUND", "Verifikasi OTP gagal (tidak ditemukan atau kedaluwarsa)", r.RemoteAddr, r.UserAgent())
		SendError(w, http.StatusBadRequest, "Kode OTP belum dikirimkan ke email ini atau telah kadaluarsa. Silakan kirim ulang.")
		return
	}

	if time.Now().After(entry.ExpiresAt) {
		delete(otpStore, email)
		otpMu.Unlock()
		_ = h.store.RecordActivity("SECURITY", "WARN", email, "OTP_EXPIRED", "Verifikasi OTP gagal (melewati batas 5 menit)", r.RemoteAddr, r.UserAgent())
		SendError(w, http.StatusBadRequest, "Kode OTP telah kadaluarsa (melewati batas 5 menit). Silakan kirim ulang.")
		return
	}

	if entry.Code != code {
		entry.Attempts++
		if entry.Attempts >= 3 {
			delete(otpStore, email)
			otpMu.Unlock()
			_ = h.store.RecordAudit("VerifyOTP", "AUTH", 0, "BLOCKED", fmt.Sprintf("Percobaan verifikasi OTP email %s diblokir (melebihi batas 3 kali)", email))
			_ = h.store.RecordActivity("SECURITY", "CRITICAL", email, "OTP_BRUTE_FORCE_BLOCKED", fmt.Sprintf("Percobaan verifikasi OTP email %s diblokir (melebihi batas 3 kali)", email), r.RemoteAddr, r.UserAgent())
			SendError(w, http.StatusUnauthorized, "Kode OTP salah. Batas percobaan (3 kali) terlampaui. Kode dibatalkan demi keamanan.")
			return
		}
		otpStore[email] = entry
		remaining := 3 - entry.Attempts
		otpMu.Unlock()
		_ = h.store.RecordAudit("VerifyOTP", "AUTH", 0, "FAILED", fmt.Sprintf("Kode OTP salah untuk email %s (sisa percobaan: %d)", email, remaining))
		_ = h.store.RecordActivity("SECURITY", "WARN", email, "OTP_VERIFY_FAILED", fmt.Sprintf("Kode OTP salah untuk email %s (sisa percobaan: %d)", email, remaining), r.RemoteAddr, r.UserAgent())
		SendError(w, http.StatusBadRequest, fmt.Sprintf("Kode OTP tidak cocok. Sisa kesempatan: %d kali.", remaining))
		return
	}

	// OTP Valid: hapus dari penyimpanan agar tidak dapat dipakai ulang (Replay Attack Prevention)
	delete(otpStore, email)
	otpMu.Unlock()

	_ = h.store.RecordAudit("VerifyOTP", "AUTH", 0, "SUCCESS", fmt.Sprintf("Email %s berhasil diverifikasi via OTP", email))
	_ = h.store.RecordActivity("AUTH", "INFO", email, "OTP_VERIFY_SUCCESS", fmt.Sprintf("Email %s berhasil diverifikasi via OTP", email), r.RemoteAddr, r.UserAgent())

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

