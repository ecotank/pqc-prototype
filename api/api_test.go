package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"pqc-prototype/storage"
)

// TestMain mengalihkan direktori material CA ke direktori sementara agar
// pengujian tidak menulis apa pun ke dalam repo.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "arsign-api-ca-")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("ARSIGN_CA_DIR", tmp)
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

func newTestHandler(t *testing.T) *APIHandler {
	t.Helper()
	store, err := storage.InitStorage(filepath.Join(t.TempDir(), "uji.db"))
	if err != nil {
		t.Fatalf("InitStorage gagal: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewAPIHandler(store)
}

func doJSON(t *testing.T, h http.HandlerFunc, method, target string, payload any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()

	body := bytes.NewReader(nil)
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("gagal menyusun payload: %v", err)
		}
		body = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)

	var decoded map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	return rec, decoded
}

// registerSigner mendaftarkan akun uji beserta passphrase penandatanganannya.
func registerSigner(t *testing.T, h *APIHandler) (username, password, passphrase string) {
	t.Helper()

	username, password, passphrase = "penanda.uji", "KataSandiUji#2026", "PassphraseUji#2026"

	rec, body := doJSON(t, h.HandleAuthRegister, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"fullname":    "Pejabat Penandatangan Resmi, S.Kom.",
		"username":    username,
		"password":    password,
		"nik_nip":     "199910262024011001",
		"institution": "ARSign Trust Network",
		"email":       "penanda.uji@smallcircle.web.id",
		"role":        "ASN",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("pendaftaran gagal (HTTP %d): %s", rec.Code, rec.Body.String())
	}
	data, _ := body["data"].(map[string]any)
	if data["mldsa_private_key"] != nil {
		t.Fatal("respons pendaftaran membocorkan mldsa_private_key")
	}
	if data["password_hash"] != nil {
		t.Fatal("respons pendaftaran membocorkan password_hash")
	}

	rec, _ = doJSON(t, h.HandleSetPassphrase, http.MethodPost, "/api/v1/auth/passphrase/set", map[string]string{
		"username":   username,
		"password":   password,
		"passphrase": passphrase,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("penyetelan passphrase gagal (HTTP %d): %s", rec.Code, rec.Body.String())
	}
	return username, password, passphrase
}

// minimalPDFBase64 mengembalikan PDF minimal terkode base64 untuk bahan uji.
func minimalPDFBase64() string {
	pdf := "%PDF-1.7\n" +
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
		"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n" +
		"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
	return base64Encode([]byte(pdf))
}

func base64Encode(src []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(src); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], src[i:])
		v := uint32(chunk[0])<<16 | uint32(chunk[1])<<8 | uint32(chunk[2])
		out = append(out, alphabet[(v>>18)&0x3f], alphabet[(v>>12)&0x3f])
		if n > 1 {
			out = append(out, alphabet[(v>>6)&0x3f])
		} else {
			out = append(out, '=')
		}
		if n > 2 {
			out = append(out, alphabet[v&0x3f])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}

func TestHandleAuthLoginDoesNotLeakSecrets(t *testing.T) {
	h := newTestHandler(t)
	username, password, _ := registerSigner(t, h)

	rec, body := doJSON(t, h.HandleAuthLogin, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": username,
		"password": password,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login gagal (HTTP %d): %s", rec.Code, rec.Body.String())
	}

	data, _ := body["data"].(map[string]any)
	for _, field := range []string{"mldsa_private_key", "password_hash", "signing_passphrase_hash"} {
		if data[field] != nil {
			t.Errorf("respons login membocorkan %s", field)
		}
	}
	if data["mldsa_public_key"] == nil {
		t.Error("kunci publik seharusnya tetap dipublikasikan")
	}

	rec, _ = doJSON(t, h.HandleAuthLogin, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": username,
		"password": "SalahTotal",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("kata sandi salah seharusnya 401, diperoleh %d", rec.Code)
	}
}

func TestHandleSetPassphraseRequiresAccountPassword(t *testing.T) {
	h := newTestHandler(t)

	rec, _ := doJSON(t, h.HandleAuthRegister, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"fullname": "Sri Mulyani", "username": "sri.uji", "password": "KataSandiUji#2026",
		"nik_nip": "1", "institution": "ARSign", "email": "sri@contoh.id", "role": "PUBLIC",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("pendaftaran gagal: %s", rec.Body.String())
	}

	rec, _ = doJSON(t, h.HandleSetPassphrase, http.MethodPost, "/api/v1/auth/passphrase/set", map[string]string{
		"username": "sri.uji", "password": "SalahTotal", "passphrase": "PassphraseBaru#1",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("kata sandi salah seharusnya 401, diperoleh %d", rec.Code)
	}
}

// TestHandlePAdESSignRequiresAuthentication adalah uji regresi untuk celah
// penandatanganan tanpa kredensial: dulu siapa pun dapat menandatangani dengan
// nama dan NIK sembarang, dan server membangkitkan kunci acak bila kunci tidak
// tersedia sehingga dokumen tampak sah tanpa pemilik yang sah.
func TestHandlePAdESSignRequiresAuthentication(t *testing.T) {
	h := newTestHandler(t)
	username, _, passphrase := registerSigner(t, h)
	pdf := minimalPDFBase64()

	// a. Tanpa identitas akun sama sekali.
	rec, _ := doJSON(t, h.HandlePAdESSign, http.MethodPost, "/api/v1/pades/sign", map[string]string{
		"pdf_base64":      pdf,
		"signer_fullname": "Menteri Keuangan Republik Indonesia",
		"signer_nik":      "1234567890123456",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("penandatanganan anonim seharusnya 401, diperoleh %d: %s", rec.Code, rec.Body.String())
	}

	// b. Akun tidak terdaftar.
	rec, _ = doJSON(t, h.HandlePAdESSign, http.MethodPost, "/api/v1/pades/sign", map[string]string{
		"pdf_base64": pdf, "username": "tidak.ada", "passphrase": passphrase,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("akun tidak terdaftar seharusnya 401, diperoleh %d", rec.Code)
	}

	// c. Passphrase salah.
	rec, _ = doJSON(t, h.HandlePAdESSign, http.MethodPost, "/api/v1/pades/sign", map[string]string{
		"pdf_base64": pdf, "username": username, "passphrase": "PassphraseSalah",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("passphrase salah seharusnya 401, diperoleh %d", rec.Code)
	}

	// d. Kredensial benar: identitas sertifikat diambil dari registri akun.
	rec, body := doJSON(t, h.HandlePAdESSign, http.MethodPost, "/api/v1/pades/sign", map[string]string{
		"pdf_base64": pdf, "username": username, "passphrase": passphrase,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("penandatanganan sah gagal (HTTP %d): %s", rec.Code, rec.Body.String())
	}
	data, _ := body["data"].(map[string]any)
	signedHex, _ := data["signed_pdf_hex"].(string)
	if signedHex == "" {
		t.Fatal("respons penandatanganan tidak memuat dokumen hasil")
	}

	// e. Dokumen hasil wajib lolos verifikasi, dengan identitas dari akun.
	rec, body = doJSON(t, h.HandlePAdESVerify, http.MethodPost, "/api/v1/pades/verify", map[string]string{
		"pdf_base64": signedHex,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("verifikasi gagal (HTTP %d): %s", rec.Code, rec.Body.String())
	}
	vd, _ := body["data"].(map[string]any)
	if vd["is_valid"] != true {
		t.Fatalf("dokumen hasil seharusnya SAH: %v", vd["message"])
	}
	if vd["signer_fullname"] != "Pejabat Penandatangan Resmi, S.Kom." {
		t.Fatalf("identitas sertifikat %v tidak sesuai registri akun", vd["signer_fullname"])
	}
}

func TestAdminAuthMiddleware(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { SendSuccess(w, nil, "ok") }

	// Tanpa ADMIN_SECRET_KEY layanan administrator wajib menolak melayani.
	t.Setenv("ADMIN_SECRET_KEY", "")
	rec := httptest.NewRecorder()
	AdminAuthMiddleware(ok)(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/logs", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("tanpa ADMIN_SECRET_KEY seharusnya 503, diperoleh %d", rec.Code)
	}

	t.Setenv("ADMIN_SECRET_KEY", "KunciAdminUji#2026")

	// Kunci lewat query string tidak lagi diterima.
	rec = httptest.NewRecorder()
	AdminAuthMiddleware(ok)(rec, httptest.NewRequest(http.MethodGet, "/api/v1/admin/logs?key=KunciAdminUji%232026", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("kunci via query string seharusnya ditolak 401, diperoleh %d", rec.Code)
	}

	// Kunci salah di header.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/logs", nil)
	req.Header.Set("X-Admin-Key", "salah")
	rec = httptest.NewRecorder()
	AdminAuthMiddleware(ok)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("kunci salah seharusnya 401, diperoleh %d", rec.Code)
	}

	// Kunci benar di header.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/logs", nil)
	req.Header.Set("X-Admin-Key", "KunciAdminUji#2026")
	rec = httptest.NewRecorder()
	AdminAuthMiddleware(ok)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("kunci benar seharusnya 200, diperoleh %d", rec.Code)
	}
}

func TestCORSMiddlewareRestrictsOrigin(t *testing.T) {
	t.Setenv("ALLOWED_ORIGINS", "https://arsign.contoh.id")
	handler := CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Origin", "https://penyerang.contoh.id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("origin tak terdaftar seharusnya tidak diizinkan, diperoleh %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Origin", "https://arsign.contoh.id")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://arsign.contoh.id" {
		t.Fatalf("origin terdaftar seharusnya diizinkan, diperoleh %q", got)
	}
}

func TestOTPVerifyRejectsReplayAndWrongCode(t *testing.T) {
	h := newTestHandler(t)
	const email = "otp.uji@smallcircle.web.id"

	rec, _ := doJSON(t, h.HandleAuthSendOTP, http.MethodPost, "/api/v1/auth/otp/send", map[string]string{"email": email})
	if rec.Code != http.StatusOK {
		t.Fatalf("pengiriman OTP gagal: %s", rec.Body.String())
	}

	rec, body := doJSON(t, h.HandleAuthTestInspectOTP, http.MethodGet, "/api/v1/auth/otp/test-inspect?email="+email, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pembacaan OTP uji gagal: %s", rec.Body.String())
	}
	data, _ := body["data"].(map[string]any)
	code, _ := data["code"].(string)
	if len(code) != 6 {
		t.Fatalf("panjang kode OTP %d, diharapkan 6", len(code))
	}

	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	rec, _ = doJSON(t, h.HandleAuthVerifyOTP, http.MethodPost, "/api/v1/auth/otp/verify", map[string]string{
		"email": email, "code": wrong,
	})
	if rec.Code == http.StatusOK {
		t.Fatal("kode OTP salah seharusnya ditolak")
	}

	rec, _ = doJSON(t, h.HandleAuthVerifyOTP, http.MethodPost, "/api/v1/auth/otp/verify", map[string]string{
		"email": email, "code": code,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("kode OTP benar seharusnya diterima: %s", rec.Body.String())
	}

	rec, _ = doJSON(t, h.HandleAuthVerifyOTP, http.MethodPost, "/api/v1/auth/otp/verify", map[string]string{
		"email": email, "code": code,
	})
	if rec.Code == http.StatusOK {
		t.Fatal("kode OTP yang sudah terpakai seharusnya tidak dapat dipakai ulang")
	}
}
