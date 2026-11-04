package api

import (
	"net/http"
	"os"
	"strings"
)

func RegisterRoutes(mux *http.ServeMux, h *APIHandler) {
	// 1. Key Generation
	mux.HandleFunc("POST /api/v1/keys/generate", h.HandleKeyGen)

	// 2. Signing (Pola ECS)
	mux.HandleFunc("POST /api/v1/sign", h.HandleSign)

	// 3. Verification & Integrity Check
	mux.HandleFunc("POST /api/v1/verify", h.HandleVerify)

	// 4. Dual Sign (Transition Coexistence)
	mux.HandleFunc("POST /api/v1/dual-sign", h.HandleDualSign)

	// 5. Dual Verify
	mux.HandleFunc("POST /api/v1/dual-verify", h.HandleDualVerify)

	// 6. Benchmark
	mux.HandleFunc("POST /api/v1/benchmarks", h.HandleBenchmark)
	mux.HandleFunc("GET /api/v1/benchmarks/export", h.HandleBenchmarkExport)

	// 7. FIPS 204 Compliance Report
	mux.HandleFunc("GET /api/v1/fips204-compliance", h.HandleFIPSCompliance)

	// 8. Audit Logs (SQLite)
	mux.HandleFunc("GET /api/v1/audit", h.HandleAuditLogs)

	// 9. Document Registry (SQLite)
	mux.HandleFunc("GET /api/v1/registry", h.HandleRegistryList)
	mux.HandleFunc("POST /api/v1/registry", h.HandleRegistryRecord)

	// 10. Process Tracing (Deep Mathematical Inspection)
	mux.HandleFunc("POST /api/v1/process/trace-sign", h.HandleTraceSign)
	mux.HandleFunc("POST /api/v1/process/trace-verify", h.HandleTraceVerify)

	// 11. Autentikasi & Akun Pengguna (ASN & Publik)
	mux.HandleFunc("POST /api/v1/auth/login", h.HandleAuthLogin)
	mux.HandleFunc("POST /api/v1/auth/register", h.HandleAuthRegister)
	// Daftar pengguna memuat NIK/NIP dan surel seluruh akun: khusus administrator.
	mux.HandleFunc("GET /api/v1/auth/users", AdminAuthMiddleware(h.HandleAuthUsersList))
	mux.HandleFunc("POST /api/v1/auth/passphrase/set", h.HandleSetPassphrase)
	mux.HandleFunc("POST /api/v1/auth/passphrase/verify", h.HandleVerifyPassphrase)

	// 12. PAdES ISO 32000-1 Digital Signature & CA Endpoints
	mux.HandleFunc("POST /api/v1/pades/sign", h.HandlePAdESSign)
	mux.HandleFunc("POST /api/v1/pades/verify", h.HandlePAdESVerify)
	mux.HandleFunc("GET /api/v1/ca/certificates", h.HandleCACertificates)

	// 13. Layanan Verifikasi Email OTP
	mux.HandleFunc("POST /api/v1/auth/otp/send", h.HandleAuthSendOTP)
	mux.HandleFunc("POST /api/v1/auth/otp/verify", h.HandleAuthVerifyOTP)

	// Endpoint bantu pengujian otomatis membocorkan kode OTP, sehingga pendaftarannya
	// wajib diaktifkan secara eksplisit. Menggantungkannya pada "bukan produksi"
	// bersifat fail-open: APP_ENV yang lupa disetel langsung membuka endpoint ini.
	if IsTestEndpointsEnabled() {
		mux.HandleFunc("GET /api/v1/auth/otp/test-inspect", h.HandleAuthTestInspectOTP)
	}

	// 14. Certificate Revocation List (CRL) & Status Pencabutan Sertifikat
	mux.HandleFunc("GET /api/v1/ca/crl", h.HandleCACRL)
	mux.HandleFunc("POST /api/v1/ca/revoke", AdminAuthMiddleware(h.HandleCARevoke))

	// 15. Pengaturan Akun & Profil Pengguna
	mux.HandleFunc("POST /api/v1/user/password", h.HandleUpdatePassword)
	mux.HandleFunc("POST /api/v1/user/profile", h.HandleUpdateProfile)
	mux.HandleFunc("POST /api/v1/user/specimen", h.HandleUpdateSpecimen)
	mux.HandleFunc("GET /api/v1/user/specimens", h.HandleGetSpecimens)
	mux.HandleFunc("POST /api/v1/user/specimens", h.HandleSaveSpecimens)
}

// maxRequestBodyBytes membatasi ukuran badan permintaan. Tanpa batas ini, satu
// permintaan dengan pdf_base64 raksasa cukup untuk menghabiskan memori server,
// karena berkas disalin ke memori lalu dikodekan ulang ke hex dan base64.
const maxRequestBodyBytes = 32 << 20 // 32 MiB

// IsProductionEnv melaporkan apakah layanan berjalan pada lingkungan produksi.
func IsProductionEnv() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
}

// IsTestEndpointsEnabled melaporkan apakah endpoint bantu pengujian boleh aktif.
// Aktivasi bersifat opt-in lewat ARSIGN_ENABLE_TEST_ENDPOINTS dan tetap ditolak
// mutlak pada lingkungan produksi.
func IsTestEndpointsEnabled() bool {
	if IsProductionEnv() {
		return false
	}
	v := strings.TrimSpace(os.Getenv("ARSIGN_ENABLE_TEST_ENDPOINTS"))
	return v == "1" || strings.EqualFold(v, "true")
}

// allowedOrigins mengembalikan daftar origin yang boleh memanggil API lintas asal.
// Nilai bawaan hanya mencakup ketiga port layanan lokal; sebelumnya seluruh origin
// diizinkan (Access-Control-Allow-Origin: *), termasuk untuk rute administrator.
func allowedOrigins() []string {
	raw := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS"))
	if raw == "" {
		return []string{
			"http://localhost:8080", "http://localhost:8081", "http://localhost:8082",
			"http://127.0.0.1:8080", "http://127.0.0.1:8081", "http://127.0.0.1:8082",
		}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// CORSMiddleware memasang kebijakan lintas asal berbasis daftar izin dan
// menerapkan batas ukuran badan permintaan.
func CORSMiddleware(next http.Handler) http.Handler {
	origins := allowedOrigins()
	wildcard := len(origins) == 1 && origins[0] == "*"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		switch {
		case wildcard:
			w.Header().Set("Access-Control-Allow-Origin", "*")
		case origin != "":
			for _, allowed := range origins {
				if strings.EqualFold(origin, allowed) {
					w.Header().Set("Access-Control-Allow-Origin", allowed)
					w.Header().Set("Vary", "Origin")
					break
				}
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
