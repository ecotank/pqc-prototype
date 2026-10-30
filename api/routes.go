package api

import (
	"net/http"
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
	mux.HandleFunc("GET /api/v1/auth/users", h.HandleAuthUsersList)

	// 12. PAdES ISO 32000-1 Digital Signature & CA Endpoints
	mux.HandleFunc("POST /api/v1/pades/sign", h.HandlePAdESSign)
	mux.HandleFunc("GET /api/v1/ca/certificates", h.HandleCACertificates)

	// 13. Layanan Verifikasi Email OTP
	mux.HandleFunc("POST /api/v1/auth/otp/send", h.HandleAuthSendOTP)
	mux.HandleFunc("POST /api/v1/auth/otp/verify", h.HandleAuthVerifyOTP)
	mux.HandleFunc("GET /api/v1/auth/otp/test-inspect", h.HandleAuthTestInspectOTP)
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
