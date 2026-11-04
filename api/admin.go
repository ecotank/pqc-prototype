package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// AdminAuthMiddleware mengamankan endpoint administrator.
//
// Perubahan keamanan dibanding versi sebelumnya:
//   - kunci tidak lagi diterima lewat query string (?key=...), karena nilai itu
//     ikut tercatat di log akses, riwayat peramban, dan header Referer;
//   - tidak ada lagi kunci cadangan hardcoded; bila ADMIN_SECRET_KEY belum
//     disetel, layanan administrator menolak melayani permintaan;
//   - perbandingan kunci dilakukan dalam waktu konstan.
func AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminKey := strings.TrimSpace(os.Getenv("ADMIN_SECRET_KEY"))
		if adminKey == "" {
			SendError(w, http.StatusServiceUnavailable,
				"Layanan administrator tidak aktif: ADMIN_SECRET_KEY belum disetel pada lingkungan server")
			return
		}

		key := r.Header.Get("X-Admin-Key")
		if key == "" {
			if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
				key = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if subtle.ConstantTimeCompare([]byte(key), []byte(adminKey)) != 1 {
			SendError(w, http.StatusUnauthorized, "Akses ditolak: Kredensial Administrator tidak valid")
			return
		}

		next(w, r)
	}
}

// HandleAdminLogs mengambil seluruh rekaman aktivitas sistem
func (h *APIHandler) HandleAdminLogs(w http.ResponseWriter, r *http.Request) {
	category := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("category")))
	level := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("level")))
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	logs, total, err := h.store.GetSystemActivityLogs(category, level, limit, offset)
	if err != nil {
		SendError(w, http.StatusInternalServerError, "Gagal memuat log aktivitas: "+err.Error())
		return
	}

	SendSuccess(w, map[string]interface{}{
		"logs":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}, "Log aktivitas sistem berhasil dimuat")
}

// HandleAdminStats mengambil metrik dan statistik kesehatan sistem
func (h *APIHandler) HandleAdminStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.GetSystemActivityStats()
	if err != nil {
		SendError(w, http.StatusInternalServerError, "Gagal memuat statistik sistem: "+err.Error())
		return
	}
	SendSuccess(w, stats, "Statistik sistem berhasil dimuat")
}

// HandleAdminExportLogs mengekspor seluruh log aktivitas dalam format JSON forensik
func (h *APIHandler) HandleAdminExportLogs(w http.ResponseWriter, r *http.Request) {
	logs, _, err := h.store.GetSystemActivityLogs("", "", 5000, 0)
	if err != nil {
		SendError(w, http.StatusInternalServerError, "Gagal mengekspor log: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=arsign_system_activity_logs.json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"export_service": "ARSign PQC Administrator Audit Subsystem",
		"version":        "NIST FIPS 204 Ready",
		"logs":           logs,
	})
}

// RegisterAdminRoutes mendaftarkan rute khusus Service Administrator
func RegisterAdminRoutes(mux *http.ServeMux, h *APIHandler) {
	mux.HandleFunc("GET /api/v1/admin/logs", AdminAuthMiddleware(h.HandleAdminLogs))
	mux.HandleFunc("GET /api/v1/admin/stats", AdminAuthMiddleware(h.HandleAdminStats))
	mux.HandleFunc("GET /api/v1/admin/export", AdminAuthMiddleware(h.HandleAdminExportLogs))
}
