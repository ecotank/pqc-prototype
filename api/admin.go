package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// AdminAuthMiddleware mengamankan endpoint administrator
func AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminKey := os.Getenv("ADMIN_SECRET_KEY")
		if adminKey == "" {
			adminKey = "ARSign-SuperAdmin-PQC2026!"
		}

		key := r.Header.Get("X-Admin-Key")
		if key == "" {
			key = r.URL.Query().Get("key")
		}
		if key == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				key = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if key != adminKey {
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
		"export_service": "ARSign PQC Administrator Audit Subsystem (3 RPLK)",
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

