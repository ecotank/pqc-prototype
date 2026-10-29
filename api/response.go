package api

import (
	"encoding/json"
	"net/http"
	"time"
)

type APIResponse struct {
	Status         string      `json:"status"` // "SUCCESS" | "ERROR"
	StatusCode     int         `json:"status_code"`
	StatusMessage  string      `json:"status_message"`
	TimestampUTC   string      `json:"timestamp_utc"`
	Message        string      `json:"message,omitempty"`
	Data           interface{} `json:"data,omitempty"`
	SignatureValue string      `json:"signature_value,omitempty"`
	SignerInfo     string      `json:"signer_info,omitempty"`
}

func SendSuccess(w http.ResponseWriter, data interface{}, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Status:        "SUCCESS",
		StatusCode:    http.StatusOK,
		StatusMessage: "OK",
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339),
		Message:       msg,
		Data:          data,
	})
}

func SendSignSuccess(w http.ResponseWriter, data interface{}, sigHex, signer string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Status:         "SUCCESS",
		StatusCode:     http.StatusOK,
		StatusMessage:  "DOKUMEN_BERHASIL_DITANDATANGANI",
		TimestampUTC:   time.Now().UTC().Format(time.RFC3339),
		Message:        "Tanda tangan digital pascakuantum ML-DSA berhasil dibubuhkan",
		Data:           data,
		SignatureValue: sigHex,
		SignerInfo:     signer,
	})
}

func SendError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(APIResponse{
		Status:        "ERROR",
		StatusCode:    code,
		StatusMessage: "KESALAHAN_OPERASI",
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339),
		Message:       msg,
		Data:          nil,
	})
}
