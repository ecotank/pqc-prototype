package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"pqc-prototype/crypto"
	"pqc-prototype/storage"
)

type APIHandler struct {
	store       *storage.Storage
	latestBench *crypto.BenchmarkReport
	benchMu     sync.Mutex
}

func NewAPIHandler(store *storage.Storage) *APIHandler {
	h := &APIHandler{
		store: store,
	}
	h.seedDefaultUsers()
	return h
}

func (h *APIHandler) HandleKeyGen(w http.ResponseWriter, r *http.Request) {
	alg := r.URL.Query().Get("algorithm")
	if alg == "" {
		alg = "ML-DSA-65"
	}

	algUpper := strings.ToUpper(alg)
	if strings.HasPrefix(algUpper, "RSA") {
		bits := 2048
		if algUpper == "RSA-3072" {
			bits = 3072
		}
		res, err := crypto.GenerateRSAKeyPair(bits)
		if err != nil {
			SendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = h.store.RecordAudit("KeyGen", res.Algorithm, res.GenDurationMs, "SUCCESS", fmt.Sprintf("Kunci RSA-%d dibangkitkan", bits))
		SendSuccess(w, res, "")
		return
	}

	res, err := crypto.GenerateMLDSAKeyPair(alg)
	if err != nil {
		SendError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = h.store.RecordAudit("KeyGen", res.Algorithm, res.GenDurationMs, "SUCCESS", fmt.Sprintf("Kunci ML-DSA %s dibangkitkan", alg))
	SendSuccess(w, res, "")
}

type SignRequest struct {
	SignerID   string `json:"signer_id"`
	Algorithm  string `json:"algorithm"`
	Digest     string `json:"digest"`
	Data       string `json:"data"`
	PrivateKey string `json:"private_key"`
	Format     string `json:"format"`
}

func (h *APIHandler) HandleSign(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Payload JSON tidak valid: "+err.Error())
		return
	}

	var payloadToSign []byte
	if req.Digest != "" {
		d, err := hex.DecodeString(strings.TrimSpace(req.Digest))
		if err != nil {
			payloadToSign = []byte(req.Digest)
		} else {
			payloadToSign = d
		}
	} else if req.Data != "" {
		hSum := sha256.Sum256([]byte(req.Data))
		payloadToSign = hSum[:]
	} else {
		SendError(w, http.StatusBadRequest, "Parameter 'digest' atau 'data' wajib diisi")
		return
	}

	privBytes, err := crypto.DecodeHexOrBase64(req.PrivateKey)
	if err != nil {
		SendError(w, http.StatusBadRequest, "Kunci privat tidak valid: "+err.Error())
		return
	}

	signer := req.SignerID
	if signer == "" {
		signer = "satria.alba@bsre.bssn.go.id"
	}

	algUpper := strings.ToUpper(strings.TrimSpace(req.Algorithm))
	if strings.HasPrefix(algUpper, "RSA") {
		res, err := crypto.SignRSA(privBytes, payloadToSign, "SHA-256")
		if err != nil {
			_ = h.store.RecordAudit("Sign", algUpper, 0, "FAILED", err.Error())
			SendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = h.store.RecordAudit("Sign", res.Algorithm, res.SignDurationMs, "SUCCESS", fmt.Sprintf("Tanda tangan RSA ukuran %d B", res.SignatureBytes))
		SendSignSuccess(w, res, res.SignatureHex, signer)
		return
	}

	res, err := crypto.SignMLDSA(req.Algorithm, privBytes, payloadToSign)
	if err != nil {
		_ = h.store.RecordAudit("Sign", req.Algorithm, 0, "FAILED", err.Error())
		SendError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = h.store.RecordAudit("Sign", res.Algorithm, res.SignDurationMs, "SUCCESS", fmt.Sprintf("Tanda tangan ML-DSA ukuran %d B", res.SignatureBytes))
	SendSignSuccess(w, res, res.SignatureHex, signer)
}

type VerifyRequest struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Data      string `json:"data"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func (h *APIHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Payload JSON tidak valid: "+err.Error())
		return
	}

	var payload []byte
	if req.Digest != "" {
		d, err := hex.DecodeString(strings.TrimSpace(req.Digest))
		if err != nil {
			payload = []byte(req.Digest)
		} else {
			payload = d
		}
	} else if req.Data != "" {
		hSum := sha256.Sum256([]byte(req.Data))
		payload = hSum[:]
	} else {
		SendError(w, http.StatusBadRequest, "Pesan atau digest wajib disediakan")
		return
	}

	pubBytes, err := crypto.DecodeHexOrBase64(req.PublicKey)
	if err != nil {
		SendError(w, http.StatusBadRequest, "Kunci publik tidak valid: "+err.Error())
		return
	}

	sigBytes, err := crypto.DecodeHexOrBase64(req.Signature)
	if err != nil {
		SendError(w, http.StatusBadRequest, "Tanda tangan tidak valid: "+err.Error())
		return
	}

	algUpper := strings.ToUpper(strings.TrimSpace(req.Algorithm))
	if strings.HasPrefix(algUpper, "RSA") {
		res, err := crypto.VerifyRSA(pubBytes, payload, sigBytes, "SHA-256")
		if err != nil {
			SendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		status := "SUCCESS"
		if !res.Valid {
			status = "REJECTED"
		}
		_ = h.store.RecordAudit("Verify", res.Algorithm, res.VerifyDurationMs, status, res.Reason)
		SendSuccess(w, res, "")
		return
	}

	res, err := crypto.VerifyMLDSA(req.Algorithm, pubBytes, payload, sigBytes)
	if err != nil {
		SendError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := "SUCCESS"
	if !res.Valid {
		status = "REJECTED"
	}
	_ = h.store.RecordAudit("Verify", res.Algorithm, res.VerifyDurationMs, status, res.Reason)
	SendSuccess(w, res, "")
}

type DualSignRequest struct {
	MLDSAAlgorithm  string `json:"mldsa_algorithm"`
	MLDSAPrivateKey string `json:"mldsa_private_key"`
	RSAPrivateKey   string `json:"rsa_private_key"`
	Digest          string `json:"digest"`
	Data            string `json:"data"`
}

func (h *APIHandler) HandleDualSign(w http.ResponseWriter, r *http.Request) {
	var req DualSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "JSON tidak valid: "+err.Error())
		return
	}

	var payload []byte
	if req.Digest != "" {
		d, err := hex.DecodeString(strings.TrimSpace(req.Digest))
		if err != nil {
			payload = []byte(req.Digest)
		} else {
			payload = d
		}
	} else if req.Data != "" {
		hSum := sha256.Sum256([]byte(req.Data))
		payload = hSum[:]
	} else {
		SendError(w, http.StatusBadRequest, "Digest atau data wajib diisi")
		return
	}

	if req.MLDSAAlgorithm == "" {
		req.MLDSAAlgorithm = "ML-DSA-65"
	}

	mldsaSK, err := crypto.DecodeHexOrBase64(req.MLDSAPrivateKey)
	if err != nil {
		SendError(w, http.StatusBadRequest, "ML-DSA SK tidak valid: "+err.Error())
		return
	}

	var rsaSK []byte
	if req.RSAPrivateKey != "" {
		rsaSK, err = crypto.DecodeHexOrBase64(req.RSAPrivateKey)
		if err != nil {
			SendError(w, http.StatusBadRequest, "RSA SK tidak valid: "+err.Error())
			return
		}
	} else {
		rsaKey, err := crypto.GenerateRSAKeyPair(2048)
		if err != nil {
			SendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		rsaSK, _ = crypto.DecodeHexOrBase64(rsaKey.PrivateKeyHex)
	}

	res, err := crypto.SignDual(req.MLDSAAlgorithm, mldsaSK, rsaSK, payload, "SHA-256")
	if err != nil {
		_ = h.store.RecordAudit("DualSign", req.MLDSAAlgorithm+"+RSA", 0, "FAILED", err.Error())
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = h.store.RecordAudit("DualSign", req.MLDSAAlgorithm+"+RSA", res.TotalDurationMs, "SUCCESS", fmt.Sprintf("Dual Sign ukuran %d B", res.TotalSizeBytes))
	SendSignSuccess(w, res, res.MLDSAResult.SignatureHex, "Satria Alba Pramasha (Dual PQC+RSA)")
}

type DualVerifyRequest struct {
	MLDSAAlgorithm string `json:"mldsa_algorithm"`
	MLDSAPublicKey string `json:"mldsa_public_key"`
	MLDSASignature string `json:"mldsa_signature"`
	RSAPublicKey   string `json:"rsa_public_key"`
	RSASignature   string `json:"rsa_signature"`
	Digest         string `json:"digest"`
	Data           string `json:"data"`
}

func (h *APIHandler) HandleDualVerify(w http.ResponseWriter, r *http.Request) {
	var req DualVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, err.Error())
		return
	}

	var payload []byte
	if req.Digest != "" {
		d, err := hex.DecodeString(strings.TrimSpace(req.Digest))
		if err != nil {
			payload = []byte(req.Digest)
		} else {
			payload = d
		}
	} else if req.Data != "" {
		hSum := sha256.Sum256([]byte(req.Data))
		payload = hSum[:]
	} else {
		SendError(w, http.StatusBadRequest, "Digest atau data wajib diisi")
		return
	}

	mldsaPK, err := crypto.DecodeHexOrBase64(req.MLDSAPublicKey)
	if err != nil {
		SendError(w, http.StatusBadRequest, "ML-DSA PK tidak valid: "+err.Error())
		return
	}
	mldsaSig, err := crypto.DecodeHexOrBase64(req.MLDSASignature)
	if err != nil {
		SendError(w, http.StatusBadRequest, "ML-DSA Sig tidak valid: "+err.Error())
		return
	}

	rsaPK, err := crypto.DecodeHexOrBase64(req.RSAPublicKey)
	if err != nil {
		SendError(w, http.StatusBadRequest, "RSA PK tidak valid: "+err.Error())
		return
	}
	rsaSig, err := crypto.DecodeHexOrBase64(req.RSASignature)
	if err != nil {
		SendError(w, http.StatusBadRequest, "RSA Sig tidak valid: "+err.Error())
		return
	}

	res, err := crypto.VerifyDual(req.MLDSAAlgorithm, mldsaPK, mldsaSig, rsaPK, rsaSig, payload, "SHA-256")
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	status := "SUCCESS"
	if !res.BothValid {
		status = "REJECTED"
	}
	_ = h.store.RecordAudit("DualVerify", req.MLDSAAlgorithm+"+RSA", res.TotalDurationMs, status, res.Summary)
	SendSuccess(w, res, "")
}

type BenchRequest struct {
	Iterations int `json:"iterations"`
}

func (h *APIHandler) HandleBenchmark(w http.ResponseWriter, r *http.Request) {
	var req BenchRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Iterations <= 0 {
		req.Iterations = 50
	}

	report, err := crypto.RunFullBenchmark(req.Iterations)
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.benchMu.Lock()
	h.latestBench = report
	h.benchMu.Unlock()

	_ = h.store.RecordAudit("Benchmark", "ALL", 0, "SUCCESS", fmt.Sprintf("Benchmark %d iterasi selesai", req.Iterations))
	SendSuccess(w, report, "")
}

func (h *APIHandler) HandleBenchmarkExport(w http.ResponseWriter, r *http.Request) {
	h.benchMu.Lock()
	bench := h.latestBench
	h.benchMu.Unlock()

	if bench == nil {
		var err error
		bench, err = crypto.RunFullBenchmark(50)
		if err != nil {
			SendError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	csvBytes, err := crypto.ExportBenchmarkCSV(bench)
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=\"pqc_bsre_benchmark.csv\"")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, string(csvBytes))
}

func (h *APIHandler) HandleFIPSCompliance(w http.ResponseWriter, r *http.Request) {
	report := crypto.RunFIPS204Validation()
	SendSuccess(w, report, "")
}

func (h *APIHandler) HandleAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := h.store.GetAuditLogs(100)
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	SendSuccess(w, logs, "")
}

func (h *APIHandler) HandleRegistryList(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.GetRegistryList(50)
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	SendSuccess(w, list, "")
}

func (h *APIHandler) HandleRegistryRecord(w http.ResponseWriter, r *http.Request) {
	var item storage.RegistryEntry
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		SendError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.store.RecordRegistry(item.ID, item.Title, item.Signer, item.Algorithm, item.Time, item.DocumentHash, item.SignatureHex); err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	SendSuccess(w, item, "Tercatat di buku registrasi")
}

type TraceSignReq struct {
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"`
	Data       string `json:"data"`
}

func (h *APIHandler) HandleTraceSign(w http.ResponseWriter, r *http.Request) {
	var req TraceSignReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Payload tidak valid: "+err.Error())
		return
	}

	privBytes, err := crypto.DecodeHexOrBase64(req.PrivateKey)
	if err != nil {
		SendError(w, http.StatusBadRequest, "Kunci privat tidak valid: "+err.Error())
		return
	}

	if req.Algorithm == "" {
		req.Algorithm = "ML-DSA-65"
	}

	trace, err := crypto.TraceSignMLDSA(req.Algorithm, privBytes, []byte(req.Data))
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	SendSuccess(w, trace, "")
}

type TraceVerifyReq struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Data      string `json:"data"`
}

func (h *APIHandler) HandleTraceVerify(w http.ResponseWriter, r *http.Request) {
	var req TraceVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Payload tidak valid: "+err.Error())
		return
	}

	pubBytes, err := crypto.DecodeHexOrBase64(req.PublicKey)
	if err != nil {
		SendError(w, http.StatusBadRequest, "Kunci publik tidak valid: "+err.Error())
		return
	}

	sigBytes, err := crypto.DecodeHexOrBase64(req.Signature)
	if err != nil {
		SendError(w, http.StatusBadRequest, "Signature tidak valid: "+err.Error())
		return
	}

	if req.Algorithm == "" {
		req.Algorithm = "ML-DSA-65"
	}

	trace, err := crypto.TraceVerifyMLDSA(req.Algorithm, pubBytes, []byte(req.Data), sigBytes)
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	SendSuccess(w, trace, "")
}

func (h *APIHandler) seedDefaultUsers() {
	users, _ := h.store.GetUsersList()
	if len(users) > 0 {
		return
	}

	demoUsers := []struct {
		ID          string
		Username    string
		Password    string
		FullName    string
		NikNip      string
		Institution string
		Email       string
		Role        string
	}{
		{
			ID:          "USR-BSRE-01",
			Username:    "satria.alba",
			Password:    "bsre2026",
			FullName:    "Satria Alba Pramasha, S.Tr.Kom.",
			NikNip:      "19991026 202401 1 001",
			Institution: "Balai Besar Sertifikasi Elektronik (BSrE) - BSSN",
			Email:       "satria.alba@bsre.bssn.go.id",
			Role:        "ASN",
		},
		{
			ID:          "USR-BSRE-02",
			Username:    "ezra.dhiatara",
			Password:    "bsre2026",
			FullName:    "Muhammad Ezra Dhiatara, S.Tr.Kom.",
			NikNip:      "19980512 202302 1 002",
			Institution: "Balai Besar Sertifikasi Elektronik (BSrE) - BSSN",
			Email:       "ezra.dhiatara@bsre.bssn.go.id",
			Role:        "ASN",
		},
		{
			ID:          "USR-BSRE-03",
			Username:    "sulthan.aidhan",
			Password:    "bsre2026",
			FullName:    "Sulthan Aidhan Afiq Sukarto, S.Tr.Kom.",
			NikNip:      "19990415 202401 1 003",
			Institution: "Balai Besar Sertifikasi Elektronik (BSrE) - BSSN",
			Email:       "sulthan.aidhan@bsre.bssn.go.id",
			Role:        "ASN",
		},
		{
			ID:          "USR-PUB-01",
			Username:    "warga.publik",
			Password:    "warga2026",
			FullName:    "Budi Santoso",
			NikNip:      "3171022810990001",
			Institution: "Masyarakat Umum (Pemohon Mandiri)",
			Email:       "budi.santoso@warga.id",
			Role:        "PUBLIC",
		},
	}

	for _, d := range demoUsers {
		keyRes, err := crypto.GenerateMLDSAKeyPair("ML-DSA-65")
		if err != nil {
			continue
		}
		_ = h.store.CreateUser(&storage.User{
			ID:              d.ID,
			Username:        d.Username,
			PasswordHash:    storage.HashPassword(d.Password),
			FullName:        d.FullName,
			NikNip:          d.NikNip,
			Institution:     d.Institution,
			Email:           d.Email,
			Role:            d.Role,
			MldsaPublicKey:  keyRes.PublicKeyHex,
			MldsaPrivateKey: keyRes.PrivateKeyHex,
			CreatedAt:       time.Now().Format("2006-01-02 15:04:05"),
		})
	}
}

type LoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *APIHandler) HandleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Permintaan login tidak valid: "+err.Error())
		return
	}

	user, err := h.store.GetUserByUsername(strings.TrimSpace(req.Username))
	if err != nil {
		SendError(w, http.StatusUnauthorized, "Nama pengguna atau kata sandi salah")
		return
	}

	if user.PasswordHash != storage.HashPassword(req.Password) {
		SendError(w, http.StatusUnauthorized, "Nama pengguna atau kata sandi salah")
		return
	}

	_ = h.store.RecordAudit("AuthLogin", "ML-DSA-65", 0, "SUCCESS", fmt.Sprintf("Pengguna %s (%s) berhasil masuk", user.Username, user.FullName))

	user.PasswordHash = ""
	SendSuccess(w, user, "Berhasil masuk ke layanan")
}

type RegisterReq struct {
	FullName    string `json:"fullname"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	NikNip      string `json:"nik_nip"`
	Institution string `json:"institution"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

func (h *APIHandler) HandleAuthRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendError(w, http.StatusBadRequest, "Permintaan registrasi tidak valid: "+err.Error())
		return
	}

	if req.Username == "" || req.Password == "" || req.FullName == "" {
		SendError(w, http.StatusBadRequest, "Nama lengkap, username, dan kata sandi wajib diisi")
		return
	}

	if existing, _ := h.store.GetUserByUsername(req.Username); existing != nil {
		SendError(w, http.StatusBadRequest, "Nama pengguna sudah terdaftar, silakan gunakan username lain")
		return
	}

	keyRes, err := crypto.GenerateMLDSAKeyPair("ML-DSA-65")
	if err != nil {
		SendError(w, http.StatusInternalServerError, "Gagal membangkitkan kunci kriptografi pascakuantum: "+err.Error())
		return
	}

	role := req.Role
	if role == "" {
		role = "PUBLIC"
	}

	newID := fmt.Sprintf("USR-%s-%d", role, time.Now().Unix()%1000000)
	user := &storage.User{
		ID:              newID,
		Username:        strings.ToLower(strings.TrimSpace(req.Username)),
		PasswordHash:    storage.HashPassword(req.Password),
		FullName:        strings.TrimSpace(req.FullName),
		NikNip:          strings.TrimSpace(req.NikNip),
		Institution:     strings.TrimSpace(req.Institution),
		Email:           strings.TrimSpace(req.Email),
		Role:            role,
		MldsaPublicKey:  keyRes.PublicKeyHex,
		MldsaPrivateKey: keyRes.PrivateKeyHex,
		CreatedAt:       time.Now().Format("2006-01-02 15:04:05"),
	}

	if err := h.store.CreateUser(user); err != nil {
		SendError(w, http.StatusInternalServerError, "Gagal menyimpan akun: "+err.Error())
		return
	}

	_ = h.store.RecordAudit("AuthRegister", "ML-DSA-65", 0, "SUCCESS", fmt.Sprintf("Registrasi akun baru %s (%s)", user.Username, user.FullName))

	user.PasswordHash = ""
	SendSuccess(w, user, "Akun berhasil didaftarkan bersama kunci ML-DSA-65")
}

func (h *APIHandler) HandleAuthUsersList(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.GetUsersList()
	if err != nil {
		SendError(w, http.StatusInternalServerError, err.Error())
		return
	}
	SendSuccess(w, list, "")
}
