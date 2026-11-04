package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"pqc-prototype/api"
	"pqc-prototype/storage"
)

//go:embed web/*
var webFS embed.FS

func main() {
	portProd := os.Getenv("PORT")
	if portProd == "" {
		portProd = os.Getenv("PORT_PROD")
		if portProd == "" {
			portProd = "8080"
		}
	}

	portProc := os.Getenv("PORT_PROC")
	if portProc == "" {
		portProc = "8081"
	}

	portAdmin := os.Getenv("PORT_ADMIN")
	if portAdmin == "" {
		portAdmin = "8082"
	}

	// 1. Inisialisasi Database SQLite Lokal
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "pqc_arsign.db"
	}
	store, err := storage.InitStorage(dbPath)
	if err != nil {
		log.Fatalf("Gagal inisialisasi SQLite storage: %v", err)
	}
	defer store.Close()

	// 2. Inisialisasi API Handler
	handler := api.NewAPIHandler(store)

	// 3. Inisialisasi Sub-Filesystem Web
	webSubFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("Gagal inisialisasi embedded filesystem: %v", err)
	}

	readWebFile := func(filename string) ([]byte, error) {
		diskPath := filepath.Join("web", filename)
		if data, err := os.ReadFile(diskPath); err == nil {
			return data, nil
		}
		return fs.ReadFile(webSubFS, filename)
	}

	var staticHandler http.Handler
	if _, err := os.Stat("web"); err == nil {
		staticHandler = http.FileServer(http.Dir("web"))
	} else {
		staticHandler = http.FileServer(http.FS(webSubFS))
	}

	// 4. Mux Web Siap Produksi (Port 8080)
	muxProd := http.NewServeMux()
	api.RegisterRoutes(muxProd, handler)
	api.RegisterAdminRoutes(muxProd, handler)
	muxProd.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/production.html" || r.URL.Path == "/prod" {
			data, err := readWebFile("production.html")
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		if r.URL.Path == "/process" || r.URL.Path == "/process.html" || r.URL.Path == "/lab" {
			data, err := readWebFile("process.html")
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		if r.URL.Path == "/admin" || r.URL.Path == "/admin.html" {
			data, err := readWebFile("admin.html")
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		staticHandler.ServeHTTP(w, r)
	})

	// 5. Mux Web Visualisasi Proses Lab (Port 8081)
	muxProc := http.NewServeMux()
	api.RegisterRoutes(muxProc, handler)
	muxProc.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" || r.URL.Path == "/process.html" || r.URL.Path == "/process" || r.URL.Path == "/lab" {
			data, err := readWebFile("process.html")
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		if r.URL.Path == "/production" || r.URL.Path == "/production.html" || r.URL.Path == "/prod" {
			data, err := readWebFile("production.html")
			if err != nil {
				http.Error(w, "File not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
		staticHandler.ServeHTTP(w, r)
	})

	// 6. Mux Service Administrator & Audit Forensik (Port 8082)
	muxAdmin := http.NewServeMux()
	api.RegisterAdminRoutes(muxAdmin, handler)
	muxAdmin.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		data, err := readWebFile("admin.html")
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	// ReadTimeout 15 detik sebelumnya memutus unggahan dokumen berukuran besar.
	// Batas header tetap ketat, sedangkan badan permintaan diberi waktu lebih
	// panjang dan dibatasi ukurannya oleh api.CORSMiddleware.
	newServer := func(port string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              ":" + port,
			Handler:           handler,
			ReadHeaderTimeout: 15 * time.Second,
			ReadTimeout:       120 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
	}

	serverProd := newServer(portProd, api.CORSMiddleware(muxProd))
	serverProc := newServer(portProc, api.CORSMiddleware(muxProc))
	serverAdmin := newServer(portAdmin, api.CORSMiddleware(muxAdmin))

	_ = store.RecordActivity("SYSTEM", "INFO", "SYSTEM", "SERVER_STARTUP", fmt.Sprintf("Layanan ARSign TTE Pascakuantum aktif di Port %s (Prod), %s (Lab), %s (Admin Audit)", portProd, portProc, portAdmin), "127.0.0.1", "pqc-server")

	fmt.Println("================================================================")
	fmt.Println("   ARSIGN — POST-QUANTUM DIGITAL SIGNATURE ENGINE (ML-DSA)     ")
	fmt.Println("   Layanan Penandatanganan Elektronik Pascakuantum Resmi       ")
	fmt.Println("================================================================")
	fmt.Printf("   Standar   : NIST FIPS 204 (ML-DSA-44, ML-DSA-65, ML-DSA-87)\n")
	fmt.Printf("   Target TTE: =< 2.0 Detik (Aktual: Sub-Milidetik / < 1 ms)\n")
	fmt.Printf("   Basis Data: SQLite (%s)\n", dbPath)
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("   [1] WEB SIAP PRODUKSI (ARSign Portal) : http://localhost:%s\n", portProd)
	fmt.Printf("   [2] WEB VISUALISASI PROSES (Lab PQC)  : http://localhost:%s\n", portProc)
	fmt.Printf("   [3] SERVICE AUDIT & LOG ADMIN (Port)  : http://localhost:%s\n", portAdmin)
	fmt.Println("================================================================")

	if os.Getenv("ADMIN_SECRET_KEY") == "" {
		log.Println("[PERINGATAN] ADMIN_SECRET_KEY belum disetel. Seluruh endpoint administrator dan daftar pengguna akan menolak permintaan.")
	}

	// Goroutine untuk listener Web Proses
	if portProc != portProd && portProc != "" {
		go func() {
			if err := serverProc.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Server Visualisasi Proses berhenti: %v", err)
			}
		}()
	}

	// Goroutine untuk listener Service Admin
	if portAdmin != portProd && portAdmin != "" {
		go func() {
			if err := serverAdmin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Service Administrator berhenti: %v", err)
			}
		}()
	}

	// Goroutine untuk listener Web Produksi.
	// Galat dikirim lewat kanal, bukan log.Fatalf di dalam goroutine, agar jalur
	// graceful shutdown tetap dijalankan dan basis data ditutup dengan benar.
	fatalErr := make(chan error, 1)
	go func() {
		if err := serverProd.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatalErr <- fmt.Errorf("server produksi berhenti: %w", err)
		}
	}()

	// Graceful Shutdown on Interrupt
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case <-quit:
	case err := <-fatalErr:
		log.Printf("[FATAL] %v", err)
	}

	fmt.Println("\n[*] Menghentikan server secara graceful...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = serverProd.Shutdown(ctx)
	_ = serverProc.Shutdown(ctx)
	_ = serverAdmin.Shutdown(ctx)
	fmt.Println("[*] Seluruh layanan berhenti dengan bersih.")
}
