const { createApp } = Vue;

createApp({
  data() {
    return {
      // 1. Theme & Navigation
      theme: localStorage.getItem('arsign_theme') || 'dark',
      activeTab: 'tte', // 'tte' | 'verify' | 'history' | 'settings'

      // 2. Authentication & Current User
      currentUser: null,
      authTab: 'login', // 'login' | 'register'
      loginForm: {
        username: '',
        password: '',
        error: '',
        loading: false
      },
      registerForm: {
        fullname: '',
        nik_nip: '',
        institution: '',
        email: '',
        username: '',
        password: '',
        role: 'PUBLIC',
        error: '',
        loading: false
      },

      // 3. Toast Notifications
      toast: {
        show: false,
        message: '',
        type: 'success', // 'success' | 'error' | 'warning' | 'info'
        timeout: null
      },

      // 4. Fitur TTE (Signing State)
      inputMethod: 'file', // 'file' | 'text'
      documentContent: 'DOKUMEN RESMI TANDA TANGAN ELEKTRONIK ARSIGN\nNomor: ARS-DOC-2026-TTE\nPerihal: Penerapan Standar Digital Signature Sah dan Tersertifikasi.',
      fileName: '',
      fileSize: 0,
      fileArrayBuffer: null,
      documentHash: '',
      algorithm: 'ML-DSA-65', // 'ML-DSA-65' | 'Dual-Sign'
      enableDualSign: false,
      isSigning: false,
      signedResult: null,

      // Specimen Tanda Tangan
      specimenImage: null,
      specimenPosition: 'custom',
      specimenWidth: 200,
      specimenHeight: 85,
      specimenCustomX: 350,
      specimenCustomY: 60,
      specimenPage: 1,
      showSpecimenModal: false,
      isDrawing: false,
      drawLastX: 0,
      drawLastY: 0,

      // 2FA OTP State
      otpSent: false,
      otpCode: '',
      otpInput: '',
      otpTimer: 60,
      otpTimerInterval: null,
      otpLoading: false,
      otpVerified: false,

      // PDF Interactive Viewer
      pdfDocProxy: null,
      pdfCurrentPage: 1,
      pdfTotalPages: 1,
      pdfActualPageWidth: 595.28,
      pdfActualPageHeight: 841.89,
      canvasWidth: 595,
      canvasHeight: 842,
      isPdfLoading: false,
      zoomLevel: 1.0,

      // 5. Fitur Verifikasi TTE
      verifyInputMode: 'file', // 'file' | 'text'
      verifyFile: null,
      verifyFileName: '',
      verifySignature: '',
      verifyDocumentHash: '',
      isVerifying: false,
      verifyStatus: null,

      // 6. Riwayat TTE Pribadi (Multi-tenant User Isolation)
      registryList: [],
      historySearch: '',
      selectedDetailItem: null,
      showDetailModal: false,

      // 7. Pengaturan (Settings)
      settingsProfile: {
        fullname: '',
        nik_nip: '',
        institution: '',
        email: '',
        role: ''
      },
      passwordForm: {
        old_password: '',
        new_password: '',
        confirm_password: '',
        loading: false
      },
      specimenSaveLoading: false,

      // Cryptographic keys in memory
      mldsaKey: null,
      rsaKey: null
    };
  },

  computed: {
    userInitial() {
      if (this.currentUser && this.currentUser.fullname) {
        return this.currentUser.fullname.trim().charAt(0).toUpperCase();
      }
      return 'U';
    },

    filteredRegistry() {
      if (!this.historySearch) return this.registryList;
      const q = this.historySearch.toLowerCase();
      return this.registryList.filter(item => {
        return (item.id && item.id.toLowerCase().includes(q)) ||
               (item.title && item.title.toLowerCase().includes(q)) ||
               (item.algorithm && item.algorithm.toLowerCase().includes(q)) ||
               (item.time_str && item.time_str.toLowerCase().includes(q));
      });
    }
  },

  watch: {
    enableDualSign(val) {
      this.algorithm = val ? 'Dual-Sign' : 'ML-DSA-65';
    }
  },

  mounted() {
    this.initTheme();
    this.initSession();

    window.addEventListener('resize', () => {
      if (this.activeTab === 'tte' && this.pdfDocProxy) {
        this.renderPdfViewer(this.pdfCurrentPage);
      }
    });
  },

  methods: {
    // ==========================================
    // THEME MANAGEMENT (Dark & Light)
    // ==========================================
    initTheme() {
      const saved = localStorage.getItem('arsign_theme') || 'dark';
      this.setTheme(saved);
    },

    toggleTheme() {
      const next = this.theme === 'dark' ? 'light' : 'dark';
      this.setTheme(next);
    },

    setTheme(t) {
      this.theme = t;
      localStorage.setItem('arsign_theme', t);
      if (t === 'dark') {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
    },

    // ==========================================
    // TOAST NOTIFICATIONS
    // ==========================================
    showToast(message, type = 'success') {
      if (this.toast.timeout) clearTimeout(this.toast.timeout);
      this.toast.message = message;
      this.toast.type = type;
      this.toast.show = true;
      this.toast.timeout = setTimeout(() => {
        this.toast.show = false;
      }, 4000);
    },

    // ==========================================
    // AUTHENTICATION & SESSION
    // ==========================================
    initSession() {
      const stored = sessionStorage.getItem('arsign_user');
      if (stored) {
        try {
          const parsed = JSON.parse(stored);
          if (parsed && parsed.username && parsed.fullname) {
            this.currentUser = parsed;
            this.syncUserProfile();
            this.loadUserRegistry();
            this.initProductionKeys();
            this.$nextTick(() => {
              this.renderPdfViewer(1);
            });
          } else {
            sessionStorage.removeItem('arsign_user');
            this.currentUser = null;
          }
        } catch (e) {
          sessionStorage.removeItem('arsign_user');
          this.currentUser = null;
        }
      }
    },

    syncUserProfile() {
      if (!this.currentUser) return;
      this.settingsProfile = {
        fullname: this.currentUser.fullname || '',
        nik_nip: this.currentUser.nik_nip || '',
        institution: this.currentUser.institution || '',
        email: this.currentUser.email || '',
        role: this.currentUser.role || 'PUBLIC'
      };
      if (this.currentUser.specimen_signature) {
        this.specimenImage = this.currentUser.specimen_signature;
      }
    },

    async login() {
      if (!this.loginForm.username || !this.loginForm.password) {
        this.loginForm.error = 'Nama pengguna dan kata sandi wajib diisi.';
        return;
      }

      this.loginForm.loading = true;
      this.loginForm.error = '';

      try {
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: this.loginForm.username.trim(),
            password: this.loginForm.password
          })
        });

        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.currentUser = json.data;
          sessionStorage.setItem('arsign_user', JSON.stringify(this.currentUser));
          this.syncUserProfile();
          this.showToast(`Selamat datang, ${this.currentUser.fullname}!`, 'success');
          this.loadUserRegistry();
          this.initProductionKeys();
          this.$nextTick(() => {
            this.renderPdfViewer(1);
          });
        } else {
          this.loginForm.error = json.message || 'Login gagal. Periksa username dan password.';
        }
      } catch (err) {
        this.loginForm.error = 'Gagal menghubungi server: ' + err.message;
      } finally {
        this.loginForm.loading = false;
      }
    },

    async register() {
      const f = this.registerForm;
      if (!f.fullname || !f.username || !f.password || !f.nik_nip || !f.email) {
        f.error = 'Seluruh bidang wajib diisi lengkap.';
        return;
      }

      f.loading = true;
      f.error = '';

      try {
        const res = await fetch('/api/v1/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fullname: f.fullname.trim(),
            username: f.username.trim(),
            password: f.password,
            nik_nip: f.nik_nip.trim(),
            institution: f.institution.trim() || 'ARSign Public User',
            email: f.email.trim(),
            role: f.role || 'PUBLIC'
          })
        });

        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.showToast('Akun berhasil dibuat beserta sertifikat tanda tangan digital! Silakan login.', 'success');
          this.authTab = 'login';
          this.loginForm.username = f.username.trim();
          this.loginForm.password = f.password;
          this.login();
        } else {
          f.error = json.message || 'Pendaftaran gagal.';
        }
      } catch (err) {
        f.error = 'Gagal mendaftar: ' + err.message;
      } finally {
        f.loading = false;
      }
    },

    logout() {
      sessionStorage.removeItem('arsign_user');
      this.currentUser = null;
      this.registryList = [];
      this.signedResult = null;
      this.showToast('Anda telah keluar dari sesi ARSign.', 'info');
    },

    // ==========================================
    // KEYS INITIALIZATION
    // ==========================================
    async initProductionKeys() {
      try {
        const res = await fetch('/api/v1/keys/generate?algorithm=ML-DSA-65', { method: 'POST' });
        const json = await res.json();
        if (json.status === 'SUCCESS') {
          this.mldsaKey = json.data;
        }
      } catch (e) {
        console.warn('Inisialisasi kunci PQC:', e);
      }
    },

    // ==========================================
    // MULTI-TENANT ISOLATED REGISTRY (Riwayat TTE)
    // ==========================================
    async loadUserRegistry() {
      if (!this.currentUser) return;
      try {
        const res = await fetch(`/api/v1/registry?username=${encodeURIComponent(this.currentUser.username)}`);
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.registryList = json.data || [];
          return;
        }
      } catch (err) {
        console.warn('Gagal memuat registry dari server, fallback ke local storage:', err);
      }

      // Fallback local per-user storage
      const cacheKey = `arsign_registry_${this.currentUser.username}`;
      const local = localStorage.getItem(cacheKey);
      if (local) {
        try {
          this.registryList = JSON.parse(local);
        } catch (e) {
          this.registryList = [];
        }
      } else {
        this.registryList = [];
      }
    },

    saveLocalRegistryItem(item) {
      if (!this.currentUser) return;
      const cacheKey = `arsign_registry_${this.currentUser.username}`;
      let list = [];
      try {
        list = JSON.parse(localStorage.getItem(cacheKey) || '[]');
      } catch (e) { list = []; }
      list.unshift(item);
      localStorage.setItem(cacheKey, JSON.stringify(list));
    },

    openDetailModal(item) {
      this.selectedDetailItem = item;
      this.showDetailModal = true;
    },

    closeDetailModal() {
      this.showDetailModal = false;
      this.selectedDetailItem = null;
    },

    // ==========================================
    // PDF VIEWER & PLACEMENT ENGINE
    // ==========================================
    async handleFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;

      this.fileName = file.name;
      this.fileSize = file.size;
      this.signedResult = null;

      const buffer = await file.arrayBuffer();
      this.fileArrayBuffer = buffer;

      // Hash awal berkas
      const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
      this.documentHash = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');

      await this.renderPdfViewer(1);
      this.showToast(`Berkas ${file.name} siap ditandatangani.`, 'info');
    },

    async renderPdfViewer(pageNumber = 1) {
      if (!window.pdfjsLib) return;
      this.isPdfLoading = true;

      try {
        let pdfData = this.fileArrayBuffer;
        if (!pdfData) {
          // Generate PDF A4 placeholder in-memory from text
          const doc = await PDFLib.PDFDocument.create();
          const page = doc.addPage([595.28, 841.89]);
          const fontBold = await doc.embedFont(PDFLib.StandardFonts.HelveticaBold);
          const fontNorm = await doc.embedFont(PDFLib.StandardFonts.Helvetica);

          page.drawText('ARSIGN — POST-QUANTUM SIGNATURE PLATFORM', { x: 50, y: 790, size: 14, font: fontBold, color: PDFLib.rgb(0.05, 0.15, 0.35) });
          page.drawText('OTORITAS TTE TERSERTIFIKASI ARSIGN', { x: 50, y: 772, size: 10, font: fontBold, color: PDFLib.rgb(0.2, 0.2, 0.2) });
          page.drawLine({ start: { x: 50, y: 760 }, end: { x: 545, y: 760 }, thickness: 1.5, color: PDFLib.rgb(0.1, 0.3, 0.6) });

          const lines = (this.documentContent || 'Dokumen Resmi Elektronik').split('\n');
          let curY = 730;
          for (const line of lines) {
            page.drawText(line, { x: 50, y: curY, size: 10, font: fontNorm, color: PDFLib.rgb(0.15, 0.15, 0.15) });
            curY -= 16;
            if (curY < 180) break;
          }
          const savedBytes = await doc.save();
          pdfData = savedBytes.buffer;
        }

        const dataCopy = pdfData.slice(0);
        const loadingTask = pdfjsLib.getDocument({ data: dataCopy });
        const rawDoc = await loadingTask.promise;
        this.pdfDocProxy = (window.Vue && window.Vue.markRaw) ? window.Vue.markRaw(rawDoc) : rawDoc;
        this.pdfTotalPages = rawDoc.numPages;
        this.pdfCurrentPage = Math.min(Math.max(1, pageNumber), this.pdfTotalPages);
        this.specimenPage = this.pdfCurrentPage;

        const page = await rawDoc.getPage(this.pdfCurrentPage);
        const viewport = page.getViewport({ scale: 1.0 });
        this.pdfActualPageWidth = viewport.width;
        this.pdfActualPageHeight = viewport.height;

        const canvas = document.getElementById('pdfViewerCanvas');
        if (!canvas) return;

        const container = canvas.parentElement;
        let availableWidth = container ? Math.max(300, container.clientWidth - 40) : 580;
        availableWidth = Math.min(availableWidth, 750);
        const scale = (availableWidth / viewport.width) * this.zoomLevel;

        const scaledViewport = page.getViewport({ scale: scale });
        canvas.width = scaledViewport.width;
        canvas.height = scaledViewport.height;
        this.canvasWidth = scaledViewport.width;
        this.canvasHeight = scaledViewport.height;

        const context = canvas.getContext('2d');
        await page.render({ canvasContext: context, viewport: scaledViewport }).promise;
      } catch (err) {
        console.warn('Gagal merender PDF:', err);
      } finally {
        this.isPdfLoading = false;
      }
    },

    prevPdfPage() {
      if (this.pdfCurrentPage > 1) {
        this.renderPdfViewer(this.pdfCurrentPage - 1);
      }
    },

    nextPdfPage() {
      if (this.pdfCurrentPage < this.pdfTotalPages) {
        this.renderPdfViewer(this.pdfCurrentPage + 1);
      }
    },

    zoomIn() {
      if (this.zoomLevel < 2.0) {
        this.zoomLevel += 0.15;
        this.renderPdfViewer(this.pdfCurrentPage);
      }
    },

    zoomOut() {
      if (this.zoomLevel > 0.7) {
        this.zoomLevel -= 0.15;
        this.renderPdfViewer(this.pdfCurrentPage);
      }
    },

    handlePdfOverlayClick(e) {
      const overlay = this.$refs.pdfOverlay;
      if (!overlay || !this.canvasWidth || !this.canvasHeight) return;

      const rect = overlay.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      // Konversi ke koordinat titik PDF standar (bottom-left origin)
      const scaleX = this.pdfActualPageWidth / this.canvasWidth;
      const scaleY = this.pdfActualPageHeight / this.canvasHeight;

      const pdfX = Math.round(clickX * scaleX);
      const pdfY = Math.round((this.canvasHeight - clickY) * scaleY);

      // Pastikan stempel tetap berada di dalam halaman
      const stampW = this.specimenWidth;
      const stampH = this.specimenHeight;
      this.specimenCustomX = Math.max(10, Math.min(this.pdfActualPageWidth - stampW - 10, pdfX - (stampW / 2)));
      this.specimenCustomY = Math.max(10, Math.min(this.pdfActualPageHeight - stampH - 10, pdfY - (stampH / 2)));
      this.specimenPage = this.pdfCurrentPage;
    },

    getSpecimenBoxStyle() {
      if (!this.canvasWidth || !this.canvasHeight || !this.pdfActualPageWidth || !this.pdfActualPageHeight) {
        return { display: 'none' };
      }

      const leftPercent = (this.specimenCustomX / this.pdfActualPageWidth) * 100;
      const widthPercent = (this.specimenWidth / this.pdfActualPageWidth) * 100;
      const heightPercent = (this.specimenHeight / this.pdfActualPageHeight) * 100;
      const topPercent = ((this.pdfActualPageHeight - this.specimenCustomY - this.specimenHeight) / this.pdfActualPageHeight) * 100;

      const isCurrentTarget = Number(this.specimenPage) === this.pdfCurrentPage;

      return {
        left: Math.max(0, Math.min(100 - widthPercent, leftPercent)) + '%',
        top: Math.max(0, Math.min(100 - heightPercent, topPercent)) + '%',
        width: Math.max(5, Math.min(100, widthPercent)) + '%',
        height: Math.max(4, Math.min(100, heightPercent)) + '%',
        opacity: isCurrentTarget ? 1 : 0.35
      };
    },

    // ==========================================
    // SPESIMEN TANDA TANGAN (DRAW & MODAL)
    // ==========================================
    openSpecimenModal() {
      this.showSpecimenModal = true;
      this.$nextTick(() => {
        this.initDrawCanvas();
      });
    },

    closeSpecimenModal() {
      this.showSpecimenModal = false;
    },

    initDrawCanvas() {
      const canvas = document.getElementById('specimenDrawCanvas');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      ctx.strokeStyle = '#1e3a8a';
      ctx.lineWidth = 2.5;
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
    },

    startDrawing(e) {
      this.isDrawing = true;
      const canvas = document.getElementById('specimenDrawCanvas');
      const rect = canvas.getBoundingClientRect();
      this.drawLastX = (e.clientX || (e.touches && e.touches[0].clientX)) - rect.left;
      this.drawLastY = (e.clientY || (e.touches && e.touches[0].clientY)) - rect.top;
    },

    draw(e) {
      if (!this.isDrawing) return;
      const canvas = document.getElementById('specimenDrawCanvas');
      const ctx = canvas.getContext('2d');
      const rect = canvas.getBoundingClientRect();
      const currentX = (e.clientX || (e.touches && e.touches[0].clientX)) - rect.left;
      const currentY = (e.clientY || (e.touches && e.touches[0].clientY)) - rect.top;

      ctx.beginPath();
      ctx.moveTo(this.drawLastX, this.drawLastY);
      ctx.lineTo(currentX, currentY);
      ctx.stroke();

      this.drawLastX = currentX;
      this.drawLastY = currentY;
    },

    stopDrawing() {
      this.isDrawing = false;
    },

    clearSpecimenCanvas() {
      const canvas = document.getElementById('specimenDrawCanvas');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    },

    saveSpecimenFromModal() {
      const canvas = document.getElementById('specimenDrawCanvas');
      if (!canvas) return;
      const dataUrl = canvas.toDataURL('image/png');
      this.specimenImage = dataUrl;
      this.closeSpecimenModal();
      this.showToast('Spesimen tanda tangan berhasil diterapkan.', 'success');
    },

    // ==========================================
    // 2FA EMAIL OTP VERIFICATION
    // ==========================================
    async sendOtp() {
      if (!this.currentUser || !this.currentUser.email) {
        this.showToast('Email penanda tangan tidak terdeteksi.', 'error');
        return;
      }

      this.otpLoading = true;
      this.otpVerified = false;

      try {
        const res = await fetch('/api/v1/auth/otp/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.currentUser.email })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.otpSent = true;
          this.otpInput = '';
          this.showToast(`Kode OTP dikirim ke ${this.currentUser.email}`, 'success');
          this.startOtpTimer();
        } else {
          this.showToast(json.message || 'Gagal mengirim OTP.', 'error');
        }
      } catch (err) {
        this.showToast('Gagal menghubungi layanan OTP: ' + err.message, 'error');
      } finally {
        this.otpLoading = false;
      }
    },

    startOtpTimer() {
      this.otpTimer = 60;
      if (this.otpTimerInterval) clearInterval(this.otpTimerInterval);
      this.otpTimerInterval = setInterval(() => {
        if (this.otpTimer > 0) {
          this.otpTimer--;
        } else {
          clearInterval(this.otpTimerInterval);
        }
      }, 1000);
    },

    async verifyOtp() {
      if (!this.otpInput || this.otpInput.length < 6) {
        this.showToast('Masukkan 6-digit kode OTP.', 'warning');
        return;
      }

      this.otpLoading = true;
      try {
        const res = await fetch('/api/v1/auth/otp/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: this.currentUser.email,
            code: this.otpInput.trim()
          })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.otpVerified = true;
          this.showToast('Otorisasi OTP Berhasil! Anda siap menandatangani.', 'success');
        } else {
          this.showToast(json.message || 'Kode OTP tidak sesuai.', 'error');
        }
      } catch (err) {
        this.showToast('Gagal verifikasi OTP: ' + err.message, 'error');
      } finally {
        this.otpLoading = false;
      }
    },

    // ==========================================
    // FITUR TTE: SIGNING PROCESS (ML-DSA-65)
    // ==========================================
    async signDocument() {
      if (!this.currentUser) {
        this.showToast('Wajib login untuk menandatangani dokumen.', 'error');
        return;
      }

      // Pastikan OTP terverifikasi jika sudah dikirim, atau minta OTP
      if (!this.otpVerified) {
        if (!this.otpSent) {
          this.showToast('Silakan klik "Kirim OTP" untuk otorisasi keamanan sebelum TTE.', 'warning');
        } else {
          this.showToast('Silakan masukkan dan verifikasi kode OTP Anda.', 'warning');
        }
        return;
      }

      this.isSigning = true;

      try {
        let pdfBytesFinal = null;
        const receiptUUID = 'ARS-TTE-' + Math.floor(100000 + Math.random() * 900000);
        const signerFullName = this.currentUser.fullname;
        const signerEmail = this.currentUser.email;
        let signerPrivKey = (this.currentUser && this.currentUser.mldsa_private_key) || (this.mldsaKey ? this.mldsaKey.private_key_hex : '');
        let signerPubKey = (this.currentUser && this.currentUser.mldsa_public_key) || (this.mldsaKey ? this.mldsaKey.public_key_hex : '');

        if (!signerPrivKey || !signerPubKey) {
          try {
            const keyRes = await fetch('/api/v1/keys/generate?algorithm=ML-DSA-65', { method: 'POST' });
            const keyJson = await keyRes.json();
            if (keyJson && keyJson.data) {
              this.mldsaKey = keyJson.data;
              signerPrivKey = keyJson.data.private_key_hex;
              signerPubKey = keyJson.data.public_key_hex;
            }
          } catch (e) {
            console.warn('Fallback key generation:', e);
          }
        }

        // 1. Sematkan visualisasi spesimen & stempel PAdES
        if (window.PDFSigner) {
          const visualRes = await window.PDFSigner.embedSpecimenAndStamp({
            pdfArrayBuffer: this.inputMethod === 'file' ? this.fileArrayBuffer : null,
            textContent: this.inputMethod === 'text' ? this.documentContent : null,
            specimenDataUrl: this.specimenImage,
            position: this.specimenPosition,
            customX: Number(this.specimenCustomX),
            customY: Number(this.specimenCustomY),
            customW: Number(this.specimenWidth),
            customH: Number(this.specimenHeight),
            pageNumber: this.specimenPage,
            receiptId: receiptUUID,
            signerName: signerFullName
          });
          pdfBytesFinal = visualRes.pdfBytes;
          this.documentHash = visualRes.sha256Hex;
        }

        // 2. Hubungi Backend PAdES Endpoint
        let binaryStr = '';
        const chunkSize = 8192;
        for (let i = 0; i < pdfBytesFinal.length; i += chunkSize) {
          binaryStr += String.fromCharCode.apply(null, pdfBytesFinal.subarray(i, i + chunkSize));
        }
        const b64Pdf = btoa(binaryStr);

        const padesRes = await fetch('/api/v1/pades/sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            pdf_base64: b64Pdf,
            signer_fullname: signerFullName,
            signer_email: signerEmail,
            signer_nik: this.currentUser ? (this.currentUser.nik_nip || '') : '',
            institution: this.currentUser ? (this.currentUser.institution || '') : '',
            receipt_id: receiptUUID,
            username: this.currentUser ? this.currentUser.username : '',
            mldsa_private_key: signerPrivKey,
            mldsa_public_key: signerPubKey,
            signer_mldsa_privkey: signerPrivKey,
            signer_mldsa_pubkey: signerPubKey,
            dual_sign: this.enableDualSign
          })
        });

        const padesJson = await padesRes.json();
        if (!padesRes.ok || padesJson.status !== 'SUCCESS') {
          throw new Error(padesJson.message || 'Gagal menandatangani berkas PAdES');
        }

        const data = padesJson.data;

        // Decode signed PDF
        const rawPdfData = data.signed_pdf_base64 || data.pdf_base64;
        let signedBytes;
        if (data.signed_pdf_hex) {
          const hexStr = data.signed_pdf_hex;
          signedBytes = new Uint8Array(hexStr.length / 2);
          for (let i = 0; i < hexStr.length; i += 2) {
            signedBytes[i / 2] = parseInt(hexStr.substr(i, 2), 16);
          }
        } else {
          const binarySigned = atob(rawPdfData);
          signedBytes = new Uint8Array(binarySigned.length);
          for (let i = 0; i < binarySigned.length; i++) {
            signedBytes[i] = binarySigned.charCodeAt(i);
          }
        }
        const blob = new Blob([signedBytes], { type: 'application/pdf' });
        const blobUrl = URL.createObjectURL(blob);

        this.signedResult = {
          receipt_id: receiptUUID,
          signer_fullname: signerFullName,
          signer_email: signerEmail,
          algorithm: 'Tersertifikasi Sah',
          duration_ms: data.signing_duration_ms || data.duration_ms || 0.6,
          signature_hex: data.signature_hex || data.mldsa_signature_hex || data.pkcs7_signature_hex,
          pdf_blob_url: blobUrl,
          file_name: 'ARSIGN_SIGNED_' + (this.fileName || 'dokumen.pdf'),
          signed_at: new Date().toLocaleString('id-ID')
        };

        // 3. Catat di Registry (dengan kepemilikan username pengguna aktif)
        const registryItem = {
          id: receiptUUID,
          title: this.fileName || 'Nota Dinas Resmi Elektronik',
          signer: signerFullName,
          username: this.currentUser.username,
          algorithm: 'Tersertifikasi Sah',
          time_str: new Date().toLocaleString('id-ID'),
          document_hash: this.documentHash,
          signature_hex: data.signature_hex || data.mldsa_signature_hex || data.pkcs7_signature_hex
        };

        try {
          await fetch('/api/v1/registry', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(registryItem)
          });
        } catch (e) {
          console.warn('Sync registry SQLite:', e);
        }

        this.saveLocalRegistryItem(registryItem);
        this.loadUserRegistry();
        this.showToast('Dokumen berhasil ditandatangani secara sah!', 'success');
      } catch (err) {
        this.showToast('Gagal menandatangani: ' + err.message, 'error');
      } finally {
        this.isSigning = false;
      }
    },

    // ==========================================
    // FITUR VERIFIKASI TTE
    // ==========================================
    async handleVerifyFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      this.verifyFileName = file.name;

      const arrayBuf = await file.arrayBuffer();
      const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuf);
      this.verifyDocumentHash = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async executeVerify() {
      if (!this.verifyDocumentHash && !this.verifySignature) {
        this.showToast('Unggah berkas PDF atau masukkan Signature Hex untuk diverifikasi.', 'warning');
        return;
      }

      this.isVerifying = true;
      this.verifyStatus = null;

      try {
        // Cari di registry SQLite berdasarkan hash
        await this.loadUserRegistry();
        const found = this.registryList.find(r => r.document_hash.toLowerCase() === this.verifyDocumentHash.toLowerCase()) ||
                      this.registryList.find(r => this.verifySignature && r.signature_hex.startsWith(this.verifySignature.substring(0, 40)));

        if (found) {
          this.verifyStatus = {
            isValid: true,
            signer: found.signer,
            algorithm: found.algorithm,
            time: found.time_str,
            hash: found.document_hash,
            receiptId: found.id,
            caName: 'ARSign Trust Network (Pascakuantum Ready)',
            chainValid: true
          };
          this.showToast('Tanda Tangan Elektronik TERVERIFIKASI SAH!', 'success');
        } else {
          // Lakukan verifikasi via backend endpoint
          const res = await fetch('/api/v1/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              algorithm: 'ML-DSA-65',
              public_key: this.currentUser ? this.currentUser.mldsa_public_key : '',
              data: this.verifyDocumentHash || 'sample_document',
              signature: this.verifySignature || '00'
            })
          });
          const json = await res.json();
          if (res.ok && json.data && json.data.is_valid) {
            this.verifyStatus = {
              isValid: true,
              signer: this.currentUser ? this.currentUser.fullname : 'Penanda Tangan Sah',
              algorithm: 'Tersertifikasi Sah',
              time: new Date().toLocaleString('id-ID'),
              hash: this.verifyDocumentHash,
              receiptId: 'ARS-VERIFIED',
              caName: 'ARSign Trust Network',
              chainValid: true
            };
            this.showToast('Tanda Tangan Elektronik TERVERIFIKASI SAH!', 'success');
          } else {
            this.verifyStatus = {
              isValid: false,
              message: 'Tanda tangan tidak valid atau berkas telah mengalami modifikasi setelah penandatanganan.'
            };
            this.showToast('Verifikasi gagal: Berkas tidak sah atau telah dimodifikasi.', 'error');
          }
        }
      } catch (err) {
        this.verifyStatus = {
          isValid: false,
          message: 'Kesalahan proses verifikasi: ' + err.message
        };
        this.showToast('Gagal memverifikasi: ' + err.message, 'error');
      } finally {
        this.isVerifying = false;
      }
    },

    // ==========================================
    // PENGATURAN (SETTINGS)
    // ==========================================
    async saveProfile() {
      if (!this.currentUser) return;
      try {
        const res = await fetch('/api/v1/user/profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: this.currentUser.username,
            fullname: this.settingsProfile.fullname,
            email: this.settingsProfile.email,
            institution: this.settingsProfile.institution
          })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.currentUser.fullname = this.settingsProfile.fullname;
          this.currentUser.email = this.settingsProfile.email;
          this.currentUser.institution = this.settingsProfile.institution;
          sessionStorage.setItem('arsign_user', JSON.stringify(this.currentUser));
          this.showToast('Data profil berhasil diperbarui.', 'success');
        } else {
          this.showToast(json.message || 'Gagal menyimpan profil.', 'error');
        }
      } catch (err) {
        this.showToast('Gagal update profil: ' + err.message, 'error');
      }
    },

    async changePassword() {
      const p = this.passwordForm;
      if (!p.old_password || !p.new_password) {
        this.showToast('Kata sandi lama dan baru wajib diisi.', 'warning');
        return;
      }
      if (p.new_password !== p.confirm_password) {
        this.showToast('Konfirmasi kata sandi baru tidak cocok.', 'warning');
        return;
      }

      p.loading = true;
      try {
        const res = await fetch('/api/v1/user/password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: this.currentUser.username,
            old_password: p.old_password,
            new_password: p.new_password
          })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          p.old_password = '';
          p.new_password = '';
          p.confirm_password = '';
          this.showToast('Kata sandi dan Vault kunci privat berhasil diperbarui!', 'success');
        } else {
          this.showToast(json.message || 'Gagal mengubah kata sandi.', 'error');
        }
      } catch (err) {
        this.showToast('Gagal update kata sandi: ' + err.message, 'error');
      } finally {
        p.loading = false;
      }
    },

    async saveDefaultSpecimen() {
      if (!this.specimenImage) {
        this.showToast('Buat atau gambar spesimen terlebih dahulu.', 'warning');
        return;
      }

      this.specimenSaveLoading = true;
      try {
        const res = await fetch('/api/v1/user/specimen', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: this.currentUser.username,
            specimen: this.specimenImage
          })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.currentUser.specimen_signature = this.specimenImage;
          sessionStorage.setItem('arsign_user', JSON.stringify(this.currentUser));
          this.showToast('Spesimen tanda tangan default berhasil disimpan.', 'success');
        } else {
          this.showToast(json.message || 'Gagal menyimpan spesimen.', 'error');
        }
      } catch (err) {
        this.showToast('Gagal menyimpan spesimen: ' + err.message, 'error');
      } finally {
        this.specimenSaveLoading = false;
      }
    },

    async downloadCACertificates() {
      try {
        const res = await fetch('/api/v1/ca/certificates');
        const json = await res.json();
        if (res.ok && json.data && json.data.chain_pem) {
          const blob = new Blob([json.data.chain_pem], { type: 'application/x-pem-file' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'ARSIGN_Root_and_SubCA.pem';
          a.click();
          this.showToast('Rantai Sertifikat ARSign Sub-CA & Root CA diunduh.', 'success');
        }
      } catch (e) {
        this.showToast('Gagal mengunduh sertifikat CA: ' + e.message, 'error');
      }
    },

    copyToClipboard(text) {
      if (!text) return;
      navigator.clipboard.writeText(text);
      this.showToast('Disalin ke papan klip!', 'info');
    }
  }
}).mount('#app');
