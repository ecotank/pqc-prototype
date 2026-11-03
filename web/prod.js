const { createApp } = Vue;

createApp({
  data() {
    return {
      // 1. Theme & Navigation
      theme: localStorage.getItem('arsign_theme') || 'dark',
      currentScreen: 'landing', // 'landing' | 'auth' | 'app'
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
      registerOtp: {
        sent: false,
        input: '',
        timer: 60,
        interval: null,
        loading: false,
        verified: false
      },

      // Onboarding Passphrase Setup
      showPassphraseSetupModal: false,
      passphraseForm: {
        passphrase: '',
        confirm_passphrase: '',
        error: '',
        loading: false
      },

      // Center Signing Passphrase Modal
      showSigningPassphraseModal: false,
      signingPassphraseInput: '',
      signingPassphraseError: '',
      signingPassphraseLoading: false,

      // Center Success Modal & Verification Offer
      showSuccessModal: false,

      // 3. Toast Notifications
      toast: {
        show: false,
        message: '',
        type: 'success', // 'success' | 'error' | 'warning' | 'info'
        timeout: null
      },

      // 4. Fitur TTE (Signing State)
      tteMode: 'visible', // 'visible' | 'invisible'
      specimenSource: 'qrcode', // 'file' | 'qrcode'
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

      // Interactive Drag & Resize Stamp
      isDraggingStamp: false,
      isResizingStamp: false,
      resizeDir: '',
      dragStartMouseX: 0,
      dragStartMouseY: 0,
      dragStartStampX: 0,
      dragStartStampY: 0,
      dragStartStampW: 0,
      dragStartStampH: 0,

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
    // SCREEN NAVIGATION & FLOW
    // ==========================================
    goToLanding() {
      this.currentScreen = 'landing';
    },

    goToAuth(tab = 'login') {
      if (this.currentUser) {
        if (!this.currentUser.has_passphrase) {
          this.showPassphraseSetupModal = true;
        }
        this.currentScreen = 'app';
        return;
      }
      this.authTab = tab;
      this.currentScreen = 'auth';
    },

    goToApp() {
      if (!this.currentUser) {
        this.goToAuth('login');
        return;
      }
      if (!this.currentUser.has_passphrase) {
        this.showPassphraseSetupModal = true;
      }
      this.currentScreen = 'app';
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
            if (!this.currentUser.has_passphrase) {
              this.showPassphraseSetupModal = true;
            }
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
          if (!this.currentUser.has_passphrase) {
            this.showPassphraseSetupModal = true;
          }
          this.currentScreen = 'app';
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

    async sendRegisterOtp() {
      if (!this.registerForm.email || !this.registerForm.email.includes('@')) {
        this.registerForm.error = 'Masukkan alamat email yang valid untuk pengiriman OTP.';
        return;
      }
      this.registerOtp.loading = true;
      this.registerForm.error = '';

      try {
        const res = await fetch('/api/v1/auth/otp/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.registerForm.email.trim() })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.registerOtp.sent = true;
          this.registerOtp.timer = 60;
          this.showToast(`Kode OTP dikirim ke ${this.registerForm.email}`, 'info');
          if (this.registerOtp.interval) clearInterval(this.registerOtp.interval);
          this.registerOtp.interval = setInterval(() => {
            if (this.registerOtp.timer > 0) {
              this.registerOtp.timer--;
            } else {
              clearInterval(this.registerOtp.interval);
            }
          }, 1000);
        } else {
          this.registerForm.error = json.message || 'Gagal mengirim OTP pendaftaran.';
        }
      } catch (err) {
        this.registerForm.error = 'Gagal menghubungi layanan OTP: ' + err.message;
      } finally {
        this.registerOtp.loading = false;
      }
    },

    async verifyRegisterOtp() {
      if (!this.registerOtp.input || this.registerOtp.input.length < 6) {
        this.registerForm.error = 'Masukkan 6 digit kode OTP verifikasi email.';
        return;
      }
      this.registerOtp.loading = true;
      this.registerForm.error = '';

      try {
        const res = await fetch('/api/v1/auth/otp/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: this.registerForm.email.trim(),
            code: this.registerOtp.input.trim()
          })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.registerOtp.verified = true;
          this.showToast('Email terverifikasi secara sah! Silakan selesaikan pendaftaran.', 'success');
        } else {
          this.registerForm.error = json.message || 'Kode OTP tidak cocok.';
        }
      } catch (err) {
        this.registerForm.error = 'Gagal memverifikasi OTP: ' + err.message;
      } finally {
        this.registerOtp.loading = false;
      }
    },

    async register() {
      const f = this.registerForm;
      if (!f.fullname || !f.username || !f.password || !f.nik_nip || !f.email) {
        f.error = 'Seluruh bidang wajib diisi lengkap.';
        return;
      }

      if (!this.registerOtp.verified) {
        f.error = 'Verifikasi kode OTP email Anda terlebih dahulu sebelum mendaftar.';
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
          this.showToast('Akun berhasil dibuat! Silakan masuk dan setel passphrase TTE Anda.', 'success');
          this.authTab = 'login';
          this.loginForm.username = f.username.trim();
          this.loginForm.password = f.password;
          await this.login();
        } else {
          f.error = json.message || 'Pendaftaran gagal.';
        }
      } catch (err) {
        f.error = 'Gagal mendaftar: ' + err.message;
      } finally {
        f.loading = false;
      }
    },

    async savePassphrase() {
      const p = this.passphraseForm;
      if (!p.passphrase || p.passphrase.length < 6) {
        p.error = 'Passphrase minimal 6 karakter demi keamanan penandatanganan.';
        return;
      }
      if (p.passphrase !== p.confirm_passphrase) {
        p.error = 'Konfirmasi passphrase tidak cocok dengan input pertama.';
        return;
      }

      p.loading = true;
      p.error = '';

      try {
        const res = await fetch('/api/v1/auth/passphrase/set', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: this.currentUser.username,
            passphrase: p.passphrase
          })
        });
        const json = await res.json();
        if (res.ok && json.status === 'SUCCESS') {
          this.currentUser.has_passphrase = true;
          sessionStorage.setItem('arsign_user', JSON.stringify(this.currentUser));
          this.showPassphraseSetupModal = false;
          this.showToast('Passphrase penandatanganan TTE berhasil diaktifkan!', 'success');
          this.currentScreen = 'app';
        } else {
          p.error = json.message || 'Gagal menyimpan passphrase.';
        }
      } catch (err) {
        p.error = 'Gagal menyimpan passphrase: ' + err.message;
      } finally {
        p.loading = false;
      }
    },

    logout() {
      sessionStorage.removeItem('arsign_user');
      this.currentUser = null;
      this.registryList = [];
      this.signedResult = null;
      this.currentScreen = 'landing';
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
      if (this.isDraggingStamp || this.isResizingStamp) return;
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

    startStampDrag(e) {
      if (this.isResizingStamp) return;
      e.preventDefault();
      e.stopPropagation();
      this.isDraggingStamp = true;
      this.dragStartMouseX = e.clientX;
      this.dragStartMouseY = e.clientY;
      this.dragStartStampX = this.specimenCustomX;
      this.dragStartStampY = this.specimenCustomY;

      window.addEventListener('mousemove', this.onStampMouseMove);
      window.addEventListener('mouseup', this.onStampMouseUp);
    },

    startStampResize(dir, e) {
      e.preventDefault();
      e.stopPropagation();
      this.isResizingStamp = true;
      this.resizeDir = dir;
      this.dragStartMouseX = e.clientX;
      this.dragStartMouseY = e.clientY;
      this.dragStartStampX = this.specimenCustomX;
      this.dragStartStampY = this.specimenCustomY;
      this.dragStartStampW = this.specimenWidth;
      this.dragStartStampH = this.specimenHeight;

      window.addEventListener('mousemove', this.onStampMouseMove);
      window.addEventListener('mouseup', this.onStampMouseUp);
    },

    onStampMouseMove(e) {
      if (!this.canvasWidth || !this.canvasHeight || !this.pdfActualPageWidth || !this.pdfActualPageHeight) return;

      const scaleX = this.pdfActualPageWidth / this.canvasWidth;
      const scaleY = this.pdfActualPageHeight / this.canvasHeight;

      const deltaPdfX = (e.clientX - this.dragStartMouseX) * scaleX;
      const deltaPdfY = -(e.clientY - this.dragStartMouseY) * scaleY;

      if (this.isDraggingStamp) {
        let newX = this.dragStartStampX + deltaPdfX;
        let newY = this.dragStartStampY + deltaPdfY;

        newX = Math.max(5, Math.min(this.pdfActualPageWidth - this.specimenWidth - 5, newX));
        newY = Math.max(5, Math.min(this.pdfActualPageHeight - this.specimenHeight - 5, newY));

        this.specimenCustomX = Math.round(newX);
        this.specimenCustomY = Math.round(newY);
      } else if (this.isResizingStamp) {
        const dir = this.resizeDir;
        let newW = this.dragStartStampW;
        let newH = this.dragStartStampH;
        let newX = this.dragStartStampX;
        let newY = this.dragStartStampY;

        if (dir.includes('e')) {
          newW = Math.max(60, Math.min(this.pdfActualPageWidth - this.dragStartStampX - 5, this.dragStartStampW + deltaPdfX));
        } else if (dir.includes('w')) {
          const maxLeftShift = this.dragStartStampX;
          const shift = Math.min(maxLeftShift, Math.max(-(this.dragStartStampW - 60), -deltaPdfX));
          newX = this.dragStartStampX - shift;
          newW = this.dragStartStampW + shift;
        }

        if (dir.includes('n')) {
          newH = Math.max(35, Math.min(this.pdfActualPageHeight - this.dragStartStampY - 5, this.dragStartStampH + deltaPdfY));
        } else if (dir.includes('s')) {
          const maxBottomShift = this.dragStartStampY;
          const shift = Math.min(maxBottomShift, Math.max(-(this.dragStartStampH - 35), -deltaPdfY));
          newY = this.dragStartStampY - shift;
          newH = this.dragStartStampH + shift;
        }

        this.specimenCustomX = Math.round(newX);
        this.specimenCustomY = Math.round(newY);
        this.specimenWidth = Math.round(newW);
        this.specimenHeight = Math.round(newH);
      }
    },

    onStampMouseUp() {
      this.isDraggingStamp = false;
      this.isResizingStamp = false;
      this.resizeDir = '';
      window.removeEventListener('mousemove', this.onStampMouseMove);
      window.removeEventListener('mouseup', this.onStampMouseUp);
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
    // SPESIMEN & FILE HANDLING
    // ==========================================
    async handleSpecimenFileUpload(e) {
      const file = e.target.files && e.target.files[0];
      if (!file) return;

      if (file.type === 'application/pdf') {
        try {
          const arrayBuffer = await file.arrayBuffer();
          if (window.pdfjsLib) {
            const pdf = await window.pdfjsLib.getDocument({ data: arrayBuffer }).promise;
            const page = await pdf.getPage(1);
            const viewport = page.getViewport({ scale: 1.5 });
            const canvas = document.createElement('canvas');
            canvas.width = viewport.width;
            canvas.height = viewport.height;
            const ctx = canvas.getContext('2d');
            await page.render({ canvasContext: ctx, viewport: viewport }).promise;
            this.specimenImage = canvas.toDataURL('image/png');
            this.specimenSource = 'file';
            this.showToast('Halaman pertama spesimen PDF berhasil dimuat sebagai stempel.', 'success');
          } else {
            this.showToast('Pustaka PDF viewer belum siap.', 'warning');
          }
        } catch (err) {
          this.showToast('Gagal memuat spesimen PDF: ' + err.message, 'error');
        }
      } else {
        const reader = new FileReader();
        reader.onload = (ev) => {
          this.specimenImage = ev.target.result;
          this.specimenSource = 'file';
          this.showToast('Gambar spesimen tanda tangan berhasil diunggah.', 'success');
        };
        reader.readAsDataURL(file);
      }
    },

    // ==========================================
    // FITUR TTE: SIGNING PROCESS (PASSPHRASE AUTH)
    // ==========================================
    openSigningPassphraseModal() {
      if (!this.currentUser) {
        this.showToast('Wajib masuk untuk menandatangani berkas.', 'error');
        this.goToAuth('login');
        return;
      }

      if (!this.currentUser.has_passphrase) {
        this.showToast('Silakan atur passphrase penandatanganan Anda terlebih dahulu.', 'warning');
        this.showPassphraseSetupModal = true;
        return;
      }

      if (this.inputMethod === 'file' && !this.fileArrayBuffer) {
        this.showToast('Silakan pilih berkas PDF yang akan ditandatangani.', 'warning');
        return;
      }

      this.signingPassphraseInput = '';
      this.signingPassphraseError = '';
      this.showSigningPassphraseModal = true;
    },

    async confirmAndSignDocument() {
      if (!this.signingPassphraseInput) {
        this.signingPassphraseError = 'Masukkan passphrase penandatanganan Anda.';
        return;
      }

      this.signingPassphraseLoading = true;
      this.signingPassphraseError = '';

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

        // 1. Sematkan visualisasi spesimen / stempel QR Code / mode invisible
        if (window.PDFSigner) {
          const visualRes = await window.PDFSigner.embedSpecimenAndStamp({
            pdfArrayBuffer: this.inputMethod === 'file' ? this.fileArrayBuffer : null,
            textContent: this.inputMethod === 'text' ? this.documentContent : null,
            invisible: this.tteMode === 'invisible',
            stampType: this.specimenSource === 'file' ? 'specimen' : 'qrcode_name',
            specimenDataUrl: (this.tteMode === 'visible' && this.specimenSource === 'file') ? this.specimenImage : null,
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

        // 2. Hubungi Backend PAdES Endpoint dengan Passphrase
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
            passphrase: this.signingPassphraseInput,
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
          signed_blob: blob,
          file_name: 'ARSIGN_SIGNED_' + (this.fileName || 'dokumen.pdf'),
          signed_at: new Date().toLocaleString('id-ID')
        };

        // Catat di Registry SQLite
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

        // Tutup modal passphrase, buka modal sukses
        this.showSigningPassphraseModal = false;
        this.showSuccessModal = true;
        this.showToast('Dokumen berhasil ditandatangani secara elektronik!', 'success');
      } catch (err) {
        this.signingPassphraseError = err.message || 'Gagal menandatangani berkas';
      } finally {
        this.signingPassphraseLoading = false;
      }
    },

    downloadSignedPdf() {
      if (!this.signedResult || !this.signedResult.pdf_blob_url) return;
      const a = document.createElement('a');
      a.href = this.signedResult.pdf_blob_url;
      a.download = this.signedResult.file_name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    },

    openVerificationFromSuccess() {
      if (!this.signedResult) return;
      const targetBlob = this.signedResult.signed_blob;
      const targetName = this.signedResult.file_name;
      this.showSuccessModal = false;

      this.activeTab = 'verify';
      this.verifyFileName = targetName;
      this.verifyFile = new File([targetBlob], targetName, { type: 'application/pdf' });
      this.verifyStatus = null;

      this.$nextTick(() => {
        this.executeVerify();
      });
    },

    // ==========================================
    // FITUR VERIFIKASI TTE
    // ==========================================
    async handleVerifyFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      this.verifyFile = file;
      this.verifyFileName = file.name;
      this.verifyStatus = null;
    },

    async executeVerify() {
      if (!this.verifyFile) {
        this.showToast('Silakan unggah berkas PDF untuk diverifikasi.', 'warning');
        return;
      }

      this.isVerifying = true;
      this.verifyStatus = null;

      try {
        const arrayBuf = await this.verifyFile.arrayBuffer();
        let binary = '';
        const bytes = new Uint8Array(arrayBuf);
        const len = bytes.byteLength;
        const chunkSize = 8192;
        for (let i = 0; i < len; i += chunkSize) {
          binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + chunkSize, len)));
        }
        const base64Data = btoa(binary);

        const res = await fetch('/api/v1/pades/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pdf_base64: base64Data })
        });
        const json = await res.json();

        if (res.ok && json.status === 'SUCCESS' && json.data) {
          const d = json.data;
          if (d.is_valid) {
            this.verifyStatus = {
              isValid: true,
              signer: d.signer_fullname || d.signer_name || 'Penanda Tangan Sah',
              time: d.signed_at || d.signing_time || new Date().toLocaleString('id-ID'),
              statusMessage: d.integrity_status || d.status_message || d.message || 'Dokumen Asli & Utuh — Belum pernah diubah atau dimodifikasi sejak ditandatangani.',
              receiptId: d.receipt_id || 'ARS-VERIFIED',
              caName: d.cert_issuer || 'ARSign Sub-CA Pelayanan TTE Pascakuantum',
              institution: d.institution || 'ARSign Trust Network',
              hasPqc: d.has_pqc,
              pqcValid: d.pqc_valid
            };
            this.showToast('Dokumen ASLI & Tanda Tangan Elektronik TERVERIFIKASI SAH!', 'success');
          } else {
            this.verifyStatus = {
              isValid: false,
              message: d.integrity_status || d.status_message || d.message || 'Dokumen telah mengalami perubahan atau manipulasi setelah ditandatangani.'
            };
            this.showToast('Verifikasi gagal: Berkas telah mengalami modifikasi atau tidak valid.', 'error');
          }
        } else {
          this.verifyStatus = {
            isValid: false,
            message: json.message || 'Berkas tidak memiliki struktur tanda tangan elektronik resmi (PAdES).'
          };
          this.showToast(json.message || 'Verifikasi gagal: Berkas bukan dokumen bertanda tangan resmi.', 'error');
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
