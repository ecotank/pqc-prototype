const { createApp } = Vue;

createApp({
  data() {
    return {
      activeTab: 'dashboard',
      inputMethod: 'file',
      documentContent: 'NOTA DINAS RESMI BADAN SIBER DAN SANDI NEGARA\nNomor: ND-812/BSSN/BSRE/PQC/10/2026\nPerihal: Penerapan Standar Digital Signature NIST FIPS 204 pada Layanan Sertifikasi Elektronik Nasional.',
      fileName: '',
      fileSize: 0,
      fileArrayBuffer: null,
      documentHash: '',
      enableDualSign: false,
      isSigning: false,
      signedResult: null,

      // Specimen state
      specimenMode: 'upload',
      specimenImage: null,
      specimenFileName: '',
      specimenPosition: 'bottom-right',
      specimenWidth: 210,
      specimenHeight: 92,
      specimenCustomX: 350,
      specimenCustomY: 50,
      specimenPage: 'last',
      specimenSizePreset: 'standar',

      // PDF Interactive Viewer & Select Tool
      pdfDocProxy: null,
      pdfCurrentPage: 1,
      pdfTotalPages: 1,
      pdfActualPageWidth: 595.28,
      pdfActualPageHeight: 841.89,
      canvasWidth: 595,
      canvasHeight: 842,
      isPdfLoading: false,
      selectToolActive: true,
      isSelectingArea: false,
      selectionStart: null,
      selectionCurrent: null,
      isDraggingBox: false,
      dragMouseStartX: 0,
      dragMouseStartY: 0,
      dragInitialPdfX: 350,
      dragInitialPdfY: 50,

      // Signer active keys
      mldsaKey: null,
      rsaKey: null,

      // Verifier form
      verifyDocument: '',
      verifySignature: '',
      verifyFileName: '',
      isVerifying: false,
      verifyStatus: null,

      // Document Registry Log (Persisted in SQLite)
      registryList: [],

      // Authentication State
      currentUser: null,
      showAuthModal: false,
      authModalTab: 'login', // 'login' | 'register' | 'quick'
      loginForm: {
        username: '',
        password: '',
        error: '',
        loading: false
      },
      registerForm: {
        fullname: '',
        username: '',
        password: '',
        nik_nip: '',
        institution: '',
        email: '',
        role: 'PUBLIC',
        error: '',
        loading: false
      },
      availableUsers: []
    };
  },

  watch: {
    activeTab(newTab) {
      if (newTab === 'sign') {
        this.$nextTick(() => {
          this.renderPdfViewer(this.pdfCurrentPage);
        });
      }
    },
    inputMethod() {
      this.$nextTick(() => {
        this.renderPdfViewer(1);
      });
    }
  },

  mounted() {
    // Restore session if exists
    const savedUser = localStorage.getItem('pqc_user');
    if (savedUser) {
      try {
        this.currentUser = JSON.parse(savedUser);
      } catch (e) {}
    }

    if (window.pdfjsLib) {
      window.pdfjsLib.GlobalWorkerOptions.workerSrc = '/vendor/pdf.worker.min.js';
    }

    this.calculateHash();
    this.initProductionKeys();
    this.generateDefaultSpecimen();
    this.fetchRegistry();
    this.fetchUsersList();

    this.$nextTick(() => {
      this.renderPdfViewer(1);
    });
  },

  methods: {
    tabClass(tab) {
      if (this.activeTab === tab) {
        return 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white shadow-sm';
      }
      return 'px-3.5 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition';
    },

    async initProductionKeys() {
      try {
        const resMldsa = await fetch('/api/v1/keys/generate?algorithm=ML-DSA-65', { method: 'POST' });
        const jsonMldsa = await resMldsa.json();
        if (jsonMldsa.status === 'SUCCESS') {
          this.mldsaKey = jsonMldsa.data;
        }

        const resRsa = await fetch('/api/v1/keys/generate?algorithm=RSA-2048', { method: 'POST' });
        const jsonRsa = await resRsa.json();
        if (jsonRsa.status === 'SUCCESS') {
          this.rsaKey = jsonRsa.data;
        }
      } catch (err) {
        console.error('Inisialisasi kunci gagal:', err);
      }
    },

    async fetchRegistry() {
      try {
        const res = await fetch('/api/v1/registry');
        const json = await res.json();
        if (json.status === 'SUCCESS' && json.data) {
          this.registryList = json.data;
        }
      } catch (err) {
        console.error('Gagal memuat buku registrasi:', err);
      }
    },

    // Buat contoh spesimen tanda tangan default jika user belum upload
    generateDefaultSpecimen() {
      const canvas = document.createElement('canvas');
      canvas.width = 280;
      canvas.height = 100;
      const ctx = canvas.getContext('2d');

      ctx.strokeStyle = '#1e3a8a';
      ctx.lineWidth = 3;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.moveTo(30, 70);
      ctx.bezierCurveTo(60, 20, 80, 80, 110, 40);
      ctx.bezierCurveTo(130, 20, 150, 75, 180, 50);
      ctx.bezierCurveTo(210, 30, 230, 80, 260, 35);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(25, 80);
      ctx.lineTo(265, 75);
      ctx.stroke();

      this.specimenImage = canvas.toDataURL('image/png');
      this.specimenFileName = 'spesimen_tanda_tangan_satria_alba.png';
    },

    handleSpecimenUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      this.specimenFileName = file.name;

      const reader = new FileReader();
      reader.onload = (event) => {
        this.specimenImage = event.target.result;
      };
      reader.readAsDataURL(file);
    },

    setSpecimenSizePreset(preset) {
      this.specimenSizePreset = preset;
      if (preset === 'kecil') {
        this.specimenWidth = 160;
        this.specimenHeight = 70;
      } else if (preset === 'standar') {
        this.specimenWidth = 210;
        this.specimenHeight = 92;
      } else if (preset === 'besar') {
        this.specimenWidth = 270;
        this.specimenHeight = 118;
      }
      this.updateSpecimenPresetCoordinates(this.specimenPosition);
    },

    setSpecimenPositionPreset(pos) {
      this.specimenPosition = pos;
      this.updateSpecimenPresetCoordinates(pos);
    },

    updateSpecimenPresetCoordinates(pos) {
      const pageW = 595;
      const pageH = 842;
      const w = Number(this.specimenWidth) || 210;
      const h = Number(this.specimenHeight) || 92;

      if (pos === 'bottom-right') {
        this.specimenCustomX = Math.round(pageW - w - 35);
        this.specimenCustomY = 50;
      } else if (pos === 'bottom-left') {
        this.specimenCustomX = 45;
        this.specimenCustomY = 50;
      } else if (pos === 'center') {
        this.specimenCustomX = Math.round((pageW - w) / 2);
        this.specimenCustomY = 50;
      } else if (pos === 'top-right') {
        this.specimenCustomX = Math.round(pageW - w - 35);
        this.specimenCustomY = Math.round(pageH - h - 50);
      } else if (pos === 'top-left') {
        this.specimenCustomX = 45;
        this.specimenCustomY = Math.round(pageH - h - 50);
      } else if (pos === 'center-middle') {
        this.specimenCustomX = Math.round((pageW - w) / 2);
        this.specimenCustomY = Math.round((pageH - h) / 2);
      }
    },

    handleMiniCanvasClick(e) {
      const rect = e.currentTarget.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      const pageW = 595;
      const pageH = 842;
      const w = Number(this.specimenWidth) || 210;
      const h = Number(this.specimenHeight) || 92;

      let targetX = Math.round((clickX / rect.width) * pageW - (w / 2));
      let targetY = Math.round(((rect.height - clickY) / rect.height) * pageH - (h / 2));

      targetX = Math.max(10, Math.min(targetX, pageW - w - 10));
      targetY = Math.max(10, Math.min(targetY, pageH - h - 10));

      this.specimenCustomX = targetX;
      this.specimenCustomY = targetY;
      this.specimenPosition = 'custom';
    },

    async calculateHash() {
      if (this.inputMethod === 'text' && this.documentContent) {
        const enc = new TextEncoder();
        const buf = enc.encode(this.documentContent);
        const hashBuf = await crypto.subtle.digest('SHA-256', buf);
        this.documentHash = Array.from(new Uint8Array(hashBuf))
          .map(b => b.toString(16).padStart(2, '0')).join('');
        await this.renderPdfViewer(1);
      }
    },

    async handleFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      this.fileName = file.name;
      this.fileSize = file.size;

      const arrayBuf = await file.arrayBuffer();
      this.fileArrayBuffer = arrayBuf;
      const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuf);
      this.documentHash = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      
      await this.renderPdfViewer(1);
    },

    async renderPdfViewer(pageNumber = 1) {
      if (!window.pdfjsLib) return;
      this.isPdfLoading = true;
      try {
        let pdfData = this.fileArrayBuffer;
        if (!pdfData) {
          // Buat representasi PDF dari teks nota dinas secara in-memory
          const doc = await PDFLib.PDFDocument.create();
          const page = doc.addPage([595.28, 841.89]);
          const fontBold = await doc.embedFont(PDFLib.StandardFonts.HelveticaBold);
          const fontNorm = await doc.embedFont(PDFLib.StandardFonts.Helvetica);

          page.drawText('BADAN SIBER DAN SANDI NEGARA', { x: 50, y: 790, size: 14, font: fontBold, color: PDFLib.rgb(0.05, 0.15, 0.35) });
          page.drawText('BALAI BESAR SERTIFIKASI ELEKTRONIK (BSrE)', { x: 50, y: 772, size: 11, font: fontBold, color: PDFLib.rgb(0.2, 0.2, 0.2) });
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
        this.pdfDocProxy = await loadingTask.promise;
        this.pdfTotalPages = this.pdfDocProxy.numPages;
        this.pdfCurrentPage = Math.min(Math.max(1, pageNumber), this.pdfTotalPages);

        const page = await this.pdfDocProxy.getPage(this.pdfCurrentPage);
        const viewport = page.getViewport({ scale: 1.0 });
        this.pdfActualPageWidth = viewport.width;
        this.pdfActualPageHeight = viewport.height;

        const canvas = document.getElementById('pdfViewerCanvas');
        if (!canvas) return;

        const container = canvas.parentElement;
        const availableWidth = container ? Math.min(container.clientWidth, 680) : 580;
        const scale = availableWidth / viewport.width;

        const scaledViewport = page.getViewport({ scale: scale });
        canvas.width = scaledViewport.width;
        canvas.height = scaledViewport.height;
        this.canvasWidth = scaledViewport.width;
        this.canvasHeight = scaledViewport.height;

        const context = canvas.getContext('2d');
        const renderContext = {
          canvasContext: context,
          viewport: scaledViewport
        };
        await page.render(renderContext).promise;
      } catch (err) {
        console.warn('Gagal merender pratinjau PDF:', err);
      } finally {
        this.isPdfLoading = false;
      }
    },

    async prevPdfPage() {
      if (this.pdfCurrentPage > 1) {
        await this.renderPdfViewer(this.pdfCurrentPage - 1);
        this.specimenPage = this.pdfCurrentPage;
      }
    },

    async nextPdfPage() {
      if (this.pdfCurrentPage < this.pdfTotalPages) {
        await this.renderPdfViewer(this.pdfCurrentPage + 1);
        this.specimenPage = this.pdfCurrentPage;
      }
    },

    startSelection(e) {
      if (!this.selectToolActive) return;
      const overlay = this.$refs.pdfOverlay;
      if (!overlay) return;
      const rect = overlay.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      this.isSelectingArea = true;
      this.selectionStart = { x, y };
      this.selectionCurrent = { x, y };

      const onMove = (moveEvt) => {
        if (!this.isSelectingArea) return;
        const curX = Math.max(0, Math.min(rect.width, moveEvt.clientX - rect.left));
        const curY = Math.max(0, Math.min(rect.height, moveEvt.clientY - rect.top));
        this.selectionCurrent = { x: curX, y: curY };
      };

      const onUp = () => {
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
        if (!this.isSelectingArea) return;
        this.isSelectingArea = false;

        if (!this.selectionStart || !this.selectionCurrent) return;

        const x0 = this.selectionStart.x;
        const y0 = this.selectionStart.y;
        const x1 = this.selectionCurrent.x;
        const y1 = this.selectionCurrent.y;

        const left = Math.min(x0, x1);
        const top = Math.min(y0, y1);
        const w = Math.abs(x1 - x0);
        const h = Math.abs(y1 - y0);

        const ptScaleX = this.pdfActualPageWidth / this.canvasWidth;
        const ptScaleY = this.pdfActualPageHeight / this.canvasHeight;

        if (w < 15 || h < 15) {
          const clickPdfX = left * ptScaleX;
          const clickPdfY = (this.canvasHeight - top) * ptScaleY;
          this.specimenCustomX = Math.round(Math.max(5, Math.min(this.pdfActualPageWidth - this.specimenWidth - 5, clickPdfX - (this.specimenWidth / 2))));
          this.specimenCustomY = Math.round(Math.max(5, Math.min(this.pdfActualPageHeight - this.specimenHeight - 5, clickPdfY - (this.specimenHeight / 2))));
        } else {
          const newW = Math.round(w * ptScaleX);
          const newH = Math.round(h * ptScaleY);
          const newX = Math.round(left * ptScaleX);
          const newY = Math.round((this.canvasHeight - (top + h)) * ptScaleY);

          this.specimenWidth = Math.max(90, Math.min(Math.round(this.pdfActualPageWidth - 10), newW));
          this.specimenHeight = Math.max(45, Math.min(Math.round(this.pdfActualPageHeight - 10), newH));
          this.specimenCustomX = Math.max(5, Math.min(Math.round(this.pdfActualPageWidth - this.specimenWidth - 5), newX));
          this.specimenCustomY = Math.max(5, Math.min(Math.round(this.pdfActualPageHeight - this.specimenHeight - 5), newY));
        }

        this.specimenPosition = 'custom';
        this.specimenSizePreset = 'custom';
        this.specimenPage = this.pdfCurrentPage;
        this.selectionStart = null;
        this.selectionCurrent = null;
      };

      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    },

    startDragBox(e) {
      e.stopPropagation();
      this.isDraggingBox = true;
      this.dragMouseStartX = e.clientX;
      this.dragMouseStartY = e.clientY;
      this.dragInitialPdfX = Number(this.specimenCustomX);
      this.dragInitialPdfY = Number(this.specimenCustomY);

      const ptScaleX = this.pdfActualPageWidth / this.canvasWidth;
      const ptScaleY = this.pdfActualPageHeight / this.canvasHeight;

      const onMove = (moveEvt) => {
        if (!this.isDraggingBox) return;
        const deltaX = moveEvt.clientX - this.dragMouseStartX;
        const deltaY = moveEvt.clientY - this.dragMouseStartY;

        const ptDeltaX = deltaX * ptScaleX;
        const ptDeltaY = -deltaY * ptScaleY;

        const targetX = Math.round(Math.max(5, Math.min(this.pdfActualPageWidth - this.specimenWidth - 5, this.dragInitialPdfX + ptDeltaX)));
        const targetY = Math.round(Math.max(5, Math.min(this.pdfActualPageHeight - this.specimenHeight - 5, this.dragInitialPdfY + ptDeltaY)));

        this.specimenCustomX = targetX;
        this.specimenCustomY = targetY;
        this.specimenPosition = 'custom';
      };

      const onUp = () => {
        this.isDraggingBox = false;
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
      };

      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    },

    getSpecimenBoxStyle() {
      if (!this.canvasWidth || !this.canvasHeight || !this.pdfActualPageWidth || !this.pdfActualPageHeight) {
        return { display: 'none' };
      }
      const leftPercent = (this.specimenCustomX / this.pdfActualPageWidth) * 100;
      const widthPercent = (this.specimenWidth / this.pdfActualPageWidth) * 100;
      const heightPercent = (this.specimenHeight / this.pdfActualPageHeight) * 100;
      const topPercent = ((this.pdfActualPageHeight - this.specimenCustomY - this.specimenHeight) / this.pdfActualPageHeight) * 100;

      const isCurrentTarget = (this.specimenPage === 'last' && this.pdfCurrentPage === this.pdfTotalPages) ||
                              (this.specimenPage === 'first' && this.pdfCurrentPage === 1) ||
                              (Number(this.specimenPage) === this.pdfCurrentPage) ||
                              (this.specimenPage === this.pdfCurrentPage);

      return {
        left: Math.max(0, Math.min(100 - widthPercent, leftPercent)) + '%',
        top: Math.max(0, Math.min(100 - heightPercent, topPercent)) + '%',
        width: Math.max(5, Math.min(100, widthPercent)) + '%',
        height: Math.max(4, Math.min(100, heightPercent)) + '%',
        opacity: isCurrentTarget ? 1 : 0.4
      };
    },

    getSelectingBoxStyle() {
      if (!this.selectionStart || !this.selectionCurrent) return { display: 'none' };
      const left = Math.min(this.selectionStart.x, this.selectionCurrent.x);
      const top = Math.min(this.selectionStart.y, this.selectionCurrent.y);
      const width = Math.abs(this.selectionCurrent.x - this.selectionStart.x);
      const height = Math.abs(this.selectionCurrent.y - this.selectionStart.y);
      return {
        left: left + 'px',
        top: top + 'px',
        width: width + 'px',
        height: height + 'px'
      };
    },

    async handleVerifyFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      this.verifyFileName = file.name;

      const arrayBuf = await file.arrayBuffer();
      const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuf);
      this.verifyDocument = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async signDocument() {
      // Wajib login untuk menandatangani dokumen
      if (!this.currentUser) {
        this.openAuthModal('login');
        return;
      }

      if (!this.mldsaKey) {
        await this.initProductionKeys();
      }
      this.isSigning = true;

      try {
        let pdfBytesFinal = null;
        const receiptUUID = 'BSRE-TTE-' + Math.floor(100000 + Math.random() * 900000);
        const signerFullName = this.currentUser.fullname || 'Satria Alba Pramasha, S.Tr.Kom.';
        const signerEmail = this.currentUser.email || 'satria.alba@bsre.bssn.go.id';
        const signerPrivKey = (this.currentUser && this.currentUser.mldsa_private_key) ? this.currentUser.mldsa_private_key : (this.mldsaKey ? this.mldsaKey.private_key_hex : '');
        const signerPubKey = (this.currentUser && this.currentUser.mldsa_public_key) ? this.currentUser.mldsa_public_key : (this.mldsaKey ? this.mldsaKey.public_key_hex : '');

        // 1. Panggil Modul Ekstraksi Visual PDF (PDFSigner)
        try {
          if (window.PDFSigner) {
            const visualRes = await window.PDFSigner.embedSpecimenAndStamp({
              pdfArrayBuffer: this.inputMethod === 'file' ? this.fileArrayBuffer : null,
              textContent: this.inputMethod === 'text' ? this.documentContent : null,
              specimenDataUrl: this.specimenMode === 'upload' ? this.specimenImage : null,
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
        } catch (pdfErr) {
          console.warn('Pemrosesan visual PDF gagal, fallback ke hash dokumen asli:', pdfErr);
        }

        let blobUrl = null;
        if (pdfBytesFinal) {
          const blob = new Blob([pdfBytesFinal], { type: 'application/pdf' });
          blobUrl = URL.createObjectURL(blob);
        }

        // 2. Panggil Layanan API Penandatanganan Kriptografi (ML-DSA FIPS 204)
        let endpoint = '/api/v1/sign';
        let payload = {
          signer_id: signerEmail,
          algorithm: 'ML-DSA-65',
          digest: this.documentHash,
          private_key: signerPrivKey,
          format: 'hex'
        };

        if (this.enableDualSign) {
          endpoint = '/api/v1/dual-sign';
          payload = {
            mldsa_algorithm: 'ML-DSA-65',
            mldsa_private_key: this.mldsaKey.private_key_hex,
            rsa_private_key: this.rsaKey.private_key_hex,
            digest: this.documentHash
          };
        }

        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.status === 'SUCCESS') {
          const now = new Date();
          const algName = this.enableDualSign ? 'ML-DSA-65 + RSA-2048 (Dual Sign)' : 'ML-DSA-65 (NIST FIPS 204)';
          const sigHex = this.enableDualSign ? data.data.mldsa.signature_hex : data.data.signature_hex;
          const sigBytes = this.enableDualSign ? data.data.total_size_bytes : data.data.signature_bytes;
          const durMs = this.enableDualSign ? data.data.total_duration_ms : data.data.sign_duration_ms;

          // Buat blob PDF final dengan menyematkan metadata tanda tangan kriptografi
          if (pdfBytesFinal) {
            try {
              const pDoc = await PDFLib.PDFDocument.load(pdfBytesFinal);
              pDoc.setSubject(JSON.stringify({
                receiptId: receiptUUID,
                algorithm: algName,
                documentHash: this.documentHash,
                signatureHex: sigHex,
                publicKeyHex: signerPubKey,
                signer: signerFullName
              }));
              pDoc.setKeywords([
                `BSRE_ID:${receiptUUID}`,
                `BSRE_SIG:${sigHex}`,
                `BSRE_HASH:${this.documentHash}`
              ]);
              const taggedPdfBytes = await pDoc.save();
              const blob = new Blob([taggedPdfBytes], { type: 'application/pdf' });
              blobUrl = URL.createObjectURL(blob);
            } catch (embedMetaErr) {
              const blob = new Blob([pdfBytesFinal], { type: 'application/pdf' });
              blobUrl = URL.createObjectURL(blob);
            }
          }

          this.signedResult = {
            receiptId: receiptUUID,
            algorithm: algName,
            signedAt: now.toLocaleString('id-ID', { dateStyle: 'full', timeStyle: 'medium' }),
            durationMs: durMs,
            signatureBytes: sigBytes,
            signatureHex: sigHex,
            documentHash: this.documentHash,
            publicKeyHex: signerPubKey,
            signedPdfBlobUrl: blobUrl,
            specimenUsed: this.specimenMode === 'upload' ? this.specimenImage : null,
            hasVisualSpecimen: this.specimenMode === 'upload' && !!this.specimenImage
          };

          // 3. Simpan ke Database SQLite Permanen via API
          const docTitle = this.inputMethod === 'file' ? ('Dokumen: ' + (this.fileName || 'Dokumen_Resmi.pdf')) : 'Nota Dinas Resmi BSrE';
          const timeStr = now.toLocaleTimeString('id-ID') + ' WIB';

          await fetch('/api/v1/registry', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              id: receiptUUID,
              title: docTitle,
              signer: signerFullName,
              algorithm: algName,
              time: timeStr,
              document_hash: this.documentHash,
              signature_hex: sigHex
            })
          });

          await this.fetchRegistry();
        } else {
          alert('Gagal menandatangani: ' + (data.message || data.status_message));
        }
      } catch (err) {
        console.error(err);
        alert('Kesalahan pemrosesan tanda tangan: ' + err.message);
      } finally {
        this.isSigning = false;
      }
    },

    downloadSignedPdf() {
      if (!this.signedResult || !this.signedResult.signedPdfBlobUrl) return;
      const a = document.createElement('a');
      a.href = this.signedResult.signedPdfBlobUrl;
      a.download = `dokumen_tertanda_spesimen_${this.signedResult.receiptId}.pdf`;
      a.click();
    },

    downloadReceipt() {
      if (!this.signedResult) return;
      const receiptData = JSON.stringify({
        instansi: 'Balai Besar Sertifikasi Elektronik - BSSN',
        status: 'RESMI_TERVERIFIKASI',
        standard: 'NIST FIPS 204 (ML-DSA)',
        metadata: this.signedResult
      }, null, 2);

      const blob = new Blob([receiptData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `bukti_tte_${this.signedResult.receiptId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    },

    forwardToVerify() {
      if (!this.signedResult) return;
      this.verifyDocument = this.signedResult.documentHash;
      this.verifySignature = this.signedResult.signatureHex;
      this.activeTab = 'verify';
      this.verifyStatus = null;
    },

    async verifyPublicDocument() {
      if (!this.verifyDocument || !this.verifySignature) {
        alert('Mohon isi konten dokumen/hash dan tanda tangan digital.');
        return;
      }
      this.isVerifying = true;

      try {
        const payload = {
          algorithm: 'ML-DSA-65',
          digest: this.verifyDocument,
          public_key: this.mldsaKey.public_key_hex,
          signature: this.verifySignature
        };

        const res = await fetch('/api/v1/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.status === 'SUCCESS') {
          this.verifyStatus = {
            valid: data.data.valid,
            durationMs: data.data.verify_duration_ms,
            reason: data.data.reason
          };
        } else {
          this.verifyStatus = {
            valid: false,
            durationMs: 0,
            reason: data.message || 'Verifikasi gagal diproses'
          };
        }
      } catch (err) {
        this.verifyStatus = {
          valid: false,
          durationMs: 0,
          reason: 'Kesalahan sistem: ' + err.message
        };
      } finally {
        this.isVerifying = false;
      }
    },

    async handleVerifyFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      this.verifyFileName = file.name;
      this.verifyStatus = null;

      // 1. Jika pengguna mengunggah berkas JSON tanda terima resmi
      if (file.name.endsWith('.json')) {
        try {
          const text = await file.text();
          const json = JSON.parse(text);
          if (json.metadata && json.metadata.signatureHex) {
            this.verifyDocument = json.metadata.documentHash;
            this.verifySignature = json.metadata.signatureHex;
            await this.verifyPublicDocument();
            return;
          }
        } catch (err) {
          console.error(err);
        }
      }

      // 2. Baca berkas dokumen PDF
      const arrayBuf = await file.arrayBuffer();
      const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuf);
      const computedHash = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');

      this.verifyDocument = computedHash;

      // Pastikan registry terbaru dari server SQLite sudah dimuat
      await this.fetchRegistry();

      let detectedSig = '';
      let targetHash = computedHash;

      // Cara A: Periksa metadata internal PDF (jika memuat embedded BSrE signature)
      try {
        const pdfDoc = await PDFLib.PDFDocument.load(arrayBuf, { ignoreEncryption: true });
        const subject = pdfDoc.getSubject();
        if (subject && subject.startsWith('{') && subject.includes('signatureHex')) {
          const meta = JSON.parse(subject);
          detectedSig = meta.signatureHex;
          targetHash = meta.documentHash || computedHash;
        } else {
          const keywords = pdfDoc.getKeywords();
          if (keywords && keywords.length > 0) {
            for (const kw of keywords) {
              if (kw.startsWith('BSRE_SIG:')) detectedSig = kw.replace('BSRE_SIG:', '');
              if (kw.startsWith('BSRE_HASH:')) targetHash = kw.replace('BSRE_HASH:', '');
            }
          }
        }
      } catch (pdfErr) {
        // Abaikan jika bukan format PDF yang dapat di-parse
      }

      // Cara B: Cek apakah hash berkas terdaftar di database SQLite registry
      if (!detectedSig) {
        const matchByHash = this.registryList.find(r => r.document_hash.toLowerCase() === computedHash.toLowerCase());
        if (matchByHash && matchByHash.signature_hex) {
          detectedSig = matchByHash.signature_hex;
          targetHash = matchByHash.document_hash;
        }
      }

      // Cara C: Cek apakah nama berkas memuat Nomor Registrasi BSrE (contoh: BSRE-TTE-747830)
      if (!detectedSig) {
        const idMatch = file.name.match(/BSRE-[A-Z0-9-]+/i);
        if (idMatch) {
          const regId = idMatch[0].toUpperCase();
          const matchById = this.registryList.find(r => r.id.toUpperCase() === regId);
          if (matchById && matchById.signature_hex) {
            detectedSig = matchById.signature_hex;
            targetHash = matchById.document_hash;
          }
        }
      }

      // Jika tanda tangan digital berhasil dideteksi otomatis
      if (detectedSig) {
        this.verifyDocument = targetHash;
        this.verifySignature = detectedSig;
        // Langsung eksekusi pengujian kriptografi FIPS 204 tanpa meminta input manual!
        await this.verifyPublicDocument();
      } else {
        alert(`Berkas "${file.name}" berhasil dibaca (Hash SHA-256 terhitung). Berkas ini belum terdata di buku registrasi lokal. Silakan pilih dari Buku Registrasi atau unggah berkas tanda terima resmi (.json).`);
      }
    },

    loadRegistryToVerify(item) {
      this.verifyDocument = item.document_hash;
      this.verifySignature = item.signature_hex || '';
      this.verifyFileName = item.title;
      this.activeTab = 'verify';
      this.verifyStatus = null;
    },

    loadLastSignedToVerify() {
      if (this.signedResult) {
        this.verifyDocument = this.signedResult.documentHash;
        this.verifySignature = this.signedResult.signatureHex;
        this.verifyFileName = this.fileName || 'Dokumen_Terkini.pdf';
        this.verifyStatus = null;
      } else if (this.registryList.length > 0) {
        this.loadRegistryToVerify(this.registryList[0]);
      } else {
        alert('Belum ada dokumen yang ditandatangani dalam sesi ini.');
      }
    },

    tamperVerifyDocument() {
      if (!this.verifyDocument) return;
      const first = this.verifyDocument[0];
      const repl = first === 'a' ? 'b' : (first === '0' ? '1' : 'a');
      this.verifyDocument = repl + this.verifyDocument.slice(1);
      alert('Simulasi: Berkas atau spesimen tanda tangan telah dimodifikasi (1 bit/karakter berubah). Klik "Periksa Keabsahan Dokumen" untuk melihat proteksi integritas.');
    },

    async refreshRegistry() {
      await this.fetchRegistry();
      alert('Data registrasi diperbarui dari database SQLite.');
    },

    openAuthModal(tab) {
      this.authModalTab = tab || 'login';
      this.loginForm.error = '';
      this.registerForm.error = '';
      this.showAuthModal = true;
    },

    closeAuthModal() {
      this.showAuthModal = false;
    },

    async login(username, password) {
      this.loginForm.loading = true;
      this.loginForm.error = '';
      try {
        const u = username || this.loginForm.username;
        const p = password || this.loginForm.password;
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: u, password: p })
        });
        const data = await res.json();
        if (data.status === 'SUCCESS' && data.data) {
          this.currentUser = data.data;
          localStorage.setItem('pqc_user', JSON.stringify(data.data));
          this.showAuthModal = false;
          this.loginForm.username = '';
          this.loginForm.password = '';
        } else {
          this.loginForm.error = data.message || 'Nama pengguna atau kata sandi tidak cocok.';
        }
      } catch (err) {
        this.loginForm.error = 'Gagal menghubungi server: ' + err.message;
      } finally {
        this.loginForm.loading = false;
      }
    },

    async quickLogin(user) {
      const defaultPwd = user.role === 'ASN' ? 'bsre2026' : 'warga2026';
      await this.login(user.username, defaultPwd);
    },

    async register() {
      this.registerForm.loading = true;
      this.registerForm.error = '';
      try {
        const res = await fetch('/api/v1/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.registerForm)
        });
        const data = await res.json();
        if (data.status === 'SUCCESS' && data.data) {
          this.currentUser = data.data;
          localStorage.setItem('pqc_user', JSON.stringify(data.data));
          this.showAuthModal = false;
          alert('Akun berhasil didaftarkan! Kunci ML-DSA-65 unik Anda telah dibangkitkan.');
          await this.fetchUsersList();
        } else {
          this.registerForm.error = data.message || 'Gagal mendaftar.';
        }
      } catch (err) {
        this.registerForm.error = 'Kesalahan sistem: ' + err.message;
      } finally {
        this.registerForm.loading = false;
      }
    },

    logout() {
      this.currentUser = null;
      localStorage.removeItem('pqc_user');
      this.activeTab = 'dashboard';
    },

    async fetchUsersList() {
      try {
        const res = await fetch('/api/v1/auth/users');
        const data = await res.json();
        if (data.status === 'SUCCESS' && data.data) {
          this.availableUsers = data.data;
        }
      } catch (e) {
        console.error('Gagal mengambil daftar akun:', e);
      }
    }
  }
}).mount('#app');
