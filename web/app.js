const { createApp } = Vue;

createApp({
  data() {
    return {
      activeTab: 'sign',
      selectedAlgorithm: 'ML-DSA-65',
      activeKey: null,
      loadingKey: false,

      // Signing form
      inputMode: 'text',
      inputText: 'Surat Keputusan Elektronik Balai Besar Sertifikasi Elektronik Nomor: 042/BSRE/PQC/2026',
      calculatedDigest: '',
      uploadedFileName: '',
      uploadedFileSize: 0,
      isSigning: false,
      lastSignResult: null,

      // Verification form
      verifyForm: {
        algorithm: 'ML-DSA-65',
        message: '',
        publicKeyHex: '',
        signatureHex: ''
      },
      isVerifying: false,
      verifyResult: null,

      // Benchmark
      benchIterations: 50,
      isRunningBench: false,
      benchReport: null,
      defaultBenchItems: [
        { algorithm: 'ML-DSA-44', family: 'Post-Quantum', standard: 'FIPS 204', public_key_bytes: 1312, private_key_bytes: 2560, signature_bytes: 2420, sign_mean_ms: 0.18, sign_p95_ms: 0.25, verify_mean_ms: 0.08 },
        { algorithm: 'ML-DSA-65', family: 'Post-Quantum', standard: 'FIPS 204', public_key_bytes: 1952, private_key_bytes: 4032, signature_bytes: 3309, sign_mean_ms: 0.32, sign_p95_ms: 0.45, verify_mean_ms: 0.14 },
        { algorithm: 'ML-DSA-87', family: 'Post-Quantum', standard: 'FIPS 204', public_key_bytes: 2592, private_key_bytes: 4896, signature_bytes: 4627, sign_mean_ms: 0.51, sign_p95_ms: 0.68, verify_mean_ms: 0.22 },
        { algorithm: 'RSA-2048', family: 'Classical', standard: 'PKCS #1 v1.5', public_key_bytes: 270, private_key_bytes: 1190, signature_bytes: 256, sign_mean_ms: 1.85, sign_p95_ms: 2.30, verify_mean_ms: 0.09 },
        { algorithm: 'RSA-3072', family: 'Classical', standard: 'PKCS #1 v1.5', public_key_bytes: 398, private_key_bytes: 1750, signature_bytes: 384, sign_mean_ms: 4.95, sign_p95_ms: 5.80, verify_mean_ms: 0.16 },
      ],

      // FIPS 204
      isRunningFips: false,
      fipsReport: null,

      // Audit Logs
      auditLogs: [],

      // Charts
      speedChart: null,
      sizeChart: null,
    };
  },

  mounted() {
    this.updateDigest();
    this.generateNewKey();
    this.runFIPSValidation();
    this.fetchAuditLogs();
    
    // Auto init default charts after DOM ready
    setTimeout(() => {
      this.initCharts(this.defaultBenchItems);
    }, 400);
  },

  methods: {
    tabClass(tab) {
      if (this.activeTab === tab) {
        return 'px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-600 text-white shadow-sm';
      }
      return 'px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-800 transition';
    },

    async updateDigest() {
      if (this.inputMode === 'text') {
        const encoder = new TextEncoder();
        const data = encoder.encode(this.inputText);
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        this.calculatedDigest = Array.from(new Uint8Array(hashBuf))
          .map(b => b.toString(16).padStart(2, '0')).join('');
      }
    },

    async handleFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      this.uploadedFileName = file.name;
      this.uploadedFileSize = file.size;

      const arrayBuffer = await file.arrayBuffer();
      const hashBuf = await crypto.subtle.digest('SHA-256', arrayBuffer);
      this.calculatedDigest = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async onAlgorithmChange() {
      await this.generateNewKey();
    },

    async generateNewKey() {
      this.loadingKey = true;
      try {
        let algParam = this.selectedAlgorithm;
        if (algParam === 'DUAL') algParam = 'ML-DSA-65';

        const res = await fetch(`/api/v1/keys/generate?algorithm=${encodeURIComponent(algParam)}`, {
          method: 'POST'
        });
        const data = await res.json();
        if (data.status === 'SUCCESS') {
          this.activeKey = data.data;
        } else {
          alert('Gagal membangkitkan kunci: ' + data.message);
        }
      } catch (err) {
        console.error(err);
      } finally {
        this.loadingKey = false;
      }
    },

    async performSign() {
      if (!this.activeKey) {
        alert('Kunci belum dibangkitkan.');
        return;
      }
      this.isSigning = true;
      try {
        let endpoint = '/api/v1/sign';
        let payload = {
          signer_id: 'rplk2-bsre-signer',
          algorithm: this.selectedAlgorithm,
          digest: this.calculatedDigest,
          private_key: this.activeKey.private_key_hex,
          data: this.inputMode === 'text' ? this.inputText : '',
          format: 'hex'
        };

        if (this.selectedAlgorithm === 'DUAL') {
          endpoint = '/api/v1/dual-sign';
          payload.mldsa_algorithm = 'ML-DSA-65';
          payload.mldsa_private_key = this.activeKey.private_key_hex;
        }

        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.status === 'SUCCESS') {
          if (this.selectedAlgorithm === 'DUAL') {
            this.lastSignResult = {
              algorithm: data.data.mode,
              signature_hex: data.data.mldsa.signature_hex,
              signature_bytes: data.data.total_size_bytes,
              sign_duration_ms: data.data.total_duration_ms,
              target_compliant: data.data.target_compliant,
              dual_details: data.data
            };
          } else {
            this.lastSignResult = data.data;
          }
          this.fetchAuditLogs();
        } else {
          alert('Gagal menandatangani: ' + data.message);
        }
      } catch (err) {
        console.error(err);
        alert('Terjadi kesalahan saat memanggil API: ' + err.message);
      } finally {
        this.isSigning = false;
      }
    },

    sendToVerifyTab() {
      if (!this.lastSignResult || !this.activeKey) return;
      this.verifyForm.algorithm = this.selectedAlgorithm === 'DUAL' ? 'ML-DSA-65' : this.selectedAlgorithm;
      this.verifyForm.message = this.calculatedDigest;
      this.verifyForm.publicKeyHex = this.activeKey.public_key_hex;
      this.verifyForm.signatureHex = this.lastSignResult.signature_hex;
      this.activeTab = 'verify';
      this.verifyResult = null;
    },

    async performVerify() {
      this.isVerifying = true;
      try {
        const payload = {
          algorithm: this.verifyForm.algorithm,
          digest: this.verifyForm.message,
          public_key: this.verifyForm.publicKeyHex,
          signature: this.verifyForm.signatureHex
        };

        const res = await fetch('/api/v1/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.status === 'SUCCESS') {
          this.verifyResult = data.data;
          this.fetchAuditLogs();
        } else {
          this.verifyResult = {
            valid: false,
            reason: data.message || 'Verifikasi gagal diproses',
            verify_duration_ms: 0
          };
        }
      } catch (err) {
        console.error(err);
        this.verifyResult = {
          valid: false,
          reason: 'Kesalahan jaringan: ' + err.message,
          verify_duration_ms: 0
        };
      } finally {
        this.isVerifying = false;
      }
    },

    tamperMessage() {
      if (!this.verifyForm.message) return;
      // change first char
      const first = this.verifyForm.message[0];
      const repl = first === 'a' ? 'b' : (first === '0' ? '1' : 'a');
      this.verifyForm.message = repl + this.verifyForm.message.slice(1);
      alert('Peringatan: 1 karakter pesan diubah untuk simulasi pembajakan data.');
    },

    tamperSignature() {
      if (!this.verifyForm.signatureHex) return;
      const last = this.verifyForm.signatureHex.slice(-1);
      const repl = last === '0' ? '1' : (last === 'f' ? 'e' : '0');
      this.verifyForm.signatureHex = this.verifyForm.signatureHex.slice(0, -1) + repl;
      alert('Peringatan: 1 bit pada tanda tangan digital diubah untuk simulasi manipulasi tanda tangan.');
    },

    async loadDemoValid() {
      if (!this.activeKey) await this.generateNewKey();
      await this.performSign();
      this.sendToVerifyTab();
      await this.performVerify();
    },

    async loadDemoTampered() {
      await this.loadDemoValid();
      this.tamperMessage();
      await this.performVerify();
    },

    async runBenchmark() {
      this.isRunningBench = true;
      try {
        const res = await fetch('/api/v1/benchmarks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ iterations: this.benchIterations })
        });
        const data = await res.json();
        if (data.status === 'SUCCESS') {
          this.benchReport = data.data;
          this.updateCharts(data.data.items);
          this.fetchAuditLogs();
        } else {
          alert('Benchmark gagal: ' + data.message);
        }
      } catch (err) {
        console.error(err);
      } finally {
        this.isRunningBench = false;
      }
    },

    exportCSV() {
      window.open('/api/v1/benchmarks/export', '_blank');
    },

    async runFIPSValidation() {
      this.isRunningFips = true;
      try {
        const res = await fetch('/api/v1/fips204-compliance');
        const data = await res.json();
        if (data.status === 'SUCCESS') {
          this.fipsReport = data.data;
        }
      } catch (err) {
        console.error(err);
      } finally {
        this.isRunningFips = false;
      }
    },

    async fetchAuditLogs() {
      try {
        const res = await fetch('/api/v1/audit');
        const data = await res.json();
        if (data.status === 'SUCCESS') {
          this.auditLogs = data.data;
        }
      } catch (err) {
        console.error(err);
      }
    },

    copyToClipboard(text) {
      if (!text) return;
      navigator.clipboard.writeText(text);
      alert('Berhasil disalin ke clipboard!');
    },

    initCharts(items) {
      const labels = items.map(i => i.algorithm);

      // Speed Chart
      const ctxSpeed = document.getElementById('speedChart');
      if (ctxSpeed) {
        this.speedChart = new Chart(ctxSpeed, {
          type: 'bar',
          data: {
            labels: labels,
            datasets: [
              {
                label: 'Signing Time (ms)',
                data: items.map(i => i.sign_mean_ms),
                backgroundColor: 'rgba(59, 130, 246, 0.8)',
              },
              {
                label: 'Verify Time (ms)',
                data: items.map(i => i.verify_mean_ms),
                backgroundColor: 'rgba(16, 185, 129, 0.8)',
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                beginAtZero: true,
                title: { display: true, text: 'Waktu (Milidetik)', color: '#94a3b8' },
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
                ticks: { color: '#94a3b8' }
              },
              x: {
                grid: { display: false },
                ticks: { color: '#94a3b8' }
              }
            },
            plugins: {
              legend: { labels: { color: '#cbd5e1' } }
            }
          }
        });
      }

      // Size Chart
      const ctxSize = document.getElementById('sizeChart');
      if (ctxSize) {
        this.sizeChart = new Chart(ctxSize, {
          type: 'bar',
          data: {
            labels: labels,
            datasets: [
              {
                label: 'Public Key (Bytes)',
                data: items.map(i => i.public_key_bytes),
                backgroundColor: 'rgba(99, 102, 241, 0.8)',
              },
              {
                label: 'Signature (Bytes)',
                data: items.map(i => i.signature_bytes),
                backgroundColor: 'rgba(245, 158, 11, 0.8)',
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                beginAtZero: true,
                title: { display: true, text: 'Ukuran (Bytes)', color: '#94a3b8' },
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
                ticks: { color: '#94a3b8' }
              },
              x: {
                grid: { display: false },
                ticks: { color: '#94a3b8' }
              }
            },
            plugins: {
              legend: { labels: { color: '#cbd5e1' } }
            }
          }
        });
      }
    },

    updateCharts(items) {
      if (!this.speedChart || !this.sizeChart) {
        this.initCharts(items);
        return;
      }
      const labels = items.map(i => i.algorithm);

      this.speedChart.data.labels = labels;
      this.speedChart.data.datasets[0].data = items.map(i => i.sign_mean_ms);
      this.speedChart.data.datasets[1].data = items.map(i => i.verify_mean_ms);
      this.speedChart.update();

      this.sizeChart.data.labels = labels;
      this.sizeChart.data.datasets[0].data = items.map(i => i.public_key_bytes);
      this.sizeChart.data.datasets[1].data = items.map(i => i.signature_bytes);
      this.sizeChart.update();
    }
  }
}).mount('#app');
