const { createApp } = Vue;

createApp({
  data() {
    return {
      activeTab: 'pipeline',
      selectedAlg: 'ML-DSA-65',
      testPayload: 'Uji Komputasi Internal Transformasi Matriks Lattice ML-DSA - BSrE BSSN',
      isTracing: false,
      traceResult: null,
      activeKey: null,
      activeSigHex: '',

      // Verify trace
      isVerifyingTrace: false,
      verifyTraceResult: null,

      // Placeholder steps for initial load
      placeholderSteps: [
        { step_number: 1, name: 'Pre-Hash & Integrasi ECS', phase: 'Input Processing', formula: 'μ = H(M) = SHA-256(Payload)', description: 'Pesan di-hash secara deterministik dengan SHA-256.', status: 'COMPLETED', duration_microsec: 12.5, snapshots: { digest_sha256: 'Menghitung...', fips_variant: 'HashML-DSA' } },
        { step_number: 2, name: 'Ekspansi Matriks Lattice A', phase: 'Lattice Expansion', formula: 'A ∈ R_q^{k × l} ← ExpandA(ρ)', description: 'Matriks A berukuran k×l dalam modulo q=8380417 dibangkitkan dari seed ρ.', status: 'COMPLETED', duration_microsec: 45.2, snapshots: { matrix_dimension: 'k=6, l=5', ring_degree_n: '256' } },
        { step_number: 3, name: 'Pembangkitan Vektor Masking y', phase: 'Masking & Sampling', formula: 'y ∈ R_q^l ← ExpandMASK(K, rnd), w = A · y', description: 'Vektor acak y dibangkitkan dalam rentang [-γ₁, γ₁].', status: 'COMPLETED', duration_microsec: 68.1, snapshots: { gamma_1_bound: '2^19', sampling_type: 'Uniform' } },
        { step_number: 4, name: 'Perhitungan Challenge c', phase: 'Fiat-Shamir Transform', formula: 'c = H(μ, w₁) ∈ R_q', description: 'Transformasi Fiat-Shamir menghasilkan tantangan berbobot Hamming rendah.', status: 'COMPLETED', duration_microsec: 25.4, snapshots: { non_zero_coeffs: 'τ = 49', hash_func: 'SHAKE-256' } },
        { step_number: 5, name: 'Kalkulasi Respons z & Rejection Check', phase: 'Response & Rejection Check', formula: 'z = y + c · s₁, uji ||z||_∞ < γ₁ - β', description: 'Uji norma infinity untuk mencegah kebocoran informasi kunci privat.', status: 'COMPLETED', duration_microsec: 85.0, snapshots: { max_allowed_z: '524.092', bound_status: 'LULUS' } },
        { step_number: 6, name: 'Serialisasi Tanda Tangan FIPS 204', phase: 'Encoding & Output', formula: 'σ = Encode(c̃, z, h) → 3.309 Bytes', description: 'Pengemasan tantangan c̃, vektor z, dan hint h ke dalam format baku.', status: 'COMPLETED', duration_microsec: 18.2, snapshots: { total_bytes: '3309 Bytes', fips_compliance: '100% Memenuhi' } },
      ],

      // Benchmark data
      speedChart: null,
      sizeChart: null
    };
  },

  async mounted() {
    await this.initKey();
    await this.runSigningTrace();
    await this.runVerifyTrace(false);

    setTimeout(() => {
      this.initBenchCharts();
    }, 400);
  },

  methods: {
    tabClass(tab) {
      if (this.activeTab === tab) {
        return 'px-3 py-1.5 rounded-lg text-xs font-bold bg-purple-600 text-white shadow-sm';
      }
      return 'px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-900 transition';
    },

    async onAlgChange() {
      await this.initKey();
      await this.runSigningTrace();
    },

    async initKey() {
      try {
        const res = await fetch(`/api/v1/keys/generate?algorithm=${encodeURIComponent(this.selectedAlg)}`, { method: 'POST' });
        const json = await res.json();
        if (json.status === 'SUCCESS') {
          this.activeKey = json.data;
        }
      } catch (err) {
        console.error('Inisialisasi kunci lab gagal:', err);
      }
    },

    async runSigningTrace() {
      if (!this.activeKey) await this.initKey();
      this.isTracing = true;

      try {
        const payload = {
          algorithm: this.selectedAlg,
          private_key: this.activeKey.private_key_hex,
          data: this.testPayload
        };

        const res = await fetch('/api/v1/process/trace-sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.status === 'SUCCESS') {
          this.traceResult = data.data;
          this.activeSigHex = data.data.signature_hex;
        } else {
          alert('Tracing gagal: ' + data.message);
        }
      } catch (err) {
        console.error(err);
      } finally {
        this.isTracing = false;
      }
    },

    async runVerifyTrace(tampered) {
      if (!this.activeKey || !this.activeSigHex) {
        await this.runSigningTrace();
      }
      this.isVerifyingTrace = true;

      try {
        let msgToVerify = this.testPayload;
        if (tampered) {
          msgToVerify = msgToVerify + ' [TAMPERED]';
        }

        const payload = {
          algorithm: this.selectedAlg,
          public_key: this.activeKey.public_key_hex,
          signature: this.activeSigHex,
          data: msgToVerify
        };

        const res = await fetch('/api/v1/process/trace-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (data.status === 'SUCCESS') {
          this.verifyTraceResult = data.data;
        }
      } catch (err) {
        console.error(err);
      } finally {
        this.isVerifyingTrace = false;
      }
    },

    initBenchCharts() {
      const labels = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'RSA-2048', 'RSA-3072'];

      // Speed Chart
      const ctxSpeed = document.getElementById('procSpeedChart');
      if (ctxSpeed) {
        this.speedChart = new Chart(ctxSpeed, {
          type: 'bar',
          data: {
            labels: labels,
            datasets: [
              { label: 'Signing Time (ms)', data: [0.155, 0.161, 0.052, 0.933, 2.997], backgroundColor: 'rgba(139, 92, 246, 0.8)' },
              { label: 'Verify Time (ms)', data: [0.026, 0.010, 0.026, 0.021, 0.134], backgroundColor: 'rgba(16, 185, 129, 0.8)' }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } },
              x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
            },
            plugins: { legend: { labels: { color: '#cbd5e1' } } }
          }
        });
      }

      // Size Chart
      const ctxSize = document.getElementById('procSizeChart');
      if (ctxSize) {
        this.sizeChart = new Chart(ctxSize, {
          type: 'bar',
          data: {
            labels: labels,
            datasets: [
              { label: 'Public Key (Bytes)', data: [1312, 1952, 2592, 294, 422], backgroundColor: 'rgba(59, 130, 246, 0.8)' },
              { label: 'Signature (Bytes)', data: [2420, 3309, 4627, 256, 384], backgroundColor: 'rgba(245, 158, 11, 0.8)' }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } },
              x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
            },
            plugins: { legend: { labels: { color: '#cbd5e1' } } }
          }
        });
      }
    }
  }
}).mount('#app');
