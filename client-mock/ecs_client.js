const crypto = require('crypto');

const API_BASE = process.env.API_BASE || 'http://localhost:8080/api/v1';

async function main() {
  console.log('================================================================');
  console.log(' SIMULASI ESIGN CLIENT SERVICE (ECS) BSrE - POLA PRE-HASH PQC');
  console.log(' Menghubungi Layanan Penandatanganan ML-DSA (FIPS 204)');
  console.log('================================================================\n');

  try {
    // 1. Dokumen uji lokal instansi
    const docPayload = 'SURAT KEPUTUSAN BERSAMA PENERAPAN POST-QUANTUM CRYPTOGRAPHY DI LINGKUNGAN INSTANSI PEMERINTAH TAHUN 2026';
    console.log(`[1] Dokumen lokal instansi : "${docPayload.substring(0, 50)}..."`);

    // 2. ECS menghitung digest lokal (SHA-256) agar dokumen tidak keluar jaringan
    const hash = crypto.createHash('sha256').update(docPayload).digest('hex');
    console.log(`[2] SHA-256 Digest Lokal  : ${hash}`);

    // 3. Bangkitkan / Ambil Kunci Penanda Tangan dari API
    console.log('\n[3] Meminta kunci penanda tangan (ML-DSA-65)...');
    const keyRes = await fetch(`${API_BASE}/keys/generate?algorithm=ML-DSA-65`, { method: 'POST' });
    const keyJson = await keyRes.json();
    if (keyJson.status !== 'SUCCESS') {
      throw new Error('Gagal generate key: ' + keyJson.message);
    }
    const keyPair = keyJson.data;
    console.log(`    Kunci Publik ML-DSA-65 : ${keyPair.public_key_bytes} Bytes (FIPS 204 Level 3)`);

    // 4. Kirim hash ke API Penandatanganan
    console.log('\n[4] Mengirim HASH ke API Penandatanganan (Pola API Esign)...');
    const startT = performance.now();
    const signRes = await fetch(`${API_BASE}/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        signer_id: 'instansi-klien-001',
        algorithm: 'ML-DSA-65',
        digest: hash,
        private_key: keyPair.private_key_hex,
        format: 'hex'
      })
    });
    const signJson = await signRes.json();
    const networkLatency = (performance.now() - startT).toFixed(2);

    if (signJson.status !== 'SUCCESS') {
      throw new Error('Penandatanganan gagal: ' + signJson.message);
    }

    const signResult = signJson.data;
    console.log(`    Status               : BERHASIL`);
    console.log(`    Ukuran Signature     : ${signResult.signature_bytes} Bytes (FIPS 204 spesifikasi = 3309 B)`);
    console.log(`    Waktu Komputasi Sign : ${signResult.sign_duration_ms} ms`);
    console.log(`    Waktu Total Roundtrip: ${networkLatency} ms`);
    console.log(`    Target =< 2.0 Detik  : ${signResult.target_compliant ? 'MEMENUHI (LULUS)' : 'GAGAL'}`);

    // 5. Verifikasi Keabsahan Tanda Tangan
    console.log('\n[5] Memverifikasi Tanda Tangan terhadap Digest Dokumen Asli...');
    const verifyRes = await fetch(`${API_BASE}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        algorithm: 'ML-DSA-65',
        digest: hash,
        public_key: keyPair.public_key_hex,
        signature: signResult.signature_hex
      })
    });
    const verifyJson = await verifyRes.json();
    console.log(`    Hasil Verifikasi     : ${verifyJson.data.valid ? 'VALID (SAH)' : 'TIDAK VALID'}`);
    console.log(`    Keterangan           : ${verifyJson.data.reason}`);

    // 6. Uji Integritas (Tampering Test)
    console.log('\n[6] Uji Ketahanan Integritas (Simulasi modifikasi 1 bit)...');
    const tamperedHash = hash.slice(0, -1) + (hash.slice(-1) === '0' ? '1' : '0');
    const tamperRes = await fetch(`${API_BASE}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        algorithm: 'ML-DSA-65',
        digest: tamperedHash,
        public_key: keyPair.public_key_hex,
        signature: signResult.signature_hex
      })
    });
    const tamperJson = await tamperRes.json();
    console.log(`    Hasil Tampering Test : ${!tamperJson.data.valid ? 'BERHASIL DITOLAK (AMAN)' : 'LOLOS (RENTAN)'}`);
    console.log(`    Pesan Penolakan      : ${tamperJson.data.reason}`);

    console.log('\n================================================================');
    console.log(' SIMULASI KLIEN SELESAI DENGAN SUKSES 100%');
    console.log('================================================================');
  } catch (err) {
    console.error('Galat klien ECS:', err.message);
  }
}

main();
