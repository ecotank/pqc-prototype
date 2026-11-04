// test_functional_flow.js — Uji fungsional alur pengguna baru ARSign:
// verifikasi email OTP, pendaftaran akun, penyetelan passphrase TTE,
// penandatanganan PAdES, lalu verifikasi dokumen.
//
// Alamat server dapat diatur lewat BASE_URL, contoh:
//   BASE_URL=http://localhost:9080 node test_functional_flow.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arsign-fn-'));

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const json = await res.json().catch(function () { return null; });
  return { res: res, json: json };
}

const FALLBACK_PDF = [
  '%PDF-1.7',
  '1 0 obj',
  '<< /Type /Catalog /Pages 2 0 R >>',
  'endobj',
  '2 0 obj',
  '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
  'endobj',
  '3 0 obj',
  '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>',
  'endobj',
  'xref',
  '0 4',
  '0000000000 65535 f ',
  '0000000009 00000 n ',
  '0000000058 00000 n ',
  '0000000115 00000 n ',
  'trailer',
  '<< /Size 4 /Root 1 0 R >>',
  'startxref',
  '187',
  '%%EOF'
].join('\n');

async function main() {
  console.log('================================================================');
  console.log(' UJI FUNGSIONAL: ALUR PENGGUNA BARU & TTE ARSIGN');
  console.log(' Server: ' + BASE_URL);
  console.log('================================================================\n');

  const id = crypto.randomBytes(4).toString('hex');
  const account = {
    username: 'raden.haryo.' + id,
    password: 'KataSandi@' + id,
    passphrase: 'RahasiaKripto@' + id,
    fullname: 'Dr. Raden Haryo Wicaksono, M.Cs.',
    nik_nip: '3271012304850005',
    institution: 'ARSign Trust Network',
    email: 'signer.' + id + '@smallcircle.web.id'
  };

  // [TAHAP 1] Verifikasi alamat surel melalui OTP
  console.log('[TAHAP 1] VERIFIKASI ALAMAT SUREL MELALUI OTP...');
  const send = await postJson(BASE_URL + '/api/v1/auth/otp/send', { email: account.email });
  if (!send.res.ok || !send.json || send.json.status !== 'SUCCESS') {
    throw new Error('Pengiriman OTP gagal: ' + JSON.stringify(send.json));
  }
  console.log('  Permintaan OTP ke ' + account.email + ' -> ' + send.json.message);

  const inspectRes = await fetch(BASE_URL + '/api/v1/auth/otp/test-inspect?email=' + encodeURIComponent(account.email));
  if (inspectRes.status === 404) {
    throw new Error('Endpoint bantu uji OTP tidak tersedia. Jalankan server dengan ARSIGN_ENABLE_TEST_ENDPOINTS=1 dan APP_ENV selain "production".');
  }
  const inspect = await inspectRes.json();
  if (!inspect || inspect.status !== 'SUCCESS' || !inspect.data || !inspect.data.code) {
    throw new Error('Kode OTP tidak dapat dibaca: ' + JSON.stringify(inspect));
  }
  const otpCode = inspect.data.code;
  console.log('  Kode OTP diterbitkan (tidak pernah ditampilkan di antarmuka publik)');

  // Kode salah wajib ditolak dan mengurangi jatah percobaan
  const wrongOtp = await postJson(BASE_URL + '/api/v1/auth/otp/verify', {
    email: account.email,
    code: otpCode === '000000' ? '111111' : '000000'
  });
  if (wrongOtp.res.ok) {
    throw new Error('Kode OTP salah seharusnya ditolak');
  }
  console.log('  Kode OTP salah ditolak (HTTP ' + wrongOtp.res.status + ')');

  const verifyOtp = await postJson(BASE_URL + '/api/v1/auth/otp/verify', {
    email: account.email,
    code: otpCode
  });
  if (!verifyOtp.res.ok || !verifyOtp.json || verifyOtp.json.status !== 'SUCCESS') {
    throw new Error('Verifikasi OTP gagal: ' + JSON.stringify(verifyOtp.json));
  }
  console.log('  Verifikasi OTP LULUS');

  // Kode yang sama tidak boleh dapat dipakai ulang
  const replay = await postJson(BASE_URL + '/api/v1/auth/otp/verify', {
    email: account.email,
    code: otpCode
  });
  if (replay.res.ok) {
    throw new Error('Kode OTP yang sudah terpakai seharusnya tidak dapat dipakai ulang');
  }
  console.log('  Pemakaian ulang kode OTP ditolak (HTTP ' + replay.res.status + ')\n');

  // [TAHAP 2] Pendaftaran akun & penerbitan sertifikat elektronik
  console.log('[TAHAP 2] PENDAFTARAN AKUN & PENERBITAN SERTIFIKAT...');
  const reg = await postJson(BASE_URL + '/api/v1/auth/register', {
    fullname: account.fullname,
    username: account.username,
    password: account.password,
    nik_nip: account.nik_nip,
    institution: account.institution,
    email: account.email,
    role: 'ASN'
  });
  if (!reg.json || reg.json.status !== 'SUCCESS') {
    throw new Error('Pendaftaran akun gagal: ' + JSON.stringify(reg.json));
  }
  if (reg.json.data.mldsa_private_key || reg.json.data.password_hash) {
    throw new Error('KEBOCORAN: respons pendaftaran memuat material rahasia');
  }
  console.log('  Akun ' + reg.json.data.username + ' terdaftar (ID ' + reg.json.data.id + ')');
  console.log('  Ukuran kunci publik: ' + (reg.json.data.mldsa_public_key.length / 2) + ' byte\n');

  // [TAHAP 3] Penyetelan passphrase penandatanganan
  console.log('[TAHAP 3] PENYETELAN PASSPHRASE PENANDATANGANAN...');
  const wrongSet = await postJson(BASE_URL + '/api/v1/auth/passphrase/set', {
    username: account.username,
    password: 'KataSandiSalah123',
    passphrase: account.passphrase
  });
  if (wrongSet.res.status !== 401) {
    throw new Error('Penyetelan passphrase dengan kata sandi salah seharusnya ditolak 401, diperoleh ' + wrongSet.res.status);
  }
  console.log('  Penyetelan tanpa kata sandi akun yang benar ditolak 401');

  const setPass = await postJson(BASE_URL + '/api/v1/auth/passphrase/set', {
    username: account.username,
    password: account.password,
    passphrase: account.passphrase
  });
  if (!setPass.json || setPass.json.status !== 'SUCCESS') {
    throw new Error('Penyetelan passphrase gagal: ' + JSON.stringify(setPass.json));
  }
  console.log('  Passphrase penandatanganan aktif\n');

  // [TAHAP 4] Penandatanganan PAdES ISO 32000-1
  console.log('[TAHAP 4] PENANDATANGANAN PAdES ISO 32000-1...');
  const samplePdf = fs.existsSync('test_input_clean.pdf')
    ? fs.readFileSync('test_input_clean.pdf')
    : Buffer.from(FALLBACK_PDF, 'utf-8');

  const sign = await postJson(BASE_URL + '/api/v1/pades/sign', {
    pdf_base64: samplePdf.toString('base64'),
    receipt_id: 'ARS-REC-' + id,
    username: account.username,
    passphrase: account.passphrase
  });
  if (!sign.json || sign.json.status !== 'SUCCESS') {
    throw new Error('Penandatanganan PAdES gagal: ' + JSON.stringify(sign.json));
  }
  const signData = sign.json.data;
  console.log('  Tanda terima        : ' + signData.receipt_id);
  console.log('  Ukuran tanda tangan : ' + (signData.mldsa_signature_hex.length / 2) + ' byte');
  console.log('  Kontainer PKCS#7    : ' + (signData.pkcs7_signature_hex.length / 2) + ' byte');
  console.log('  Waktu komputasi     : ' + signData.duration_ms + ' ms');

  const signedPdfBuf = Buffer.from(signData.signed_pdf_hex || signData.pdf_base64,
    signData.signed_pdf_hex ? 'hex' : 'base64');
  fs.writeFileSync('test_functional_signed.pdf', signedPdfBuf);
  console.log('  Dokumen tersimpan   : test_functional_signed.pdf (' + signedPdfBuf.length + ' byte)\n');

  // [TAHAP 5] Verifikasi matematis & kriptografis
  console.log('[TAHAP 5] VERIFIKASI MATEMATIS & KRIPTOGRAFIS...');
  const str = signedPdfBuf.toString('latin1');

  const brMatch = str.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!brMatch) throw new Error('/ByteRange tidak ditemukan pada dokumen hasil');
  const o1 = Number(brMatch[1]);
  const l1 = Number(brMatch[2]);
  const o2 = Number(brMatch[3]);
  const l2 = Number(brMatch[4]);
  if (l1 + l2 !== signedPdfBuf.length - (o2 - l1)) {
    throw new Error('ByteRange tidak presisi: total=' + (l1 + l2) + ', diharapkan=' + (signedPdfBuf.length - (o2 - l1)));
  }
  console.log('  ByteRange [' + o1 + ', ' + l1 + ', ' + o2 + ', ' + l2 + '] presisi');

  const combined = Buffer.concat([
    signedPdfBuf.subarray(o1, o1 + l1),
    signedPdfBuf.subarray(o2, o2 + l2)
  ]);
  const docHash = crypto.createHash('sha256').update(combined).digest('hex');
  if (docHash !== signData.document_hash) {
    throw new Error('Digest dokumen tidak cocok. Dihitung: ' + docHash + ', backend: ' + signData.document_hash);
  }
  console.log('  Digest SHA-256 ByteRange cocok dengan backend');

  const contentsMatch = str.match(/\/Contents\s*<([0-9A-Fa-f]+)>/);
  if (!contentsMatch) throw new Error('/Contents tidak ditemukan');
  const p7File = path.join(tmpDir, 'functional.p7s');
  fs.writeFileSync(p7File, Buffer.from(contentsMatch[1].replace(/0+$/, ''), 'hex'));

  const certsText = execSync('openssl pkcs7 -in "' + p7File + '" -inform DER -print_certs -text', { encoding: 'utf-8' });
  const chain = [
    ['Sertifikat penanda tangan (' + account.fullname + ')', certsText.indexOf('Raden Haryo Wicaksono') !== -1],
    ['Rantai ARSign Sub-CA', certsText.indexOf('ARSign Sub-CA Pelayanan TTE Pascakuantum') !== -1],
    ['Rantai ARSign Root CA', certsText.indexOf('ARSign Root CA') !== -1]
  ];
  chain.forEach(function (c) {
    console.log('  ' + c[0] + ': ' + (c[1] ? 'TERVERIFIKASI' : 'GAGAL'));
    if (!c[1]) throw new Error('Verifikasi rantai sertifikat X.509 gagal: ' + c[0]);
  });

  const verify = await postJson(BASE_URL + '/api/v1/pades/verify', {
    pdf_base64: signedPdfBuf.toString('base64')
  });
  if (!verify.json || verify.json.status !== 'SUCCESS' || !verify.json.data.is_valid) {
    throw new Error('Verifikasi dokumen gagal: ' + JSON.stringify(verify.json && verify.json.data));
  }
  console.log('  Identitas pada sertifikat: ' + verify.json.data.signer_fullname);
  if (verify.json.data.signer_fullname !== account.fullname) {
    throw new Error('Identitas sertifikat tidak sesuai registri akun');
  }
  console.log('  Verifikasi API: SAH (' + verify.json.data.valid_signatures + '/' + verify.json.data.total_signatures + ')\n');

  console.log('================================================================');
  console.log(' HASIL AKHIR: SELURUH PENGUJIAN FUNGSIONAL LULUS');
  console.log('================================================================');
}

main()
  .catch(function (err) {
    console.error('\n[FATAL ERROR]', err.message);
    process.exitCode = 1;
  })
  .finally(function () {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
