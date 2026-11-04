// test_e2e_pades.js — Uji menyeluruh TTE PAdES ISO 32000-1 ARSign.
//
// Alamat server dapat diatur lewat BASE_URL, contoh:
//   BASE_URL=http://localhost:9080 node test_e2e_pades.js
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arsign-e2e-'));
const DEVNULL = process.platform === 'win32' ? 'NUL' : '/dev/null';

function suffix() {
  return crypto.randomBytes(4).toString('hex');
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const json = await res.json().catch(() => null);
  return { res, json };
}

// provisionSigner mendaftarkan akun penanda tangan lengkap dengan passphrase TTE.
async function provisionSigner(fullname, nik) {
  const id = suffix();
  const account = {
    username: 'uji.' + id,
    password: 'KataSandiUji#' + id,
    passphrase: 'PassphraseUji#' + id,
    fullname: fullname,
    nik_nip: nik,
    institution: 'ARSign Trust Network',
    email: 'uji.' + id + '@smallcircle.web.id'
  };

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
    throw new Error('Registrasi akun gagal: ' + JSON.stringify(reg.json));
  }
  if (reg.json.data && reg.json.data.mldsa_private_key) {
    throw new Error('KEBOCORAN: respons registrasi masih memuat kunci privat');
  }

  const pass = await postJson(BASE_URL + '/api/v1/auth/passphrase/set', {
    username: account.username,
    password: account.password,
    passphrase: account.passphrase
  });
  if (!pass.json || pass.json.status !== 'SUCCESS') {
    throw new Error('Penyetelan passphrase gagal: ' + JSON.stringify(pass.json));
  }

  return account;
}

async function signPdf(account, pdfBuffer, receiptId) {
  const { json } = await postJson(BASE_URL + '/api/v1/pades/sign', {
    pdf_base64: pdfBuffer.toString('base64'),
    receipt_id: receiptId,
    username: account.username,
    passphrase: account.passphrase
  });
  if (!json || json.status !== 'SUCCESS' || !json.data) {
    throw new Error('Penandatanganan PAdES gagal: ' + JSON.stringify(json));
  }
  const encoded = json.data.signed_pdf_hex || json.data.pdf_base64;
  return {
    data: json.data,
    buffer: Buffer.from(encoded, json.data.signed_pdf_hex ? 'hex' : 'base64')
  };
}

async function verifyPdf(buffer) {
  const { json } = await postJson(BASE_URL + '/api/v1/pades/verify', {
    pdf_base64: buffer.toString('base64')
  });
  return json;
}

const CLEAN_PDF = [
  '%PDF-1.4',
  '1 0 obj',
  '<< /Type /Catalog /Pages 2 0 R >>',
  'endobj',
  '2 0 obj',
  '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
  'endobj',
  '3 0 obj',
  '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>',
  'endobj',
  '4 0 obj',
  '<< /Length 55 >>',
  'stream',
  'BT',
  '/F1 12 Tf',
  '72 712 Td',
  '(Dokumen Resmi Uji PQC ARSign) Tj',
  'ET',
  'endstream',
  'endobj',
  'xref',
  '0 5',
  '0000000000 65535 f ',
  '0000000009 00000 n ',
  '0000000058 00000 n ',
  '0000000115 00000 n ',
  '0000000204 00000 n ',
  'trailer',
  '<< /Size 5 /Root 1 0 R >>',
  'startxref',
  '310',
  '%%EOF'
].join('\n');

async function runTests() {
  console.log('====================================================');
  console.log(' UJI MENYELURUH TTE PAdES ARSIGN');
  console.log(' Server: ' + BASE_URL);
  console.log('====================================================');

  // [1] Dokumen PDF bersih
  const cleanBuf = Buffer.from(CLEAN_PDF, 'utf-8');
  fs.writeFileSync('test_input_clean.pdf', cleanBuf);
  console.log('[UJI 1] PDF masukan dibuat (' + cleanBuf.length + ' byte)');

  // [2] Penyediaan akun & penandatanganan terautentikasi
  console.log('[UJI 2] Menyiapkan akun penanda tangan dan menandatangani dokumen...');
  const signer1 = await provisionSigner('Penandatangan Dokumen Satu, S.Kom.', '199910262024011001');
  const signed1 = await signPdf(signer1, cleanBuf, 'ARS-TEST-SIGN1-' + suffix());
  fs.writeFileSync('test_output_signed1.pdf', signed1.buffer);
  console.log('  OK tanda terima ' + signed1.data.receipt_id + ', durasi ' + signed1.data.duration_ms + ' ms, ukuran ' + signed1.buffer.length + ' byte');

  // [3] Penandatanganan tanpa kredensial WAJIB ditolak
  console.log('[UJI 3] Menolak penandatanganan tanpa kredensial...');
  const anon = await postJson(BASE_URL + '/api/v1/pades/sign', {
    pdf_base64: cleanBuf.toString('base64'),
    signer_fullname: 'Menteri Keuangan Republik Indonesia',
    signer_nik: '1234567890123456'
  });
  if (anon.res.status !== 401) {
    throw new Error('Penandatanganan anonim seharusnya ditolak 401, diperoleh ' + anon.res.status);
  }
  const wrongPass = await postJson(BASE_URL + '/api/v1/pades/sign', {
    pdf_base64: cleanBuf.toString('base64'),
    username: signer1.username,
    passphrase: 'PassphraseSalah123'
  });
  if (wrongPass.res.status !== 401) {
    throw new Error('Passphrase salah seharusnya ditolak 401, diperoleh ' + wrongPass.res.status);
  }
  console.log('  OK permintaan anonim dan passphrase salah ditolak 401');

  // [4] Matematika ByteRange & digest dokumen
  console.log('[UJI 4] Memeriksa ByteRange dan digest dokumen...');
  const str1 = signed1.buffer.toString('latin1');
  const brMatch1 = str1.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!brMatch1) throw new Error('/ByteRange tidak ditemukan pada PDF hasil');

  const o1 = Number(brMatch1[1]);
  const l1 = Number(brMatch1[2]);
  const o2 = Number(brMatch1[3]);
  const l2 = Number(brMatch1[4]);
  console.log('  ByteRange: [' + o1 + ', ' + l1 + ', ' + o2 + ', ' + l2 + ']');
  if (l1 + l2 !== signed1.buffer.length - (o2 - l1)) {
    throw new Error('ByteRange tidak presisi: l1+l2=' + (l1 + l2) + ', diharapkan=' + (signed1.buffer.length - (o2 - l1)));
  }

  const combined = Buffer.concat([
    signed1.buffer.subarray(o1, o1 + l1),
    signed1.buffer.subarray(o2, o2 + l2)
  ]);
  const docHash1 = crypto.createHash('sha256').update(combined).digest('hex');
  if (docHash1 !== signed1.data.document_hash) {
    throw new Error('Digest dokumen tidak cocok dengan hasil backend');
  }
  console.log('  OK ByteRange presisi dan digest cocok dengan backend');

  // [5] Struktur incremental update ISO 32000-1
  console.log('[UJI 5] Memeriksa struktur incremental update...');
  ['/Prev ', '/Root 1 0 R', '/AcroForm', '/SigFlags 3'].forEach(function (token) {
    if (str1.indexOf(token) === -1) throw new Error('Struktur revisi tidak memuat ' + token);
  });
  console.log('  OK trailer memuat /Prev dan /Root, katalog memuat /AcroForm');

  // [6] Rantai sertifikat & verifikasi kriptografis OpenSSL
  console.log('[UJI 6] Memeriksa kontainer PKCS#7 dengan OpenSSL...');
  const contentsMatch1 = str1.match(/\/Contents\s*<([0-9A-Fa-f]+)>/);
  if (!contentsMatch1) throw new Error('/Contents tidak ditemukan');

  const slotHex = contentsMatch1[1];
  const p7File = path.join(tmpDir, 'sig1.p7s');
  fs.writeFileSync(p7File, Buffer.from(slotHex.replace(/0+$/, ''), 'hex'));

  const chainRes = await fetch(BASE_URL + '/api/v1/ca/certificates?format=pem');
  const caFile = path.join(tmpDir, 'arsign_chain.pem');
  fs.writeFileSync(caFile, await chainRes.text());

  const certsText = execSync('openssl pkcs7 -in "' + p7File + '" -inform DER -print_certs -text', { encoding: 'utf-8' });
  const checks = [
    ['Sertifikat penanda tangan', certsText.indexOf(signer1.fullname) !== -1],
    ['Sertifikat Sub-CA', certsText.indexOf('ARSign Sub-CA Pelayanan TTE Pascakuantum') !== -1],
    ['Sertifikat Root CA', certsText.indexOf('ARSign Root CA') !== -1]
  ];
  checks.forEach(function (c) {
    console.log('  ' + c[0] + ': ' + (c[1] ? 'ADA' : 'TIDAK ADA'));
    if (!c[1]) throw new Error('Rantai sertifikat tidak lengkap: ' + c[0]);
  });

  const contentFile = path.join(tmpDir, 'digest_bytes.bin');
  fs.writeFileSync(contentFile, combined);
  execSync('openssl smime -verify -in "' + p7File + '" -inform DER -content "' + contentFile + '" -CAfile "' + caFile + '" -out ' + DEVNULL,
    { encoding: 'utf-8', stdio: ['ignore', 'ignore', 'pipe'] });
  console.log('  OK OpenSSL menyatakan tanda tangan PKCS#7 SAH terhadap rantai ARSign');

  // [7] Verifikasi lewat API
  console.log('[UJI 7] Verifikasi dokumen melalui API...');
  const verify1 = await verifyPdf(signed1.buffer);
  if (!verify1 || verify1.status !== 'SUCCESS' || !verify1.data.is_valid) {
    throw new Error('Dokumen asli seharusnya SAH: ' + JSON.stringify(verify1 && verify1.data));
  }
  if (!verify1.data.is_signature_valid || !verify1.data.is_pqc_verified || !verify1.data.is_chain_valid) {
    throw new Error('Rincian verifikasi tidak lengkap: ' + JSON.stringify(verify1.data));
  }
  console.log('  OK dokumen SAH (' + verify1.data.valid_signatures + '/' + verify1.data.total_signatures + ' tanda tangan lulus)');

  // [8] Dokumen dengan tanda tangan rusak WAJIB ditolak
  console.log('[UJI 8] Menolak dokumen dengan tanda tangan rusak...');
  const forged = Buffer.from(signed1.buffer);
  const hexStart = str1.indexOf('/Contents <') + '/Contents <'.length;
  const der = Buffer.from(slotHex.replace(/0+$/, ''), 'hex');

  const markerIdx = der.indexOf(Buffer.from('ML-DSA-65|RECEIPT:', 'latin1'));
  if (markerIdx === -1) throw new Error('Penanda lapisan pascakuantum tidak ditemukan');
  Buffer.from('XX-XXX-XX|XXXXXXX:', 'latin1').copy(der, markerIdx);
  for (let i = der.length - 8; i < der.length; i++) der[i] ^= 0xff;

  let forgedHex = der.toString('hex').toUpperCase();
  forgedHex += '0'.repeat(slotHex.length - forgedHex.length);
  forged.write(forgedHex, hexStart, 'latin1');

  const verifyForged = await verifyPdf(forged);
  if (verifyForged && verifyForged.data && verifyForged.data.is_valid) {
    throw new Error('BYPASS: dokumen bertanda tangan rusak dinyatakan SAH');
  }
  console.log('  OK dokumen bertanda tangan rusak DITOLAK');

  // [9] Dokumen yang isinya diubah WAJIB ditolak
  console.log('[UJI 9] Menolak dokumen yang isinya diubah...');
  const tampered = Buffer.from(signed1.buffer);
  const bodyIdx = str1.indexOf('Dokumen Resmi Uji PQC ARSign');
  if (bodyIdx === -1) throw new Error('Isi dokumen uji tidak ditemukan');
  tampered.write('Dokumen Resmi Uji PQC ARSigX', bodyIdx, 'latin1');
  const verifyTampered = await verifyPdf(tampered);
  if (verifyTampered && verifyTampered.data && verifyTampered.data.is_valid) {
    throw new Error('Dokumen yang diubah dinyatakan SAH');
  }
  console.log('  OK dokumen yang dimodifikasi DITOLAK');

  // [10] Multi-signature
  console.log('[UJI 10] Penandatanganan berlapis oleh penanda tangan kedua...');
  const signer2 = await provisionSigner('Penandatangan Dokumen Dua, S.Kom.', '198501012010011002');
  const signed2 = await signPdf(signer2, signed1.buffer, 'ARS-TEST-SIGN2-' + suffix());
  fs.writeFileSync('test_output_signed2_multi.pdf', signed2.buffer);

  const allByteRanges = signed2.buffer.toString('latin1').match(/\/ByteRange\s*\[[^\]]+\]/g) || [];
  if (allByteRanges.length < 2) {
    throw new Error('Diharapkan 2 ByteRange pada dokumen berlapis, diperoleh ' + allByteRanges.length);
  }

  const verify2 = await verifyPdf(signed2.buffer);
  if (!verify2.data.is_valid || verify2.data.total_signatures !== 2 || verify2.data.valid_signatures !== 2) {
    throw new Error('Dokumen berlapis seharusnya SAH pada kedua tanda tangan: ' + JSON.stringify(verify2.data));
  }
  console.log('  OK ' + verify2.data.valid_signatures + '/' + verify2.data.total_signatures + ' tanda tangan lulus verifikasi');

  // [11] Daftar pengguna wajib terlindungi
  console.log('[UJI 11] Memeriksa proteksi endpoint data pengguna...');
  const usersRes = await fetch(BASE_URL + '/api/v1/auth/users');
  if (usersRes.status === 200) {
    throw new Error('Endpoint daftar pengguna masih terbuka tanpa kredensial administrator');
  }
  console.log('  OK /api/v1/auth/users menolak akses tanpa kredensial (HTTP ' + usersRes.status + ')');

  // [12] Kunci privat tidak boleh bocor saat login
  console.log('[UJI 12] Memeriksa kebocoran kunci privat pada respons login...');
  const login = await postJson(BASE_URL + '/api/v1/auth/login', {
    username: signer1.username,
    password: signer1.password
  });
  if (!login.json || login.json.status !== 'SUCCESS') {
    throw new Error('Login gagal: ' + JSON.stringify(login.json));
  }
  ['mldsa_private_key', 'password_hash', 'signing_passphrase_hash'].forEach(function (field) {
    if (login.json.data[field]) throw new Error('KEBOCORAN: respons login memuat ' + field);
  });
  console.log('  OK respons login bersih dari material rahasia');

  console.log('====================================================');
  console.log(' SELURUH 12 UJI PAdES LULUS');
  console.log('====================================================');
}

runTests()
  .catch(function (err) {
    console.error('UJI GAGAL:', err.message);
    process.exitCode = 1;
  })
  .finally(function () {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
