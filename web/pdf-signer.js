/**
 * Modul Pemrosesan Visual PDF & Penyematan Spesimen Tanda Tangan BSrE
 * Bertanggung jawab menyatukan dokumen, gambar spesimen pengguna, QR code, dan stempel TTE.
 */
window.PDFSigner = (function() {
  /**
   * Sematkan spesimen gambar, stempel resmi, dan QR verifikasi ke dokumen PDF.
   * @param {Object} opts
   * @param {ArrayBuffer|null} opts.pdfArrayBuffer - Buffer berkas PDF yang diunggah
   * @param {string} opts.textContent - Isi teks jika masukan berupa teks surat
   * @param {string|null} opts.specimenDataUrl - Data URL gambar spesimen tanda tangan
   * @param {string} opts.position - 'bottom-right' | 'bottom-left' | 'center'
   * @param {string} opts.receiptId - Nomor registrasi TTE BSrE
   * @param {string} opts.signerName - Nama lengkap penanda tangan
   * @returns {Promise<{ pdfBytes: Uint8Array, sha256Hex: string }>}
   */
  async function embedSpecimenAndStamp(opts) {
    let pdfDoc;

    if (opts.pdfArrayBuffer) {
      pdfDoc = await PDFLib.PDFDocument.load(opts.pdfArrayBuffer);
    } else {
      // Buat dokumen PDF A4 baru jika masukan berupa teks surat dinas
      pdfDoc = await PDFLib.PDFDocument.create();
      const page = pdfDoc.addPage([595.28, 841.89]);
      const fontBold = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
      const fontNorm = await pdfDoc.embedFont(PDFLib.StandardFonts.Helvetica);

      page.drawText('BADAN SIBER DAN SANDI NEGARA', { x: 50, y: 790, size: 14, font: fontBold, color: PDFLib.rgb(0.05, 0.15, 0.35) });
      page.drawText('BALAI BESAR SERTIFIKASI ELEKTRONIK (BSrE)', { x: 50, y: 772, size: 11, font: fontBold, color: PDFLib.rgb(0.2, 0.2, 0.2) });
      page.drawLine({
        start: { x: 50, y: 760 },
        end: { x: 545, y: 760 },
        thickness: 1.5,
        color: PDFLib.rgb(0.1, 0.3, 0.6)
      });

      const lines = (opts.textContent || 'Dokumen Resmi Elektronik').split('\n');
      let curY = 730;
      for (const line of lines) {
        page.drawText(line, { x: 50, y: curY, size: 10, font: fontNorm, color: PDFLib.rgb(0.15, 0.15, 0.15) });
        curY -= 16;
        if (curY < 180) break; // batas bawah halaman
      }
    }

    const pages = pdfDoc.getPages();
    let targetPage = pages[pages.length - 1];
    if (opts.pageNumber === 'first' && pages.length > 0) {
      targetPage = pages[0];
    } else if (typeof opts.pageNumber === 'number' && opts.pageNumber >= 1 && opts.pageNumber <= pages.length) {
      targetPage = pages[opts.pageNumber - 1];
    }
    const { width, height } = targetPage.getSize();

    // 1. Buat QR Code Verifikasi Berbasis URL Resmi BSrE
    const qrDataUrl = await QRCode.toDataURL(`https://bsre.bssn.go.id/verify/${opts.receiptId}`, {
      width: 140,
      margin: 1,
      color: { dark: '#002952', light: '#FFFFFF' }
    });
    const qrImage = await pdfDoc.embedPng(qrDataUrl);

    // 2. Embed Gambar Spesimen Tanda Tangan Pengguna jika Disediakan
    let specimenEmbed = null;
    if (opts.specimenDataUrl) {
      try {
        if (opts.specimenDataUrl.includes('image/jpeg') || opts.specimenDataUrl.includes('image/jpg')) {
          specimenEmbed = await pdfDoc.embedJpg(opts.specimenDataUrl);
        } else {
          specimenEmbed = await pdfDoc.embedPng(opts.specimenDataUrl);
        }
      } catch (embedErr) {
        console.warn('Gagal memuat gambar spesimen visual, fallback ke segel teks:', embedErr);
      }
    }

    // 3. Tentukan Dimensi Ukuran Box Visual (Bebas Custom Pixel)
    const boxW = Math.max(90, Math.min(width - 20, Number(opts.customW) || 210));
    const boxH = Math.max(45, Math.min(height - 20, Number(opts.customH) || 92));

    // 4. Tentukan Koordinat Box Visual (Bebas Custom Pixel & Preset)
    let posX = width - boxW - 35;
    let posY = 50;

    if (opts.position === 'bottom-left') {
      posX = 45;
      posY = 50;
    } else if (opts.position === 'center') {
      posX = (width / 2) - (boxW / 2);
      posY = 50;
    } else if (opts.position === 'top-right') {
      posX = width - boxW - 35;
      posY = height - boxH - 50;
    } else if (opts.position === 'top-left') {
      posX = 45;
      posY = height - boxH - 50;
    } else if (opts.position === 'center-middle') {
      posX = (width / 2) - (boxW / 2);
      posY = (height / 2) - (boxH / 2);
    } else if (opts.position === 'custom' || typeof opts.customX === 'number') {
      posX = Number(opts.customX);
      posY = Number(opts.customY);
    }

    // Pastikan tidak tembus keluar batas halaman (clamping)
    posX = Math.max(5, Math.min(posX, width - boxW - 5));
    posY = Math.max(5, Math.min(posY, height - boxH - 5));

    const fontHeader = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
    const fontBody = await pdfDoc.embedFont(PDFLib.StandardFonts.Helvetica);

    // 5. Gambar Box Bingkai Resmi BSrE
    targetPage.drawRectangle({
      x: posX,
      y: posY,
      width: boxW,
      height: boxH,
      borderColor: PDFLib.rgb(0.1, 0.35, 0.75),
      borderWidth: 1.2,
      color: PDFLib.rgb(0.97, 0.985, 1.0)
    });

    // 6. Tata Letak Proporsional Komponen di Dalam Box
    const pad = Math.max(4, Math.min(8, boxH * 0.08));
    const qrSize = Math.max(26, Math.min(boxH - (pad * 2), boxW * 0.32));
    const qrX = posX + pad;
    const qrY = posY + (boxH - qrSize) / 2;

    targetPage.drawImage(qrImage, {
      x: qrX,
      y: qrY,
      width: qrSize,
      height: qrSize
    });

    const contentX = qrX + qrSize + pad;
    const contentW = Math.max(30, (posX + boxW - pad) - contentX);
    const contentH = boxH - (pad * 2);

    // Skala Font dan Jarak Baris
    const fontSizeSigner = Math.max(5.5, Math.min(9.5, boxH * 0.09));
    const fontSizeBody = Math.max(4.5, Math.min(7.5, boxH * 0.07));
    const lineSpacing = fontSizeBody + 3;

    // Area Spesimen Gambar / Banner Segel
    const specH = Math.max(16, contentH - (3 * lineSpacing) - 2);
    const specY = posY + pad + (3 * lineSpacing) + 2;

    if (specimenEmbed) {
      targetPage.drawImage(specimenEmbed, {
        x: contentX,
        y: specY,
        width: contentW,
        height: specH
      });
    } else {
      // Banner Segel Resmi BSrE BSSN RI jika gambar spesimen pribadi tidak diunggah
      targetPage.drawRectangle({
        x: contentX,
        y: specY,
        width: contentW,
        height: specH,
        color: PDFLib.rgb(0.05, 0.22, 0.52),
        borderWidth: 0
      });

      const bannerTitleSize = Math.max(5, Math.min(8, specH * 0.36));
      const bannerSubSize = Math.max(4, Math.min(6.5, specH * 0.28));

      targetPage.drawText('SEGEL ELEKTRONIK RESMI BSrE', {
        x: contentX + 4,
        y: specY + (specH / 2) + 1,
        size: bannerTitleSize,
        font: fontHeader,
        color: PDFLib.rgb(1, 1, 1)
      });

      targetPage.drawText('BADAN SIBER DAN SANDI NEGARA', {
        x: contentX + 4,
        y: specY + (specH / 2) - bannerSubSize - 1,
        size: bannerSubSize,
        font: fontBody,
        color: PDFLib.rgb(0.82, 0.9, 1.0)
      });
    }

    // 7. Label Teks Legitimasi TTE Pascakuantum
    targetPage.drawText('Ditandatangani secara elektronik:', {
      x: contentX,
      y: posY + pad + (lineSpacing * 2),
      size: fontSizeBody,
      font: fontBody,
      color: PDFLib.rgb(0.25, 0.25, 0.25)
    });

    targetPage.drawText(opts.signerName || 'Pejabat Penandatangan', {
      x: contentX,
      y: posY + pad + lineSpacing,
      size: fontSizeSigner,
      font: fontHeader,
      color: PDFLib.rgb(0.0, 0.2, 0.6)
    });

    targetPage.drawText(`No. Reg: ${opts.receiptId} • ML-DSA FIPS 204`, {
      x: contentX,
      y: posY + pad,
      size: Math.max(4, fontSizeBody - 0.5),
      font: fontBody,
      color: PDFLib.rgb(0.4, 0.4, 0.4)
    });

    // 8. Integrasikan Struktur Tanda Tangan ISO 32000-1 PAdES (/AcroForm, /Widget /FT /Sig, /Type /Sig)
    const placeholderLength = 32768; // 32768 byte = 65536 hex char (cukup untuk PKCS#7 + ML-DSA + Cert Chain)
    const placeholderHex = '0'.repeat(placeholderLength * 2);
    const byteRangePlaceholder = [0, 1000000000, 1000000000, 1000000000];

    const sigDict = pdfDoc.context.obj({
      Type: 'Sig',
      Filter: 'Adobe.PPKLite',
      SubFilter: 'adbe.pkcs7.detached',
      ByteRange: byteRangePlaceholder,
      Contents: PDFLib.PDFHexString.of(placeholderHex),
      Reason: PDFLib.PDFString.of('TTE Pascakuantum Sah BSrE BSSN RI - FIPS 204 ML-DSA-65'),
      M: PDFLib.PDFString.of('D:' + new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14) + "+07'00'"),
      Name: PDFLib.PDFString.of(opts.signerName || 'Pejabat Penandatangan BSrE'),
      Location: PDFLib.PDFString.of('Jakarta, Indonesia'),
      ContactInfo: PDFLib.PDFString.of('info@bsre.bssn.go.id')
    });
    const sigRef = pdfDoc.context.register(sigDict);

    // Hubungkan box visual spesimen langsung ke Signature Field agar klik stempel membuka Signature Properties di Acrobat/BeSign
    const widgetDict = pdfDoc.context.obj({
      Type: 'Annot',
      Subtype: 'Widget',
      FT: 'Sig',
      Rect: [posX, posY, posX + boxW, posY + boxH],
      V: sigRef,
      T: PDFLib.PDFString.of('BSRE_SIG_' + opts.receiptId),
      F: 4,
      P: targetPage.ref
    });
    const widgetRef = pdfDoc.context.register(widgetDict);
    targetPage.node.addAnnot(widgetRef);

    // Daftarkan ke AcroForm di Catalog PDF tanpa menimpa signature lama jika ada
    if (pdfDoc.catalog.has(PDFLib.PDFName.of('AcroForm'))) {
      const existingAcroForm = pdfDoc.catalog.lookup(PDFLib.PDFName.of('AcroForm'));
      if (existingAcroForm && existingAcroForm instanceof PDFLib.PDFDict) {
        let fields = existingAcroForm.lookup(PDFLib.PDFName.of('Fields'));
        if (fields && fields instanceof PDFLib.PDFArray) {
          fields.push(widgetRef);
        } else {
          existingAcroForm.set(PDFLib.PDFName.of('Fields'), pdfDoc.context.obj([widgetRef]));
        }
        existingAcroForm.set(PDFLib.PDFName.of('SigFlags'), PDFLib.PDFNumber.of(3));
      }
    } else {
      const acroForm = pdfDoc.context.obj({
        Fields: [widgetRef],
        SigFlags: 3
      });
      pdfDoc.catalog.set(PDFLib.PDFName.of('AcroForm'), pdfDoc.context.register(acroForm));
    }

    // 9. Simpan Dokumen dengan useObjectStreams: false untuk kompatibilitas mutlak ISO 32000-1 PAdES
    const rawSaved = await pdfDoc.save({ useObjectStreams: false });
    let pdfBytes = new Uint8Array(rawSaved);

    // Cari posisi pasti /ByteRange dan /Contents KHUSUS placeholder baru ini
    const strData = new TextDecoder('latin1').decode(pdfBytes);
    const placeholderPattern = 'Contents <' + placeholderHex.slice(0, 64);
    const contentsIdx = strData.lastIndexOf(placeholderPattern);
    let offset1 = 0, offset2 = 0, offset3 = 0, byteRangeDocDigest = '';

    if (contentsIdx !== -1) {
      const startContents = contentsIdx + 10;
      const endContents = startContents + (placeholderLength * 2);
      if (endContents < pdfBytes.length) {
        offset1 = startContents - 1;
        offset2 = endContents + 1;
        offset3 = pdfBytes.length - offset2;

        const byteRangeStr = `/ByteRange [ 0 ${String(offset1).padStart(10, '0')} ${String(offset2).padStart(10, '0')} ${String(offset3).padStart(10, '0')} ]`;
        const byteRangePlaceholderPattern = '/ByteRange [ 0 1000000000 1000000000 1000000000 ]';
        const brIdx = strData.lastIndexOf(byteRangePlaceholderPattern);
        if (brIdx !== -1) {
          const enc = new TextEncoder();
          const brBytes = enc.encode(byteRangeStr);
          pdfBytes.set(brBytes, brIdx);
        }

        // Hitung SHA-256 ByteRange dokumen
        const part1 = pdfBytes.subarray(0, offset1);
        const part2 = pdfBytes.subarray(offset2, offset2 + offset3);
        const combined = new Uint8Array(part1.length + part2.length);
        combined.set(part1, 0);
        combined.set(part2, part1.length);

        const digestBuf = await crypto.subtle.digest('SHA-256', combined);
        byteRangeDocDigest = Array.from(new Uint8Array(digestBuf))
          .map(b => b.toString(16).padStart(2, '0')).join('');
      }
    }

    // Hash fallback jika ByteRange tidak ditemukan
    if (!byteRangeDocDigest) {
      const hashBuf = await crypto.subtle.digest('SHA-256', pdfBytes);
      byteRangeDocDigest = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    return {
      pdfBytes,
      sha256Hex: byteRangeDocDigest,
      startContents: offset1 + 1,
      endContents: offset2 - 1,
      placeholderLength
    };
  }

  /**
   * Menyuntikkan kontainer biner PKCS#7 (DER Hex) ke dalam slot /Contents dokumen PDF
   * @param {Uint8Array} pdfBytes
   * @param {string} pkcs7Hex
   * @param {number} startContents
   * @param {number} endContents
   * @returns {Uint8Array}
   */
  function injectPKCS7(pdfBytes, pkcs7Hex, startContents, endContents) {
    const slotLen = endContents - startContents;
    let finalHex = pkcs7Hex.toUpperCase();
    if (finalHex.length > slotLen) {
      console.warn('Peringatan: PKCS#7 melebihi slot /Contents!');
      finalHex = finalHex.slice(0, slotLen);
    } else {
      finalHex = finalHex.padEnd(slotLen, '0');
    }

    const hexBytes = new TextEncoder().encode(finalHex);
    pdfBytes.set(hexBytes, startContents);
    return pdfBytes;
  }

  return {
    embedSpecimenAndStamp,
    injectPKCS7
  };
})();
