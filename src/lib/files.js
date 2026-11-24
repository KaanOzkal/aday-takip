// Dosya içeriğinin ilk baytlarına bakarak gerçek türünü doğrular (uzantı/mime sahteciliğine karşı)
function sniff(buf) {
    if (!buf || buf.length < 12) return null;
    const hex = buf.slice(0, 12).toString('hex');
    if (hex.startsWith('25504446')) return 'application/pdf';                 // %PDF
    if (hex.startsWith('ffd8ff')) return 'image/jpeg';
    if (hex.startsWith('89504e470d0a1a0a')) return 'image/png';
    if (hex.startsWith('52494646') && buf.slice(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
    if (buf.slice(4, 8).toString('ascii') === 'ftyp') {
        const brand = buf.slice(8, 12).toString('ascii');
        if (/^(heic|heix|hevc|hevx|mif1|msf1|heim|heis)$/.test(brand)) return 'image/heic';
    }
    if (hex.startsWith('504b0304')) return 'application/zip';                 // docx/xlsx (OOXML)
    if (hex.startsWith('d0cf11e0a1b11ae1')) return 'application/x-ole';       // doc/xls
    return null;
}

const FAMILY = {
    'application/pdf': ['application/pdf'],
    'image/jpeg': ['image/jpeg'], 'image/png': ['image/png'], 'image/webp': ['image/webp'],
    'image/heic': ['image/heic'], 'image/heif': ['image/heic'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['application/zip'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['application/zip'],
    'application/msword': ['application/x-ole'], 'application/vnd.ms-excel': ['application/x-ole']
};

// Bildirilen mime izinli listede mi VE içerik bu türle uyuşuyor mu?
function isAllowedFile(file, allowedMimes) {
    if (!file || !file.buffer || !allowedMimes.includes(file.mimetype)) return false;
    const real = sniff(file.buffer);
    return !!real && (FAMILY[file.mimetype] || []).includes(real);
}

// Dosya adını güvenli hale getir (yol ayırıcıları ve kontrol karakterleri temizlenir)
const safeName = (n) => String(n || 'dosya').replace(/[\\/\x00-\x1f<>:"|?*]+/g, '_').slice(0, 150);

module.exports = { sniff, isAllowedFile, safeName };
