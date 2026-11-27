// Dosya saklama: Google Drive yapılandırılmışsa Drive'a, değilse veritabanına (FileBlob) yazar.
const FileBlob = require('../models/FileBlob');
const TR_ASCII = { 'ı': 'i', 'İ': 'I', 'ş': 's', 'Ş': 'S', 'ğ': 'g', 'Ğ': 'G', 'ç': 'c', 'Ç': 'C', 'ö': 'o', 'Ö': 'O', 'ü': 'u', 'Ü': 'U' };
const { safeName } = require('./files');

const driveEnabled = () => !!(process.env.CLIENT_ID && process.env.REFRESH_TOKEN && process.env.DRIVE_FOLDER_ID);

module.exports = function createStorage({ uploadToGoogleDrive, google }) {
    async function save(file, folder, owner = {}) {
        const name = safeName(file.originalname);
        if (driveEnabled()) {
            const f = await uploadToGoogleDrive({ ...file, originalname: name }, folder);
            return { name, mimeType: file.mimetype, size: file.size, fileId: f.id, driveLink: f.webViewLink };
        }
        const b = await FileBlob.create({ name, mimeType: file.mimetype, size: file.size, data: file.buffer, ownerType: owner.type, ownerId: owner.id ? String(owner.id) : '' });
        return { name, mimeType: file.mimetype, size: file.size, blobId: b._id };
    }

    // ref: { fileId | blobId, name, mimeType }
    async function stream(ref, res, { download = false } = {}) {
        const ascii = (n) => String(n || 'dosya').replace(/[ıİşŞğĞçÇöÖüÜ]/g, ch => TR_ASCII[ch]).normalize('NFKD').replace(/[^\x20-\x7E]/g, '').replace(/["\\]/g, '') || 'dosya';
        const disp = (n) => `${download ? 'attachment' : 'inline'}; filename="${ascii(n)}"; filename*=UTF-8''${encodeURIComponent(n || 'dosya')}`;
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'private, no-store');
        if (ref.blobId) {
            const b = await FileBlob.findById(ref.blobId);
            if (!b) return res.status(404).send('Dosya bulunamadı.');
            res.setHeader('Content-Type', b.mimeType || 'application/octet-stream');
            res.setHeader('Content-Disposition', disp(ref.name || b.name));
            return res.end(b.data);
        }
        if (!ref.fileId) return res.status(404).send('Dosya bulunamadı.');
        const auth = new google.auth.OAuth2(process.env.CLIENT_ID, process.env.CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
        auth.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
        const drive = google.drive({ version: 'v3', auth });
        const meta = await drive.files.get({ fileId: ref.fileId, fields: 'mimeType, name' });
        res.setHeader('Content-Type', meta.data.mimeType);
        res.setHeader('Content-Disposition', disp(ref.name || meta.data.name));
        const r = await drive.files.get({ fileId: ref.fileId, alt: 'media' }, { responseType: 'stream' });
        r.data.on('error', () => { if (!res.headersSent) res.status(500).end(); }).pipe(res);
    }
    return { save, stream, driveEnabled };
};
