const mongoose = require('mongoose');
// Google Drive yapılandırılmamış ortamlarda yüklenen dosyaların güvenli saklanması (en fazla 5 MB)
const schema = new mongoose.Schema({
    name: String, mimeType: String, size: Number, data: Buffer,
    ownerType: String, ownerId: String
}, { timestamps: true });
module.exports = mongoose.models.FileBlob || mongoose.model('FileBlob', schema);
