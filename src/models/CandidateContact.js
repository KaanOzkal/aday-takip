const mongoose = require('mongoose');

// Aday iletişim kaydı (telefon, WhatsApp, e-posta, yüz yüze görüşme, not). Kayıtlar silinmez; düzeltme yeni kayıtla yapılır.
const contactSchema = new mongoose.Schema({
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true, index: true },
    type: { type: String, enum: ['phone', 'whatsapp', 'email', 'meeting', 'note'], required: true },
    direction: { type: String, enum: ['outgoing', 'incoming', ''], default: '' },
    subject: { type: String, maxlength: 200, default: '' },
    summary: { type: String, maxlength: 4000, default: '' },
    outcome: { type: String, maxlength: 300, default: '' },
    contactAt: { type: Date, default: Date.now },
    durationMin: { type: Number, min: 0, max: 600 },
    source: { type: String, enum: ['manual', 'system'], default: 'manual' }, // system: panelden gönderilen e-posta otomatik kaydı
    authorType: { type: String, enum: ['admin', 'staff', 'system'] },
    authorId: String,
    authorName: String
}, { timestamps: true });

contactSchema.index({ candidateId: 1, contactAt: -1 });
const block = function () { throw new Error('İletişim kayıtları değiştirilemez veya silinemez.'); };
['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndDelete'].forEach(op => contactSchema.pre(op, block));

contactSchema.statics.TYPES = { phone: 'Telefon görüşmesi', whatsapp: 'WhatsApp', email: 'E-posta', meeting: 'Yüz yüze görüşme', note: 'Personel notu' };

module.exports = mongoose.model('CandidateContact', contactSchema);
