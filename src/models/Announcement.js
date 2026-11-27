const mongoose = require('mongoose');

// Personele yönelik duyuru ve şirket bilgilendirmeleri (okundu takibiyle)
const schema = new mongoose.Schema({
    title: { type: String, required: true, trim: true, maxlength: 160 },
    body: { type: String, maxlength: 4000, default: '' },
    level: { type: String, enum: ['info', 'important', 'urgent'], default: 'info' },
    pinned: { type: Boolean, default: false },
    expiresAt: Date,
    active: { type: Boolean, default: true },
    reads: [{ staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' }, at: { type: Date, default: Date.now } }],
    createdByName: { type: String, default: 'Yönetici' }
}, { timestamps: true });
schema.index({ active: 1, pinned: -1, createdAt: -1 });

module.exports = mongoose.models.Announcement || mongoose.model('Announcement', schema);
