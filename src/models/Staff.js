const mongoose = require('mongoose');

// Personel hesabı. Silme işlemi "soft delete" (deletedAt) ile yapılır; iş emri geçmişi korunur.
const staffSchema = new mongoose.Schema({
    fullName: { type: String, required: true, trim: true, maxlength: 120 },
    email: { type: String, trim: true, lowercase: true, maxlength: 160, default: '' },
    phone: { type: String, trim: true, maxlength: 40, default: '' },
    username: { type: String, required: true, trim: true, lowercase: true, maxlength: 60 },
    passwordHash: { type: String, default: '' },
    title: { type: String, trim: true, maxlength: 80, default: '' },
    status: { type: String, enum: ['active', 'passive'], default: 'active' },
    inviteTokenHash: { type: String, default: '' },
    inviteExpires: { type: Date },
    sessionVersion: { type: Number, default: 0 }, // şifre sıfırlama / pasife alma ile artar, eski oturumları düşürür
    lastLoginAt: { type: Date },
    failedLogins: { type: Number, default: 0 },
    lockedUntil: { type: Date },
    deletedAt: { type: Date, default: null }
}, { timestamps: true });

staffSchema.index({ username: 1 }, { unique: true });
staffSchema.index({ deletedAt: 1, status: 1 });

staffSchema.methods.isUsable = function () {
    return !this.deletedAt && this.status === 'active' && !!this.passwordHash;
};

module.exports = mongoose.model('Staff', staffSchema);
