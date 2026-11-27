const mongoose = require('mongoose');

// Sürücü Kayıt ve KOD95 ödemeleri: aday başına her tür için tek kayıt (mükerrer kayıt engellenir), tüm geçmiş saklanır
const TYPES = { driver_registration: { label: 'Sürücü Kayıt', amount: 411 }, kod95: { label: 'KOD95', amount: 411 } };
const fileSchema = new mongoose.Schema({
    name: String, mimeType: String, size: Number,
    fileId: String, driveLink: String, blobId: mongoose.Schema.Types.ObjectId,
    uploadedByType: { type: String, enum: ['candidate', 'admin'] }, uploadedByName: String,
    uploadedAt: { type: Date, default: Date.now },
    review: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    reviewNote: String, reviewedAt: Date
});
const historySchema = new mongoose.Schema({ action: String, byType: String, byName: String, note: String, at: { type: Date, default: Date.now } }, { _id: false });

const paymentSchema = new mongoose.Schema({
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true, index: true },
    type: { type: String, enum: Object.keys(TYPES), required: true },
    amount: { type: Number, default: 411 },
    currency: { type: String, default: 'EUR' },
    active: { type: Boolean, default: true },     // yönetici ödemeyi bu aday için işaretledi
    // awaiting_receipt → under_review → approved | rejected (→ yeni dekontla under_review)
    status: { type: String, enum: ['awaiting_receipt', 'under_review', 'approved', 'rejected'], default: 'awaiting_receipt' },
    receipts: [fileSchema],                         // yüklenen tüm dekontlar (geçmiş)
    approvedAt: Date, approvedBy: String,
    rejectReason: { type: String, default: '' },
    history: [historySchema]
}, { timestamps: true });
paymentSchema.index({ candidateId: 1, type: 1 }, { unique: true });
paymentSchema.statics.TYPES = TYPES;

module.exports = mongoose.models.Payment || mongoose.model('Payment', paymentSchema);
