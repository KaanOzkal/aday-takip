const mongoose = require('mongoose');

// İşveren şirket. (Koleksiyon adı önceki sürümle aynı: companies — mevcut kayıtlar korunur)
const positionSchema = new mongoose.Schema({
    title: { type: String, maxlength: 120 },
    city: { type: String, maxlength: 80, default: '' },
    openings: { type: Number, min: 0, max: 9999, default: 1 },
    active: { type: Boolean, default: true }
});

const companySchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true, trim: true, maxlength: 80 },
    contactPerson: { type: String, maxlength: 120, default: '' },
    phone: { type: String, maxlength: 40, default: '' },
    email: { type: String, maxlength: 160, default: '' },
    address: { type: String, maxlength: 300, default: '' },
    city: { type: String, maxlength: 80, default: '' },
    website: { type: String, maxlength: 200, default: '' },
    contractStatus: { type: String, enum: ['Görüşülüyor', 'Sözleşme Gönderildi', 'Aktif Sözleşme', 'Askıda', 'Sona Erdi'], default: 'Görüşülüyor' },
    contractStart: Date,
    contractEnd: Date,
    positions: [positionSchema],
    notes: { type: String, maxlength: 4000, default: '' },
    date: { type: Date, default: Date.now }
}, { timestamps: true });

companySchema.statics.CONTRACT_STATUSES = ['Görüşülüyor', 'Sözleşme Gönderildi', 'Aktif Sözleşme', 'Askıda', 'Sona Erdi'];

module.exports = mongoose.models.Company || mongoose.model('Company', companySchema);
