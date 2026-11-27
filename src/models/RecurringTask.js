const mongoose = require('mongoose');

// Tekrarlayan iş emri tanımı: zamanı gelince atanan her personel için ayrı iş emri oluşturur
const schema = new mongoose.Schema({
    title: { type: String, required: true, trim: true, maxlength: 160 },
    description: { type: String, maxlength: 6000, default: '' },
    category: { type: String, maxlength: 60, default: 'Genel Görevler' },
    priority: { type: String, enum: ['Düşük', 'Normal', 'Yüksek', 'Acil'], default: 'Normal' },
    assignees: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Staff' }],
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate' },
    frequency: { type: String, enum: ['daily', 'weekdays', 'weekly', 'monthly'], required: true },
    weekday: { type: Number, min: 0, max: 6, default: 1 },   // weekly: 0=Pazar … 6=Cumartesi
    monthDay: { type: Number, min: 1, max: 28, default: 1 }, // monthly
    time: { type: String, match: /^\d{2}:\d{2}$/, default: '09:00' }, // Türkiye saati
    dueHours: { type: Number, min: 1, max: 24 * 30, default: 8 },
    checklist: [{ type: String, maxlength: 200 }],
    active: { type: Boolean, default: true },
    nextRunAt: { type: Date, index: true },
    lastRunAt: Date,
    runCount: { type: Number, default: 0 },
    createdByName: { type: String, default: 'Yönetici' }
}, { timestamps: true });

module.exports = mongoose.models.RecurringTask || mongoose.model('RecurringTask', schema);
