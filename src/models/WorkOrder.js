const mongoose = require('mongoose');

const STATUSES = ['Yeni', 'Devam Ediyor', 'Revizyon', 'Tamamlandı', 'İptal'];
const PRIORITIES = ['Düşük', 'Normal', 'Yüksek', 'Acil'];
const CATEGORIES = ['Evrak Takibi', 'Tercüme', 'Vize İşlemleri', 'Randevu Organizasyonu', 'İşveren İletişimi', 'Aday Görüşmesi', 'Seyahat & Konaklama', 'Almanya Entegrasyonu', 'Diğer'];

const attachmentSchema = new mongoose.Schema({
    name: String, fileId: String, driveLink: String, mimeType: String, size: Number,
    uploadedByType: { type: String, enum: ['admin', 'staff'] }, uploadedByName: String,
    date: { type: Date, default: Date.now }
});

const commentSchema = new mongoose.Schema({
    authorType: { type: String, enum: ['admin', 'staff'] }, authorName: String,
    text: { type: String, maxlength: 4000 }, date: { type: Date, default: Date.now }
});

const historySchema = new mongoose.Schema({
    action: String, byType: String, byName: String, note: String, at: { type: Date, default: Date.now }
});

const workOrderSchema = new mongoose.Schema({
    code: { type: String, index: true },
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true, index: true },
    candidateName: String, // aday silinse bile geçmişte görünsün
    category: { type: String, enum: CATEGORIES, default: 'Diğer' },
    title: { type: String, required: true, trim: true, maxlength: 160 },
    description: { type: String, maxlength: 6000, default: '' },
    assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff', required: true, index: true },
    priority: { type: String, enum: PRIORITIES, default: 'Normal' },
    startDate: Date,
    dueDate: Date,
    adminNote: { type: String, maxlength: 4000, default: '' },
    status: { type: String, enum: STATUSES, default: 'Yeni', index: true },
    resultNote: { type: String, maxlength: 6000, default: '' },
    startedAt: Date,
    completedAt: Date,
    cancelledAt: Date,
    attachments: [attachmentSchema],
    comments: [commentSchema],
    history: [historySchema],
    dueSoonNotifiedAt: Date,
    overdueNotifiedAt: Date
}, { timestamps: true });

workOrderSchema.virtual('isOverdue').get(function () {
    return !!(this.dueDate && !['Tamamlandı', 'İptal'].includes(this.status) && this.dueDate < new Date());
});

workOrderSchema.statics.STATUSES = STATUSES;
workOrderSchema.statics.PRIORITIES = PRIORITIES;
workOrderSchema.statics.CATEGORIES = CATEGORIES;

module.exports = mongoose.model('WorkOrder', workOrderSchema);
