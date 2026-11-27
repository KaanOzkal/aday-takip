const mongoose = require('mongoose');

const STATUSES = ['Yeni', 'Devam Ediyor', 'Revizyon', 'Tamamlandı', 'İptal'];
const PRIORITIES = ['Düşük', 'Normal', 'Yüksek', 'Acil'];
const CATEGORIES = ['Sözleşme', 'Evrak Takibi', 'Tercüme', 'Vize İşlemleri', 'Randevu Organizasyonu', 'İşveren İletişimi', 'Aday Görüşmesi', 'Seyahat & Konaklama', 'Almanya Entegrasyonu', 'Başvuru Girişi', 'Ön Onay', 'Diğer'];

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
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', index: true }, // boş = adaydan bağımsız genel görev
    candidateName: { type: String, default: '' }, // aday silinse bile geçmişte görünsün
    category: { type: String, trim: true, maxlength: 60, default: 'Diğer' }, // yönetici tarafından yönetilen kategori listesi (TaskCategory)
    // Birden fazla personele verilen iş emri: her personel için ayrı kayıt, ortak groupId (durumlar birbirinden bağımsız)
    groupId: { type: mongoose.Schema.Types.ObjectId, index: true },
    groupSize: { type: Number, default: 1 },
    checklist: [new mongoose.Schema({ text: { type: String, maxlength: 200 }, done: { type: Boolean, default: false }, doneAt: Date })],
    recurringId: { type: mongoose.Schema.Types.ObjectId, index: true },
    createdByType: { type: String, default: 'admin' },
    createdByName: { type: String, default: '' },
    reminderNotifiedAt: Date,
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
    stageKey: { type: String, index: true },      // süreç aşaması (otomasyonla veya elle)
    templateId: mongoose.Schema.Types.ObjectId,
    automationKey: { type: String },              // aday:aşama:şablon — mükerrer otomasyon koruması
    source: { type: String, enum: ['manual', 'automation', 'ai'], default: 'manual' },
    dueSoonNotifiedAt: Date,
    overdueNotifiedAt: Date
}, { timestamps: true });

workOrderSchema.index({ automationKey: 1 }, { unique: true, partialFilterExpression: { automationKey: { $type: 'string' } } });

workOrderSchema.virtual('isOverdue').get(function () {
    return !!(this.dueDate && !['Tamamlandı', 'İptal'].includes(this.status) && this.dueDate < new Date());
});

workOrderSchema.statics.STATUSES = STATUSES;
workOrderSchema.statics.PRIORITIES = PRIORITIES;
workOrderSchema.statics.CATEGORIES = CATEGORIES;

module.exports = mongoose.model('WorkOrder', workOrderSchema);
