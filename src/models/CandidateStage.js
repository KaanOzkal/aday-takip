const mongoose = require('mongoose');

// Bir adayın 9 aşamadan birindeki durumu (aday başına aşama başına tek kayıt)
const candidateStageSchema = new mongoose.Schema({
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true },
    stageKey: { type: String, required: true },
    order: Number,
    status: { type: String, enum: ['Bekliyor', 'Devam Ediyor', 'Tamamlandı', 'Sorun Var'], default: 'Bekliyor' },
    skipped: { type: Boolean, default: false },
    skipReason: { type: String, default: '' },
    skipType: { type: String, enum: ['forced', 'skipped', ''], default: '' }, // forced: tamamlanmadan geçildi · skipped: hiç başlanmadan atlandı
    startedAt: Date,
    completedAt: Date,
    responsible: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' },
    note: { type: String, maxlength: 2000, default: '' },
    issueNote: { type: String, maxlength: 1000, default: '' },
    staleNotifiedAt: Date
}, { timestamps: true });

candidateStageSchema.index({ candidateId: 1, stageKey: 1 }, { unique: true });
candidateStageSchema.index({ stageKey: 1, status: 1 });

module.exports = mongoose.model('CandidateStage', candidateStageSchema);
