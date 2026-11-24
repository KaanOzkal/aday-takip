const mongoose = require('mongoose');

// Aday süreç geçmişi: yalnızca ekleme yapılır, değiştirilemez / silinemez.
const processEventSchema = new mongoose.Schema({
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true, index: true },
    stageKey: String,
    type: { type: String, required: true }, // stage_change, stage_status, stage_update, task_created, task_completed, automation, pause, resume, migrated, note
    text: { type: String, maxlength: 1000 },
    actorType: { type: String, enum: ['admin', 'staff', 'system', 'ai'], default: 'system' },
    actorName: String,
    meta: mongoose.Schema.Types.Mixed
}, { timestamps: { createdAt: true, updatedAt: false } });

processEventSchema.index({ candidateId: 1, createdAt: -1 });

const immutable = function () { throw new Error('Süreç geçmişi kayıtları değiştirilemez veya silinemez.'); };
['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndDelete', 'findOneAndReplace'].forEach(op => processEventSchema.pre(op, immutable));
processEventSchema.pre('save', function () { if (!this.isNew) throw new Error('Süreç geçmişi kayıtları değiştirilemez.'); });

module.exports = mongoose.model('ProcessEvent', processEventSchema);
