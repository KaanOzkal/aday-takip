const mongoose = require('mongoose');

const automationLogSchema = new mongoose.Schema({
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', index: true },
    candidateName: String,
    stageKey: String,
    status: { type: String, enum: ['success', 'partial', 'failed', 'skipped'], index: true },
    message: String,
    created: [{ workOrderId: mongoose.Schema.Types.ObjectId, title: String, staffName: String }],
    failures: [String],
    trigger: String, // stage_change, manual, retry, candidate_created
    actorName: String,
    resolvedAt: Date
}, { timestamps: { createdAt: true, updatedAt: false } });

automationLogSchema.index({ createdAt: -1 });

module.exports = mongoose.model('AutomationLog', automationLogSchema);
