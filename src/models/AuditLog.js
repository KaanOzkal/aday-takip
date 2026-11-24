const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
    actorType: { type: String, enum: ['admin', 'staff', 'system', 'anonymous'] },
    actorId: String,
    actorName: String,
    action: { type: String, index: true },
    targetType: String,
    targetId: String,
    summary: String,
    ip: String,
    userAgent: String
}, { timestamps: { createdAt: true, updatedAt: false } });

auditLogSchema.index({ createdAt: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
