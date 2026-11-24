const mongoose = require('mongoose');

// recipientType: 'staff' (recipientId = Staff._id) veya 'admin' (tüm yöneticiler)
const notificationSchema = new mongoose.Schema({
    recipientType: { type: String, enum: ['staff', 'admin'], required: true },
    recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' },
    type: { type: String, enum: ['assigned', 'updated', 'cancelled', 'due_soon', 'overdue', 'comment', 'completed', 'revision', 'started', 'stage_changed', 'stale', 'automation_failed'], required: true },
    title: { type: String, maxlength: 200 },
    message: { type: String, maxlength: 600 },
    link: String,
    workOrderId: { type: mongoose.Schema.Types.ObjectId, ref: 'WorkOrder' },
    isRead: { type: Boolean, default: false },
    readAt: Date
}, { timestamps: true });

notificationSchema.index({ recipientType: 1, recipientId: 1, isRead: 1, createdAt: -1 });

module.exports = mongoose.model('Notification', notificationSchema);
