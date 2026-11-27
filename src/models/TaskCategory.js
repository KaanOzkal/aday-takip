const mongoose = require('mongoose');

// Yönetici tarafından yönetilen iş emri kategorileri
const schema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, maxlength: 60 },
    color: { type: String, default: '#D4111B', match: /^#[0-9A-Fa-f]{6}$/ },
    order: { type: Number, default: 100 },
    active: { type: Boolean, default: true }
}, { timestamps: true });
schema.index({ name: 1 }, { unique: true });

module.exports = mongoose.models.TaskCategory || mongoose.model('TaskCategory', schema);
