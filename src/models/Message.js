const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    candidateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate' },
    content: String,
    sender: String, // 'Admin' veya 'Aday'
    date: { type: Date, default: Date.now },
    
    // --- YENİ EKLENEN KISIM ---
    isRead: { type: Boolean, default: false } // Varsayılan olarak okunmamış
    // --------------------------
});

module.exports = mongoose.model('Message', messageSchema);