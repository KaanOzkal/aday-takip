const mongoose = require('mongoose');

// --- 1. DOKÜMAN ALT ŞEMASI ---
const documentSchema = new mongoose.Schema({
    name: String,
    filename: String,
    status: { 
        type: String, 
        enum: ['İnceleniyor', 'Onaylandı', 'Reddedildi'], 
        default: 'İnceleniyor' 
    },
    date: { type: Date, default: Date.now }
});

// --- 2. RANDEVU ALT ŞEMASI (Hatanın Çözümü) ---
const appointmentSchema = new mongoose.Schema({
    date: String,      // Örn: "2024-05-20"
    time: String,      // Örn: "14:30"
    type: String,      // Örn: "Genel Görüşme"
    status: { 
        type: String, 
        enum: ['Beklemede', 'Onaylandı', 'Reddedildi'], 
        default: 'Beklemede' 
    },
    createdAt: { type: Date, default: Date.now }
});

// --- 3. ANA ADAY ŞEMASI ---
const candidateSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    phone: String,
    job: String,
    location: String,
    
    // Hedef Eyalet (Admin Paneli İçin)
    targetState: { type: String, default: 'Belirtilmedi' }, 

    passportNo: String,
    applicationNo: String,
    applicationDate: { type: Date, default: Date.now },
    score: { type: Number, default: 50 },
    
    currentStage: { 
        type: String, 
        default: 'Başvuru Alındı' 
    },

    // Alt şemaları burada dizi ([]) içine koyuyoruz
    documents: [documentSchema],
    appointments: [appointmentSchema]
});

module.exports = mongoose.model('Candidate', candidateSchema);