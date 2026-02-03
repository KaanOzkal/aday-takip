const mongoose = require('mongoose');

// --- 1. DOKÜMAN ALT ŞEMASI ---
const documentSchema = new mongoose.Schema({
    name: String,
    filename: String,
    driveLink: String,
    fileId: String,
    status: { 
        type: String, 
        enum: ['İnceleniyor', 'Onaylandı', 'Reddedildi'], 
        default: 'İnceleniyor' 
    },
    date: { type: Date, default: Date.now }
});

// --- 2. RANDEVU ALT ŞEMASI ---
const appointmentSchema = new mongoose.Schema({
    date: String,
    time: String,
    type: String,
    status: { 
        type: String, 
        enum: ['Beklemede', 'Onaylandı', 'Reddedildi'], 
        default: 'Beklemede' 
    },
    createdAt: { type: Date, default: Date.now }
});

// --- 3. NOTLAR ALT ŞEMASI ---
const noteSchema = new mongoose.Schema({
    content: String,
    author: { type: String, default: 'Admin' },
    date: { type: Date, default: Date.now }
});

// --- 4. ANA ADAY ŞEMASI ---
const candidateSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    phone: String,
    job: String,
    location: String,
    targetState: { type: String, default: 'Belirtilmedi' }, 
    passportNo: String,
    applicationNo: String,
    applicationDate: { type: Date, default: Date.now },
    score: { type: Number, default: 90 },
    
    currentStage: { 
        type: String, 
        default: 'Başvuru Alındı' 
    },

    // Alt şemalar
    documents: [documentSchema],
    appointments: [appointmentSchema],
    notes: [noteSchema] 
});

module.exports = mongoose.model('Candidate', candidateSchema);