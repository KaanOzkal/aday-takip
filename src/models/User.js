// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    firstName: { type: String, default: 'Aday' },
    lastName: { type: String, default: 'Kullanıcı' },
    email: String,
    phone: String,
    job: String,
    location: String,
    
    // İŞTE İSTEDİĞİN EYALET KISMI BURASI
    targetState: { type: String, default: '' }, 
    
    passportNo: String,
    applicationNo: String,
    applicationDate: { type: Date, default: Date.now },
    score: { type: Number, default: 90 },
    currentStage: { type: String, default: 'Başvuru Alındı' },
    
    // Diğer veriler için yer tutucular
    documents: [{ name: String, status: String, date: Date, filename: String }],
});

module.exports = mongoose.model('User', userSchema);