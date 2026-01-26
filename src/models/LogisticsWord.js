const mongoose = require('mongoose');

const LogisticsWordSchema = new mongoose.Schema({
    german: { type: String, required: true },
    turkish: { type: String, required: true },
    
    // --- BU ALANLAR EKSİK OLDUĞU İÇİN ÇALIŞMIYORDU ---
    category: { type: String, default: 'Genel' }, 
    exampleGerman: { type: String },
    exampleTurkish: { type: String },
    // --------------------------------------------------

    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('LogisticsWord', LogisticsWordSchema);