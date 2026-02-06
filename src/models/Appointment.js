const mongoose = require('mongoose');

const appointmentSchema = new mongoose.Schema({
    candidateId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Candidate', 
        required: true 
    },
    date: String,
    time: String,
    type: String, // Vize Görüşmesi, Evrak Teslimi vb.
    status: { type: String, default: 'Beklemede' },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Appointment', appointmentSchema);