const mongoose = require('mongoose');

const logisticsWordSchema = new mongoose.Schema({
    german: { type: String, required: true },  // Almanca kelime
    turkish: { type: String, required: true }, // Türkçe karşılığı
    category: String,
    exampleGerman: String,
    exampleTurkish: String,
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('LogisticsWord', logisticsWordSchema);