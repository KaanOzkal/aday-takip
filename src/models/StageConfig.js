const mongoose = require('mongoose');

const templateSchema = new mongoose.Schema({
    title: { type: String, required: true, maxlength: 160 },
    description: { type: String, maxlength: 2000, default: '' },
    category: { type: String, default: 'Diğer' },
    priority: { type: String, default: 'Normal' },
    dueDays: { type: Number, default: 3, min: 0, max: 365 },
    staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' }, // boşsa aşamanın varsayılan sorumlusu
    active: { type: Boolean, default: true }
});

// Aşama başına otomasyon ayarı
const stageConfigSchema = new mongoose.Schema({
    stageKey: { type: String, required: true, unique: true },
    automationEnabled: { type: Boolean, default: true },
    defaultStaffId: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff' },   // ilk varsayılan sorumlu (geriye dönük uyumluluk)
    defaultStaffIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Staff' }], // tüm varsayılan sorumlular (her birine ortak görev)
    // Yöneticinin düzenlediği görünen bilgiler (boş = varsayılan). Aşama sayısı ve sırası sabittir.
    display: {
        name: { type: String, maxlength: 60, default: '' },
        desc: { type: String, maxlength: 400, default: '' },
        icon: { type: String, maxlength: 40, default: '' },
        time: { type: String, maxlength: 30, default: '' },
        previousNames: [{ type: String, maxlength: 60 }]
    },
    staleDays: { type: Number, default: 14, min: 1, max: 365 },
    templates: [templateSchema]
}, { timestamps: true });

module.exports = mongoose.model('StageConfig', stageConfigSchema);
