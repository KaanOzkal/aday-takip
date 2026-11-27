// İş emri kategorileri: veritabanında tutulur, hızlı erişim için bellekte önbelleklenir.
const mongoose = require('mongoose');
const TaskCategory = require('../models/TaskCategory');
const WorkOrder = require('../models/WorkOrder');

const DEFAULTS = ['Evrak Kontrolü', 'Aday Araması', 'Belge Takibi', 'Müşteri Araması', 'Sözleşme Kontrolü', 'Genel Görevler'];
let cache = { all: [], active: [] };

async function refresh() {
    const list = await TaskCategory.find().sort({ order: 1, name: 1 }).lean();
    cache = { all: list, active: list.filter(c => c.active) };
    return cache;
}

// İlk açılışta: varsayılan + mevcut iş emirlerinde/eski sabit listede kullanılan kategorileri ekle (hiçbir veri silinmez)
async function init() {
    try {
        if (!(await TaskCategory.estimatedDocumentCount())) {
            const used = await WorkOrder.distinct('category').catch(() => []);
            const names = [...new Set([...DEFAULTS, ...WorkOrder.CATEGORIES, ...used.filter(Boolean)])];
            await TaskCategory.insertMany(names.map((name, i) => ({ name, order: i + 1 })), { ordered: false }).catch(() => {});
        }
        await TaskCategory.syncIndexes().catch(() => {});
        await refresh();
    } catch (e) { console.error('Kategori yükleme hatası:', e.message); }
}
if (mongoose.connection.readyState === 1) init(); else mongoose.connection.once('open', init);

module.exports = {
    refresh, init, DEFAULTS,
    names: () => cache.active.map(c => c.name),
    all: () => cache.all,
    isValid: (n) => typeof n === 'string' && cache.active.some(c => c.name === n),
    colorOf: (n) => (cache.all.find(c => c.name === n) || {}).color || '#667085'
};
