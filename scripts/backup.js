// Veritabanı yedeği: tüm koleksiyonları JSON (EJSON) olarak ./backups/<tarih>/ klasörüne yazar.
// Kullanım:  MONGO_URI="mongodb+srv://..." npm run backup
// Geri yükleme: node scripts/backup.js --restore backups/<tarih>   (DİKKAT: koleksiyonları yedektekiyle değiştirir)
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const { EJSON } = require('bson');

(async () => {
    const uri = process.env.MONGO_URI || process.env.MONGODB_URI;
    if (!uri) { console.error('MONGO_URI tanımlı değil.'); process.exit(1); }
    await mongoose.connect(uri);
    const db = mongoose.connection.db;
    const restoreIdx = process.argv.indexOf('--restore');
    if (restoreIdx > -1) {
        const dir = process.argv[restoreIdx + 1];
        if (!dir || !fs.existsSync(dir)) { console.error('Yedek klasörü bulunamadı.'); process.exit(1); }
        if (!process.argv.includes('--yes')) { console.error('Geri yükleme mevcut verinin üzerine yazar. Onaylamak için komuta --yes ekleyin.'); process.exit(1); }
        for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.json'))) {
            const name = f.replace(/\.json$/, '');
            const docs = EJSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
            await db.collection(name).deleteMany({});
            if (docs.length) await db.collection(name).insertMany(docs);
            console.log(`↺ ${name}: ${docs.length} kayıt geri yüklendi`);
        }
    } else {
        const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const dir = path.join(__dirname, '..', 'backups', stamp);
        fs.mkdirSync(dir, { recursive: true });
        const cols = await db.listCollections().toArray();
        let total = 0;
        for (const c of cols) {
            if (c.type === 'view' || c.name.startsWith('system.')) continue;
            const docs = await db.collection(c.name).find({}).toArray();
            fs.writeFileSync(path.join(dir, c.name + '.json'), EJSON.stringify(docs, { relaxed: false }));
            total += docs.length;
            console.log(`✓ ${c.name}: ${docs.length} kayıt`);
        }
        console.log(`\nYedek tamamlandı: ${dir} (${total} kayıt)`);
    }
    await mongoose.disconnect();
})().catch(e => { console.error('Yedekleme hatası:', e.message); process.exit(1); });
