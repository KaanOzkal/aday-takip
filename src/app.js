const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');
const path = require('path');
const multer = require('multer');
require('dotenv').config(); // Yerelde .env dosyasını okumak için

// --- MODELLER ---
const Candidate = require('./models/Candidate');
const LogisticsWord = require('./models/LogisticsWord');
const Message = require('./models/Message');

const app = express();

// --- VERİTABANI BAĞLANTISI (DİNAMİK) ---
// Eğer Render'daysa MONGO_URI, yoksa yerel adresi kullan
const dbURI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/almanya_ats';

mongoose.connect(dbURI)
    .then(() => console.log('✅ Veritabanı Bağlantısı Başarılı'))
    .catch((err) => console.error('❌ Bağlantı Hatası:', err));

// --- MULTER AYARLARI ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, 'public/uploads/') },
    filename: function (req, file, cb) { 
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname) 
    }
});
const upload = multer({ storage: storage });

// --- NODEMAILER (DİNAMİK) ---
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER || 'proje@berliner.com.tr', 
        pass: process.env.EMAIL_PASS || 'rkmk zklb qbcv buhi'
    }
});

// --- AYARLAR ---
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ 
    secret: process.env.SESSION_SECRET || 'gizlianahtar', 
    resave: false, 
    saveUninitialized: true 
}));

// --- SABİT VERİLER ---
const STAGES = [
    'Başvuru Alındı', 'Evrak Kontrolü', 'Tercüme Süreci', 
    'İşveren Onayı', 'Vize Hazırlığı', 'Vize Başvurusu', 
    'Seyahat Planı', 'Almanya\'da'
];

const STATE_DATA = {
    "Berlin": { lat: 52.52, lon: 13.40, desc: "Başkent ve Doğu Avrupa'ya açılan lojistik kapısı. E-ticaret devlerinin merkezidir." },
    "Hamburg": { lat: 53.55, lon: 9.99, desc: "Avrupa'nın en büyük 3. limanı. Deniz taşımacılığı ve konteyner lojistiğinin kalbidir." },
    "Kiel": { lat: 54.32, lon: 10.12, desc: "İskandinavya lojistik rotası. Ro-Ro gemileri ve liman lojistiğinde uzmandır." },
    "Hannover": { lat: 52.37, lon: 9.73, desc: "Otomotiv lojistiği ve A2/A7 otobanlarının kesişim noktası olan kritik bir kavşaktır." },
    "Dortmund": { lat: 51.51, lon: 7.46, desc: "Avrupa'nın en büyük kanal limanı ve dijital lojistik teknolojilerinin merkezidir." },
    "Gelsenkirchen": { lat: 51.51, lon: 7.10, desc: "Ruhr sanayi bölgesi. Kimya ve ağır sanayi taşımacılığı (ADR) merkezidir." }
};

// ============================================
//  M I D D L E W A R E
// ============================================

const authCheck = async (req, res, next) => {
    if (!req.session.userId) return res.redirect('/login');
    try {
        const user = await Candidate.findById(req.session.userId);
        if (!user) return res.redirect('/login');
        req.user = user;
        const unreadCount = await Message.countDocuments({ candidateId: user._id, sender: 'Admin', isRead: false });
        res.locals.unreadCount = unreadCount;
        next();
    } catch (error) {
        console.error("AuthCheck Hatası:", error);
        res.redirect('/login');
    }
};

const adminAuthCheck = (req, res, next) => {
    if (req.session.isAdmin) {
        next(); 
    } else {
        res.redirect('/admin/login'); 
    }
};

// ============================================
//  R O T A L A R
// ============================================

app.get('/', (req, res) => res.redirect('/login')); // Ana sayfa yönlendirmesi

app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
    const { firstName, lastName, passportNo } = req.body;
    const user = await Candidate.findOne({ firstName: firstName.trim(), lastName: lastName.trim(), passportNo: passportNo.trim() });
    if (user) {
        req.session.userId = user._id;
        res.redirect('/panel?login=success'); 
    } else {
        res.send('Hatalı bilgiler. <a href="/login">Geri Dön</a>');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// --- ADMIN ---
app.get('/admin/login', (req, res) => {
    if(req.session.isAdmin) return res.redirect('/admin');
    res.render('admin_login');
});

app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    // Admin bilgileri de Env'den gelebilir veya hardcoded kalabilir
    const adminUser = process.env.ADMIN_USER || 'admin';
    const adminPass = process.env.ADMIN_PASS || 'admin123';

    if (username === adminUser && password === adminPass) {
        req.session.isAdmin = true;
        res.redirect('/admin');
    } else {
        res.render('admin_login', { error: 'Kullanıcı adı veya şifre hatalı!' });
    }
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/admin/login'));
});

// --- PANEL ---
app.get('/panel', authCheck, async (req, res) => {
    const dailyWords = await LogisticsWord.aggregate([{ $sample: { size: 5 } }]);
    const messages = await Message.find({ candidateId: req.user._id }).sort({ date: -1 });
    const targetStateInfo = req.user.targetState ? STATE_DATA[req.user.targetState] : null;
    res.render('dashboard', { user: req.user, stages: STAGES, dailyWords, messages, targetStateInfo, page: 'panel' });
});

app.get('/profile', authCheck, (req, res) => res.render('profile', { user: req.user, page: 'profile' }));

app.post('/profile/update', authCheck, async (req, res) => {
    const { email, phone, job, location, targetState } = req.body;
    await Candidate.findByIdAndUpdate(req.user._id, { email: email?.trim(), phone: phone?.trim(), job: job?.trim(), location: location?.trim(), targetState });
    res.redirect('/profile?status=success');
});

app.get('/documents', authCheck, (req, res) => res.render('documents', { user: req.user, page: 'documents' }));

app.post('/documents/upload', authCheck, upload.single('file'), async (req, res) => {
    if (!req.file) return res.send('Dosya seçin.');
    await Candidate.findByIdAndUpdate(req.user._id, { $push: { documents: { name: req.body.docType, filename: req.file.filename, status: 'İnceleniyor', date: new Date() } } });
    res.redirect('/documents');
});

app.get('/documents/delete/:docId', authCheck, async (req, res) => {
    await Candidate.findByIdAndUpdate(req.user._id, { $pull: { documents: { _id: req.params.docId } } });
    res.redirect('/documents');
});

app.get('/german', authCheck, async (req, res) => {
    const dailyWord = await LogisticsWord.findOne().sort({ date: -1 });
    const dailySentences = await LogisticsWord.aggregate([{ $match: { exampleGerman: { $exists: true, $ne: "" } } }, { $sample: { size: 5 } }]);
    res.render('german', { user: req.user, dailyWord, dailySentences, page: 'german' });
});

app.get('/german/category/:catName', authCheck, async (req, res) => {
    const words = await LogisticsWord.find({ category: req.params.catName });
    res.render('german_list', { user: req.user, words, categoryTitle: req.params.catName, page: 'german' });
});

app.get('/appointments', authCheck, (req, res) => {
    const sortedApps = (req.user.appointments || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.render('appointments', { user: req.user, page: 'appointments', appointments: sortedApps });
});

app.post('/appointments/create', authCheck, async (req, res) => {
    await Candidate.findByIdAndUpdate(req.user._id, { $push: { appointments: { date: req.body.date, time: req.body.time, type: req.body.type, status: 'Beklemede', createdAt: new Date() } } });
    res.redirect('/appointments');
});

app.get('/processes', authCheck, (req, res) => {
    const processDetails = [
        { name: 'Başvuru Alındı', time: 'Tamamlandı', icon: 'fa-file-signature', desc: 'Başvurunuz alındı.' },
        { name: 'Evrak Kontrolü', time: '1-3 Gün', icon: 'fa-search', desc: 'Belgeleriniz inceleniyor.' },
        { name: 'Tercüme Süreci', time: '3-5 Gün', icon: 'fa-language', desc: 'Yeminli tercüme yapılıyor.' },
        { name: 'İşveren Onayı', time: '1-2 Hafta', icon: 'fa-handshake', desc: 'İşveren onayı bekleniyor.' },
        { name: 'Vize Hazırlığı', time: 'Değişken', icon: 'fa-folder-open', desc: 'Vize dosyası hazırlanıyor.' },
        { name: 'Vize Başvurusu', time: 'Değişken', icon: 'fa-passport', desc: 'Konsolosluk görüşmesi.' },
        { name: 'Seyahat Planı', time: '3 Gün', icon: 'fa-plane', desc: 'Uçak ve konaklama.' },
        { name: 'Almanya\'da', time: 'Süresiz', icon: 'fa-map-marked-alt', desc: 'Yeni hayatınız başladı.' }
    ];
    const currentIndex = STAGES.indexOf(req.user.currentStage);
    const progress = Math.round(((currentIndex + 1) / STAGES.length) * 100);
    res.render('processes', { user: req.user, page: 'processes', processDetails, currentIndex, progress });
});

app.get('/game', authCheck, (req, res) => res.render('game', { user: req.user, page: 'game' }));
app.get('/settings', authCheck, (req, res) => res.render('settings', { user: req.user, page: 'settings' }));

app.get('/messages', authCheck, async (req, res) => {
    await Message.updateMany({ candidateId: req.user._id, sender: 'Admin', isRead: false }, { $set: { isRead: true } });
    const messages = await Message.find({ candidateId: req.user._id }).sort({ date: -1 });
    res.locals.unreadCount = 0; 
    res.render('messages', { user: req.user, page: 'messages', messages });
});

app.get('/help', authCheck, (req, res) => res.render('generic_page', { user: req.user, pageTitle: 'Yardım', page: 'help', icon: 'fa-question-circle' }));

// --- ADMIN YOLLARI ---
app.get('/admin', adminAuthCheck, async (req, res) => {
    const candidates = await Candidate.find().sort({ applicationDate: -1 });
    res.render('admin', { candidates, stages: STAGES });
});

app.post('/admin/message/bulk', adminAuthCheck, async (req, res) => {
    const { content } = req.body;
    try {
        const candidates = await Candidate.find({}, '_id');
        if (candidates.length > 0) {
            const messages = candidates.map(candidate => ({
                candidateId: candidate._id, content: content, sender: 'Admin', isRead: false, date: new Date()
            }));
            await Message.insertMany(messages);
        }
        res.redirect('/admin?status=bulk_success');
    } catch (error) {
        console.error("Toplu mesaj hatası:", error);
        res.send("Hata oluştu.");
    }
});

app.post('/admin/candidate/add', adminAuthCheck, async (req, res) => {
    try { await Candidate.create(req.body); res.redirect('/admin'); } 
    catch (err) { res.send("Hata: " + err.message); }
});

app.post('/admin/candidate/update', adminAuthCheck, async (req, res) => {
    await Candidate.findByIdAndUpdate(req.body.candidateId, { currentStage: req.body.newStage });
    res.redirect('/admin');
});

app.post('/admin/document/status', adminAuthCheck, async (req, res) => {
    await Candidate.updateOne({ _id: req.body.candidateId, "documents._id": req.body.docId }, { $set: { "documents.$.status": req.body.status } });
    res.redirect('/admin');
});

app.post('/admin/appointment/status', adminAuthCheck, async (req, res) => {
    await Candidate.updateOne({ _id: req.body.candidateId, "appointments._id": req.body.appId }, { $set: { "appointments.$.status": req.body.status } });
    res.redirect('/admin');
});

app.post('/admin/message/internal', adminAuthCheck, async (req, res) => {
    await Message.create({ candidateId: req.body.candidateId, content: req.body.content, sender: 'Admin', date: new Date(), isRead: false });
    res.redirect('/admin');
});

app.post('/admin/message/email', adminAuthCheck, async (req, res) => {
    const candidate = await Candidate.findById(req.body.candidateId);
    if (candidate.email) {
        try {
            await transporter.sendMail({
                from: '"Almanya Kariyer" <proje@berliner.com.tr>', to: candidate.email,
                subject: req.body.subject || 'Bildirim', html: `<div style="padding:20px;"><h3>Sayın ${candidate.firstName},</h3><p>${req.body.content}</p></div>`
            });
        } catch (error) { console.error("Mail hatası:", error); }
    }
    res.redirect('/admin');
});

app.get('/seed-german-words', async (req, res) => {
    await LogisticsWord.deleteMany({}); 
    // ... kelimeler ...
    res.send('✅ Kelimeler eklendi.');
});

// --- PORT AYARI (Render için gerekli) ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('------------------------------------------------');
    console.log(`🚀 Sunucu ${PORT} portunda çalışıyor`);
    console.log('------------------------------------------------');
});