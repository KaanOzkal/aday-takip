const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');
const path = require('path');
const { google } = require('googleapis');
const stream = require('stream');
const multer = require('multer');
require('dotenv').config(); 
const PDFDocument = require('pdfkit'); 
const fs = require('fs');
const Appointment = require('./models/Appointment');

// --- ORTAK DOSYALAR ---
const GlobalFileSchema = new mongoose.Schema({
    name: String,       
    filename: String,   
    date: { type: Date, default: Date.now }
});
const GlobalFile = mongoose.model('GlobalFile', GlobalFileSchema);

// --- YENİ: ŞİRKETLER (FİRMALAR) MODELİ ---
const CompanySchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    date: { type: Date, default: Date.now }
});
const Company = mongoose.model('Company', CompanySchema);

// --- MODELLER ---
const Candidate = require('./models/Candidate');
const LogisticsWord = require('./models/LogisticsWord');
const Message = require('./models/Message');

const app = express();

// --- VERİTABANI BAĞLANTISI ---
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
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }
});

// --- GOOGLE DRIVE AKILLI YÜKLEME FONKSİYONU ---
const uploadToGoogleDrive = async (fileObject, folderName) => {
    try {
        const auth = new google.auth.OAuth2(
            process.env.CLIENT_ID,
            process.env.CLIENT_SECRET,
            process.env.GOOGLE_REDIRECT_URI
        );
        auth.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
        const driveService = google.drive({ version: 'v3', auth });

        const searchRes = await driveService.files.list({
            q: `mimeType='application/vnd.google-apps.folder' and name='${folderName}' and '${process.env.DRIVE_FOLDER_ID}' in parents and trashed=false`,
            fields: 'files(id, name)',
        });

        let targetFolderId;

        if (searchRes.data.files.length > 0) {
            targetFolderId = searchRes.data.files[0].id;
        } else {
            const folderMeta = {
                name: folderName,
                mimeType: 'application/vnd.google-apps.folder',
                parents: [process.env.DRIVE_FOLDER_ID] 
            };
            const folder = await driveService.files.create({
                resource: folderMeta,
                fields: 'id'
            });
            targetFolderId = folder.data.id;
        }

        const bufferStream = new stream.PassThrough();
        bufferStream.end(fileObject.buffer);

        const response = await driveService.files.create({
            media: {
                mimeType: fileObject.mimetype,
                body: bufferStream,
            },
            requestBody: {
                name: fileObject.originalname,
                parents: [targetFolderId], 
            },
            fields: 'id, name, webViewLink',
        });

        return response.data;
    } catch (error) {
        console.error('Drive Yükleme Hatası:', error);
        throw error;
    }
};

// --- MAİL AYARLARI ---
const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 587, // <--- BURAYI 587 YAPTIK
    secure: false, 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    },
    family: 4 
});

// --- GENEL AYARLAR ---
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ 
    secret: process.env.SESSION_SECRET || 'gizli', 
    resave: false, 
    saveUninitialized: true 
}));

// --- SABİT VERİLER ---
const STAGES = [
    'Başvuru Alındı', 
    'Evrak Kontrolü', 
    'Tercüme Süreci', 
    'İşveren Onayı', 
    'Vize Hazırlığı', 
    'Vize Ön Onay', 
    'Vize Başvurusu', 
    'Seyahat Planı', 
    'Almanya\'da'
];

const GERMANY_STAGES = [
    '1. Başvuru ve Kayıt',
    '2. Tercüme ve Denklik',
    '3. İşveren Eşleşmesi',
    '4. Vize Hazırlığı ve Ön Onay',
    '5. Vize Başvurusu',
    '6. Almanya\'ya Uçuş ve Yerleşim'
];

const STATE_DATA = {
    "Berlin": { lat: 52.52, lon: 13.40, desc: "Başkent." },
    "Hamburg": { lat: 53.55, lon: 9.99, desc: "Liman kenti." },
    "Kiel": { lat: 54.32, lon: 10.12, desc: "Kuzey rotası." },
    "Hannover": { lat: 52.37, lon: 9.73, desc: "Sanayi merkezi." },
    "Dortmund": { lat: 51.51, lon: 7.46, desc: "Teknoloji." },
    "Gelsenkirchen": { lat: 51.51, lon: 7.10, desc: "Ruhr bölgesi." }
};

// --- MIDDLEWARE ---
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
//  ROTALAR
// ============================================

app.get('/', (req, res) => res.redirect(req.session.userId ? '/panel' : '/login'));
app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/panel');
    res.render('login', { error: null, values: {} });
});

app.post('/login', async (req, res) => {
    const firstName = (req.body.firstName || '').trim();
    const lastName = (req.body.lastName || '').trim();
    const passportNo = (req.body.passportNo || '').trim();
    const values = { firstName, lastName, passportNo };
    if (!firstName || !lastName || !passportNo) {
        return res.status(400).render('login', { error: 'Lütfen tüm alanları doldurun.', values });
    }
    try {
        // Büyük/küçük harf ve Türkçe karakter farklarını yok say (ör. "ali" = "Ali")
        let user;
        try {
            user = await Candidate.findOne({ firstName, lastName, passportNo }).collation({ locale: 'tr', strength: 1 });
        } catch (e) {
            // Collation desteklemeyen veritabanları için yedek: büyük/küçük harf duyarsız tam eşleşme
            const rx = (s) => new RegExp('^' + s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
            user = await Candidate.findOne({ firstName: rx(firstName), lastName: rx(lastName), passportNo: rx(passportNo) });
        }
        if (!user) {
            return res.status(401).render('login', { error: 'Bilgiler eşleşmedi. Ad, soyad ve pasaport numaranızı kontrol edin.', values });
        }
        req.session.userId = user._id;
        res.redirect('/panel?login=success');
    } catch (err) {
        console.error('Giriş hatası:', err);
        res.status(500).render('login', { error: 'Şu anda giriş yapılamıyor. Lütfen biraz sonra tekrar deneyin.', values });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

app.get('/admin/login', (req, res) => {
    if(req.session.isAdmin) return res.redirect('/admin');
    res.render('admin_login');
});

app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === (process.env.ADMIN_USER || 'admin') && password === (process.env.ADMIN_PASS || 'admin123')) {
        req.session.isAdmin = true;
        res.redirect('/admin');
    } else {
        res.render('admin_login', { error: 'Hatalı giriş!' });
    }
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/admin/login'));
});

// Rastgele kelime seçimi ($sample desteklenmezse JS ile karıştırarak)
const sampleWords = async (size, match = {}) => {
    try {
        return await LogisticsWord.aggregate([{ $match: match }, { $sample: { size } }]);
    } catch (e) {
        const all = await LogisticsWord.find(match).lean();
        for (let i = all.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [all[i], all[j]] = [all[j], all[i]]; }
        return all.slice(0, size);
    }
};

const stageProgress = (stage) => {
    const i = STAGES.indexOf(stage);
    return i === -1 ? 0 : Math.round(((i + 1) / STAGES.length) * 100);
};

app.get('/panel', authCheck, async (req, res) => {
    try {
        const [dailyWords, messages, globalFiles, appointments] = await Promise.all([
            sampleWords(5),
            Message.find({ candidateId: req.user._id }).sort({ date: -1 }).limit(20),
            GlobalFile.find().sort({ date: -1 }),
            Appointment.find({ candidateId: req.user._id }).sort({ createdAt: -1 }).limit(5)
        ]);
        const targetStateInfo = req.user.targetState ? STATE_DATA[req.user.targetState] : null;
        res.render('dashboard', {
            user: req.user, stages: STAGES, dailyWords, messages, targetStateInfo,
            progress: stageProgress(req.user.currentStage), globalFiles, appointments, page: 'panel'
        });
    } catch (err) {
        console.error('Panel hatası:', err);
        res.status(500).send('Panel yüklenemedi. Lütfen sayfayı yenileyin.');
    }
});

app.get('/profile', authCheck, (req, res) => res.render('profile', { user: req.user, page: 'profile', states: Object.keys(STATE_DATA) }));

app.post('/profile/update', authCheck, async (req, res) => {
    try {
        const email = (req.body.email || '').trim();
        const phone = (req.body.phone || '').trim();
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.redirect('/profile?error=invalid_email');
        const update = { email, phone, job: (req.body.job || '').trim(), location: (req.body.location || '').trim() };
        if (req.body.targetState && STATE_DATA[req.body.targetState]) update.targetState = req.body.targetState;
        await Candidate.findByIdAndUpdate(req.user._id, update);
        res.redirect('/profile?status=success');
    } catch (err) {
        res.redirect('/profile?error=failed');
    }
});

app.get('/documents', authCheck, (req, res) => res.render('documents', { user: req.user, page: 'documents' }));

const ALLOWED_UPLOAD = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif'];
app.post('/documents/upload', authCheck, (req, res, next) => {
    upload.single('file')(req, res, (err) => {
        if (err) return res.redirect('/documents?error=' + (err.code === 'LIMIT_FILE_SIZE' ? 'too_large' : 'upload_failed'));
        next();
    });
}, async (req, res) => {
    if (!req.file) return res.redirect('/documents?error=no_file');
    if (!req.body.docType) return res.redirect('/documents?error=no_type');
    if (!ALLOWED_UPLOAD.includes(req.file.mimetype)) return res.redirect('/documents?error=bad_type');
    try {
        const candidateFolderName = `${req.user.firstName} ${req.user.lastName}`;
        const driveFile = await uploadToGoogleDrive(req.file, candidateFolderName);

        await Candidate.findByIdAndUpdate(req.user._id, {
            $push: { documents: { name: req.body.docType, filename: driveFile.name, driveLink: driveFile.webViewLink, fileId: driveFile.id, status: 'İnceleniyor', date: new Date() } }
        });
        res.redirect('/documents?status=uploaded');
    } catch (error) {
        console.error('Belge yükleme hatası:', error.message);
        res.redirect('/documents?error=upload_failed');
    }
});

// Onaylanmış belgeler aday tarafından silinemez
const deleteOwnDocument = async (req, res) => {
    try {
        const doc = req.user.documents.id(req.params.docId);
        if (!doc) return res.redirect('/documents?error=not_found');
        if (doc.status === 'Onaylandı') return res.redirect('/documents?error=approved_locked');
        await Candidate.findByIdAndUpdate(req.user._id, { $pull: { documents: { _id: req.params.docId } } });
        res.redirect('/documents?status=deleted');
    } catch (err) { res.redirect('/documents?error=failed'); }
};
app.post('/documents/delete/:docId', authCheck, deleteOwnDocument);
app.get('/documents/delete/:docId', authCheck, deleteOwnDocument);

app.get('/documents/view/:docId', async (req, res) => {
    if (!req.session.userId && !req.session.isAdmin) return res.redirect('/login');
    try {
        const docId = req.params.docId;
        let fileId = null;

        // Aday yalnızca kendi belgesini görebilir; admin hepsini görebilir
        const query = { 'documents._id': docId };
        if (!req.session.isAdmin) query._id = req.session.userId;
        const candidate = await Candidate.findOne(query, { 'documents.$': 1 });
        if (candidate && candidate.documents && candidate.documents.length > 0) fileId = candidate.documents[0].fileId;
        if (!fileId) return res.status(404).send('Belge bulunamadı.');

        const auth = new google.auth.OAuth2(process.env.CLIENT_ID, process.env.CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
        auth.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
        const driveService = google.drive({ version: 'v3', auth });

        const fileMeta = await driveService.files.get({ fileId: fileId, fields: 'mimeType, name' });
        res.setHeader('Content-Type', fileMeta.data.mimeType);
        res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(fileMeta.data.name)}"`);

        const response = await driveService.files.get({ fileId: fileId, alt: 'media' }, { responseType: 'stream' });
        response.data.on('error', err => { if (!res.headersSent) res.status(500).send('Dosya okuma hatası.'); }).pipe(res);
    } catch (error) {
        res.status(500).send('Dosya görüntülenemedi: ' + error.message);
    }
});

app.get('/german', authCheck, async (req, res) => {
    const dailyWord = await LogisticsWord.findOne().sort({ date: -1 });
    const dailySentences = await sampleWords(5, { exampleGerman: { $exists: true, $ne: "" } });
    res.render('german', { user: req.user, dailyWord, dailySentences, page: 'german' });
});

app.get('/german/category/:catName', authCheck, async (req, res) => {
    const words = await LogisticsWord.find({ category: req.params.catName });
    res.render('german_list', { user: req.user, words, categoryTitle: req.params.catName, page: 'german' });
});

app.get('/appointments', authCheck, async (req, res) => {
    try {
        const myAppointments = await Appointment.find({ candidateId: req.user._id }).sort({ createdAt: -1 });
        res.render('appointments', { user: req.user, page: 'appointments', appointments: myAppointments });
    } catch (error) { res.redirect('/panel'); }
});

app.post('/appointments/create', authCheck, async (req, res) => {
    try {
        const { date, time, type } = req.body;
        const allowedTypes = ['Genel Görüşme', 'Evrak Teslimi', 'Vize Hazırlığı', 'Acil Destek'];
        if (!date || !time || !allowedTypes.includes(type)) return res.redirect('/appointments?error=missing');
        const today = new Date(); today.setHours(0, 0, 0, 0);
        if (new Date(date + 'T00:00:00') < today) return res.redirect('/appointments?error=past_date');
        const pending = await Appointment.countDocuments({ candidateId: req.user._id, status: 'Beklemede' });
        if (pending >= 3) return res.redirect('/appointments?error=too_many');

        await Appointment.create({ candidateId: req.user._id, date, time, type, status: 'Beklemede' });
        await Candidate.findByIdAndUpdate(req.user._id, { $push: { appointments: { date, time, type, status: 'Beklemede', createdAt: new Date() } } });
        res.redirect('/appointments?status=success');
    } catch (error) { res.redirect('/appointments?error=failed'); }
});

// Aday yalnızca bekleyen randevusunu iptal edebilir
app.post('/appointments/:id/cancel', authCheck, async (req, res) => {
    try {
        const app_ = await Appointment.findOne({ _id: req.params.id, candidateId: req.user._id });
        if (!app_) return res.redirect('/appointments?error=not_found');
        if (app_.status !== 'Beklemede') return res.redirect('/appointments?error=cannot_cancel');
        await Appointment.deleteOne({ _id: app_._id });
        await Candidate.updateOne({ _id: req.user._id }, { $pull: { appointments: { date: app_.date, time: app_.time, status: 'Beklemede' } } });
        res.redirect('/appointments?status=cancelled');
    } catch (error) { res.redirect('/appointments?error=failed'); }
});

const PROCESS_DETAILS = [
    { name: 'Başvuru Alındı', time: '1 Gün', icon: 'fa-file-signature', desc: 'Başvurunuz sisteme kaydedildi ve danışmanınıza atandı.' },
    { name: 'Evrak Kontrolü', time: '1-3 Gün', icon: 'fa-magnifying-glass', desc: 'Yüklediğiniz belgeler eksiksizlik ve geçerlilik açısından inceleniyor.' },
    { name: 'Tercüme Süreci', time: '3-5 Gün', icon: 'fa-language', desc: 'Belgelerinizin yeminli tercümesi yapılıyor.' },
    { name: 'İşveren Onayı', time: '1-2 Hafta', icon: 'fa-handshake', desc: 'Profiliniz Alman işverene iletildi, onay bekleniyor.' },
    { name: 'Vize Hazırlığı', time: '1 Hafta', icon: 'fa-folder-open', desc: 'Vize dosyanız hazırlanıyor, eksik evraklar tamamlanıyor.' },
    { name: 'Vize Ön Onay', time: 'Değişken', icon: 'fa-stamp', desc: 'Alman makamlarından ön onay (Vorabzustimmung) bekleniyor.' },
    { name: 'Vize Başvurusu', time: 'Değişken', icon: 'fa-passport', desc: 'Konsolosluk randevusu ve vize görüşmesi aşaması.' },
    { name: 'Seyahat Planı', time: '3 Gün', icon: 'fa-plane', desc: 'Uçuş ve ilk konaklama planlaması yapılıyor.' },
    { name: 'Almanya\'da', time: 'Son adım', icon: 'fa-flag-checkered', desc: 'Tebrikler! Almanya\'daki yeni hayatınız başladı.' }
];

app.get('/processes', authCheck, (req, res) => {
    const currentIndex = STAGES.indexOf(req.user.currentStage);
    res.render('processes', { user: req.user, page: 'processes', processDetails: PROCESS_DETAILS, currentIndex, progress: stageProgress(req.user.currentStage) });
});

app.get('/germany-process', authCheck, (req, res) => {
    res.render('germany_process', { user: req.user, page: 'germany_process', germanyStages: GERMANY_STAGES });
});

app.get('/game', authCheck, (req, res) => res.render('game', { user: req.user, page: 'game' }));
app.get('/settings', authCheck, (req, res) => res.render('settings', { user: req.user, page: 'settings' }));

app.post('/settings/update', authCheck, async (req, res) => {
    try {
        await Candidate.findByIdAndUpdate(req.user._id, {
            'preferences.emailNotifications': req.body.emailNotifications === 'on',
            'preferences.smsNotifications': req.body.smsNotifications === 'on',
            'preferences.whatsappNotifications': req.body.whatsappNotifications === 'on'
        });
        res.redirect('/settings?status=saved');
    } catch (err) { res.redirect('/settings?error=failed'); }
});

app.get('/messages', authCheck, async (req, res) => {
    const unreadIds = (await Message.find({ candidateId: req.user._id, sender: 'Admin', isRead: false }, '_id')).map(m => String(m._id));
    await Message.updateMany({ candidateId: req.user._id, sender: 'Admin', isRead: false }, { $set: { isRead: true } });
    const messages = await Message.find({ candidateId: req.user._id }).sort({ date: -1 });
    res.locals.unreadCount = 0;
    res.render('messages', { user: req.user, page: 'messages', messages, newIds: unreadIds });
});

app.get('/help', authCheck, (req, res) => res.render('generic_page', { user: req.user, pageTitle: 'Yardım', page: 'help', icon: 'fa-question-circle' }));

// ============================================
//  ADMIN PANELİ
// ============================================

// --- Yardımcılar ---
const escapeHtml = (s = '') => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const mailTemplate = (firstName, content) => `
<div style="font-family:Arial,Helvetica,sans-serif;background:#f4f6fb;padding:24px;">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
    <div style="background:#0b1220;color:#ffffff;padding:18px 24px;font-weight:bold;letter-spacing:1px;">BERLINER</div>
    <div style="padding:24px;color:#1f2937;font-size:15px;line-height:1.6;">
      <p style="margin-top:0;">Sayın ${escapeHtml(firstName)},</p>
      <p>${escapeHtml(content).replace(/\r?\n/g, '<br>')}</p>
    </div>
    <div style="padding:14px 24px;border-top:1px solid #e5e7eb;color:#6b7280;font-size:12px;">Bu e-posta BERLINER aday takip sistemi üzerinden gönderilmiştir.</div>
  </div>
</div>`;

const MAIL_FROM = process.env.MAIL_FROM || '"BERLINER" <ozkalkaan490@gmail.com>';

// Formdan gelen returnTo adresine (yalnızca /admin altı) durum parametresiyle geri dön
const redirectBack = (req, res, key, value) => {
    let target = '/admin';
    const r = req.body && req.body.returnTo;
    if (typeof r === 'string' && r.startsWith('/admin') && !r.startsWith('//')) target = r;
    const url = new URL(target, 'http://local');
    url.searchParams.delete('status');
    url.searchParams.delete('error');
    if (key) url.searchParams.set(key, value);
    res.redirect(url.pathname + url.search + url.hash);
};

const toIdArray = (ids) => {
    if (!ids) return [];
    const arr = Array.isArray(ids) ? ids : String(ids).split(',');
    return arr.map(s => s.trim()).filter(id => mongoose.Types.ObjectId.isValid(id));
};

const INTEGRATION_KEYS = ['telefonTemini', 'lojmanYerlesimi', 'genelEntegrasyon', 'bankaHesabi', 'kod95', 'saglikSigortasi', 'anmeldung', 'dilKursu'];

app.get('/admin', adminAuthCheck, async (req, res) => {
    try {
        const [candidates, appointments, companies, unreadFromCandidates] = await Promise.all([
            Candidate.find().select('-cvDetails -applicationForm').sort({ applicationDate: -1, _id: -1 }).lean(),
            Appointment.find().populate('candidateId', 'firstName lastName email').sort({ createdAt: -1 }).lean(),
            Company.find().sort({ name: 1 }).lean(),
            Message.countDocuments({ sender: { $ne: 'Admin' }, isRead: false })
        ]);

        // Tüm belgeleri tek listede topla
        const allDocuments = [];
        candidates.forEach(c => (c.documents || []).forEach(d => allDocuments.push({
            ...d, candidateId: c._id, candidateName: `${c.firstName || ''} ${c.lastName || ''}`.trim()
        })));
        allDocuments.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));

        const stageCounts = STAGES.map(s => ({ name: s, count: candidates.filter(c => c.currentStage === s).length }));
        const companyCounts = [{ name: 'Atanmadı', count: candidates.filter(c => !c.company || c.company === 'Atanmadı').length }]
            .concat(companies.map(co => ({ name: co.name, _id: co._id, count: candidates.filter(c => c.company === co.name).length })));
        const jobs = [...new Set(candidates.map(c => c.job).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'tr'));

        const stats = {
            total: candidates.length,
            pendingDocs: allDocuments.filter(d => d.status === 'İnceleniyor').length,
            pendingAppointments: appointments.filter(a => a.status === 'Beklemede').length,
            inGermany: candidates.filter(c => c.currentStage === "Almanya'da").length,
            unassigned: companyCounts[0].count,
            noEmail: candidates.filter(c => !c.email || !c.email.trim()).length,
            unreadMessages: unreadFromCandidates
        };

        res.render('admin', {
            candidates, appointments, companies, allDocuments,
            stageCounts, companyCounts, jobs, stats,
            stages: STAGES, germanyStages: GERMANY_STAGES,
            user: { firstName: 'Admin' }
        });
    } catch (error) {
        console.error('Admin panel hatası:', error);
        res.status(500).send('Panel yüklenemedi: ' + escapeHtml(error.message));
    }
});

// --- ADAY DETAY SAYFASI ---
app.get('/admin/candidate/:id', adminAuthCheck, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.redirect('/admin?error=not_found#candidates');
        const candidate = await Candidate.findById(req.params.id).lean();
        if (!candidate) return res.redirect('/admin?error=not_found#candidates');

        const [appointments, messages, companies] = await Promise.all([
            Appointment.find({ candidateId: candidate._id }).sort({ createdAt: -1 }).lean(),
            Message.find({ candidateId: candidate._id }).sort({ date: -1 }).lean(),
            Company.find().sort({ name: 1 }).lean()
        ]);

        res.render('admin_candidate_detail', {
            candidate, appointments, messages, companies,
            stages: STAGES, germanyStages: GERMANY_STAGES,
            stateNames: Object.keys(STATE_DATA),
            user: { firstName: 'Admin' }
        });
    } catch (error) {
        console.error(error);
        res.redirect('/admin?error=not_found#candidates');
    }
});

// --- ADAY EKLE / DÜZENLE / SİL ---
app.post('/admin/candidate/add', adminAuthCheck, async (req, res) => {
    try {
        const b = req.body;
        const firstName = (b.firstName || '').trim();
        const lastName = (b.lastName || '').trim();
        const passportNo = (b.passportNo || '').trim().toUpperCase();
        if (!firstName || !lastName || !passportNo) return redirectBack(req, res, 'error', 'missing_fields');

        const exists = await Candidate.findOne({ passportNo });
        if (exists) return redirectBack(req, res, 'error', 'passport_exists');

        const created = await Candidate.create({
            firstName, lastName, passportNo,
            email: (b.email || '').trim(),
            phone: (b.phone || '').trim(),
            job: (b.job || '').trim(),
            location: (b.location || '').trim(),
            company: b.company || 'Atanmadı',
            currentStage: STAGES.includes(b.currentStage) ? b.currentStage : STAGES[0],
            password: passportNo
        });
        res.redirect(`/admin/candidate/${created._id}?status=candidate_created`);
    } catch (err) {
        console.error(err);
        redirectBack(req, res, 'error', 'create_failed');
    }
});

app.post('/admin/candidate/:id/edit', adminAuthCheck, async (req, res) => {
    try {
        const b = req.body;
        const update = {};
        ['firstName', 'lastName', 'email', 'phone', 'job', 'location', 'targetState', 'applicationNo'].forEach(k => {
            if (typeof b[k] === 'string') update[k] = b[k].trim();
        });
        if (typeof b.passportNo === 'string' && b.passportNo.trim()) update.passportNo = b.passportNo.trim().toUpperCase();
        if (b.score !== undefined && b.score !== '') update.score = Math.max(0, Math.min(100, Number(b.score) || 0));
        if (typeof b.company === 'string') update.company = b.company;
        await Candidate.findByIdAndUpdate(req.params.id, update);
        redirectBack(req, res, 'status', 'candidate_updated');
    } catch (error) { redirectBack(req, res, 'error', 'update_failed'); }
});

app.post('/admin/candidate/:id/delete', adminAuthCheck, async (req, res) => {
    try {
        const id = req.params.id;
        await Promise.all([
            Candidate.findByIdAndDelete(id),
            Appointment.deleteMany({ candidateId: id }),
            Message.deleteMany({ candidateId: id })
        ]);
        res.redirect('/admin?status=candidate_deleted#candidates');
    } catch (error) { res.redirect('/admin?error=delete_failed#candidates'); }
});

// --- TOPLU İŞLEMLER ---
app.post('/admin/candidates/bulk', adminAuthCheck, async (req, res) => {
    try {
        const ids = toIdArray(req.body.ids);
        const { action, value } = req.body;
        if (ids.length === 0) return redirectBack(req, res, 'error', 'no_selection');

        if (action === 'company') {
            await Candidate.updateMany({ _id: { $in: ids } }, { $set: { company: value || 'Atanmadı' } });
        } else if (action === 'stage' && STAGES.includes(value)) {
            await Candidate.updateMany({ _id: { $in: ids } }, { $set: { currentStage: value } });
        } else if (action === 'germanyStage' && GERMANY_STAGES.includes(value)) {
            await Candidate.updateMany({ _id: { $in: ids } }, { $set: { germanyStage: value } });
        } else if (action === 'message' && value && value.trim()) {
            await Message.insertMany(ids.map(id => ({ candidateId: id, content: value.trim(), sender: 'Admin', isRead: false, date: new Date() })));
        } else if (action === 'delete') {
            await Promise.all([
                Candidate.deleteMany({ _id: { $in: ids } }),
                Appointment.deleteMany({ candidateId: { $in: ids } }),
                Message.deleteMany({ candidateId: { $in: ids } })
            ]);
        } else {
            return redirectBack(req, res, 'error', 'invalid_action');
        }
        redirectBack(req, res, 'status', 'bulk_done');
    } catch (error) {
        console.error(error);
        redirectBack(req, res, 'error', 'bulk_failed');
    }
});

// --- CSV DIŞA AKTAR (Excel uyumlu) ---
app.get('/admin/export.csv', adminAuthCheck, async (req, res) => {
    try {
        const ids = toIdArray(req.query.ids);
        const query = ids.length ? { _id: { $in: ids } } : {};
        const list = await Candidate.find(query).select('-cvDetails -applicationForm').sort({ firstName: 1 }).lean();
        const cell = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const header = ['Ad', 'Soyad', 'Pasaport', 'E-posta', 'Telefon', 'Meslek', 'Lokasyon', 'Hedef Şehir', 'Şirket', 'Genel Aşama', 'Almanya Aşaması', 'Puan', 'Belge Sayısı', 'Bekleyen Belge', 'Başvuru Tarihi'];
        const rows = list.map(c => [
            c.firstName, c.lastName, c.passportNo, c.email, c.phone || c.phoneNumber, c.job, c.location, c.targetState,
            c.company || 'Atanmadı', c.currentStage, c.germanyStage, c.score,
            (c.documents || []).length, (c.documents || []).filter(d => d.status === 'İnceleniyor').length,
            c.applicationDate ? new Date(c.applicationDate).toLocaleDateString('tr-TR') : ''
        ].map(cell).join(';'));
        const csv = '﻿' + header.map(cell).join(';') + '\r\n' + rows.join('\r\n');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="adaylar_${new Date().toISOString().slice(0, 10)}.csv"`);
        res.send(csv);
    } catch (error) { res.redirect('/admin?error=export_failed'); }
});

// --- ŞİRKET YÖNETİMİ ---
app.post('/admin/company/add', adminAuthCheck, async (req, res) => {
    try {
        const name = (req.body.name || '').trim();
        if (!name || name === 'Atanmadı') return redirectBack(req, res, 'error', 'missing_fields');
        await Company.create({ name });
        redirectBack(req, res, 'status', 'company_created');
    } catch (error) {
        redirectBack(req, res, 'error', 'company_exists');
    }
});

app.post('/admin/company/rename', adminAuthCheck, async (req, res) => {
    try {
        const comp = await Company.findById(req.body.id);
        const newName = (req.body.name || '').trim();
        if (!comp || !newName || newName === 'Atanmadı') return redirectBack(req, res, 'error', 'missing_fields');
        if (newName !== comp.name) {
            if (await Company.findOne({ name: newName })) return redirectBack(req, res, 'error', 'company_exists');
            await Candidate.updateMany({ company: comp.name }, { $set: { company: newName } });
            comp.name = newName;
            await comp.save();
        }
        redirectBack(req, res, 'status', 'company_updated');
    } catch (error) { redirectBack(req, res, 'error', 'update_failed'); }
});

app.post('/admin/company/delete', adminAuthCheck, async (req, res) => {
    try {
        const comp = await Company.findById(req.body.id);
        if (comp) {
            await Candidate.updateMany({ company: comp.name }, { $set: { company: 'Atanmadı' } });
            await Company.findByIdAndDelete(req.body.id);
        }
        redirectBack(req, res, 'status', 'company_deleted');
    } catch (error) {
        redirectBack(req, res, 'error', 'delete_failed');
    }
});

app.post('/admin/candidate/company', adminAuthCheck, async (req, res) => {
    try {
        const { candidateId, newCompany } = req.body;
        await Candidate.findByIdAndUpdate(candidateId, { company: newCompany || 'Atanmadı' });
        redirectBack(req, res, 'status', 'company_updated');
    } catch (error) {
        redirectBack(req, res, 'error', 'company_failed');
    }
});

// --- SÜREÇ GÜNCELLEMELERİ ---
app.post('/admin/candidate/update', adminAuthCheck, async (req, res) => {
    try {
        if (!STAGES.includes(req.body.newStage)) return redirectBack(req, res, 'error', 'invalid_action');
        await Candidate.findByIdAndUpdate(req.body.candidateId, { currentStage: req.body.newStage });
        redirectBack(req, res, 'status', 'updated');
    } catch (error) { redirectBack(req, res, 'error', 'update_failed'); }
});

app.post('/admin/candidate/update-germany', adminAuthCheck, async (req, res) => {
    try {
        if (!GERMANY_STAGES.includes(req.body.newGermanyStage)) return redirectBack(req, res, 'error', 'invalid_action');
        await Candidate.findByIdAndUpdate(req.body.candidateId, { germanyStage: req.body.newGermanyStage });
        redirectBack(req, res, 'status', 'updated');
    } catch (error) { redirectBack(req, res, 'error', 'update_failed'); }
});

app.post('/admin/candidate/update-integration', adminAuthCheck, async (req, res) => {
    try {
        const update = {};
        INTEGRATION_KEYS.forEach(k => { update[`integrationSteps.${k}`] = req.body[k] === 'on'; });
        await Candidate.findByIdAndUpdate(req.body.candidateId, update);
        redirectBack(req, res, 'status', 'integration_updated');
    } catch (error) { redirectBack(req, res, 'error', 'integration_failed'); }
});

// --- BELGELER ---
app.post('/admin/document/status', adminAuthCheck, async (req, res) => {
    try {
        const allowed = ['İnceleniyor', 'Onaylandı', 'Reddedildi'];
        if (!allowed.includes(req.body.status)) return redirectBack(req, res, 'error', 'invalid_action');
        await Candidate.updateOne({ _id: req.body.candidateId, 'documents._id': req.body.docId }, { $set: { 'documents.$.status': req.body.status } });
        redirectBack(req, res, 'status', 'document_updated');
    } catch (error) { redirectBack(req, res, 'error', 'update_failed'); }
});

app.post('/admin/document/delete', adminAuthCheck, async (req, res) => {
    try {
        await Candidate.findByIdAndUpdate(req.body.candidateId, { $pull: { documents: { _id: req.body.docId } } });
        redirectBack(req, res, 'status', 'document_deleted');
    } catch (error) { redirectBack(req, res, 'error', 'delete_failed'); }
});

// --- RANDEVULAR ---
app.post('/admin/appointment/status', adminAuthCheck, async (req, res) => {
    try {
        const { appId, status } = req.body;
        if (!['Beklemede', 'Onaylandı', 'Reddedildi'].includes(status)) return redirectBack(req, res, 'error', 'invalid_action');
        const appointment = await Appointment.findByIdAndUpdate(appId, { status }, { new: true });
        if (!appointment) return redirectBack(req, res, 'error', 'not_found');
        await Candidate.updateOne(
            { _id: appointment.candidateId, appointments: { $elemMatch: { date: appointment.date, time: appointment.time } } },
            { $set: { 'appointments.$.status': status } }
        );
        redirectBack(req, res, 'status', 'appointment_updated');
    } catch (error) { redirectBack(req, res, 'error', 'update_failed'); }
});

// --- NOTLAR ---
app.post('/admin/candidate/add-note', adminAuthCheck, async (req, res) => {
    try {
        const { candidateId, noteContent } = req.body;
        if (!noteContent || !noteContent.trim()) return redirectBack(req, res, 'error', 'missing_fields');
        await Candidate.findByIdAndUpdate(candidateId, { $push: { notes: { content: noteContent.trim(), date: new Date(), author: 'Admin' } } });
        redirectBack(req, res, 'status', 'note_added');
    } catch (error) { redirectBack(req, res, 'error', 'note_failed'); }
});

app.post('/admin/candidate/:id/note/:noteId/delete', adminAuthCheck, async (req, res) => {
    try {
        await Candidate.findByIdAndUpdate(req.params.id, { $pull: { notes: { _id: req.params.noteId } } });
        redirectBack(req, res, 'status', 'note_deleted');
    } catch (error) { redirectBack(req, res, 'error', 'delete_failed'); }
});

// --- MESAJ & E-POSTA ---
app.post('/admin/message/internal', adminAuthCheck, async (req, res) => {
    try {
        if (!req.body.content || !req.body.content.trim()) return redirectBack(req, res, 'error', 'missing_fields');
        await Message.create({ candidateId: req.body.candidateId, content: req.body.content.trim(), sender: 'Admin', date: new Date(), isRead: false });
        redirectBack(req, res, 'status', 'message_sent');
    } catch (error) { redirectBack(req, res, 'error', 'message_failed'); }
});

app.post('/admin/message/delete', adminAuthCheck, async (req, res) => {
    try {
        await Message.findByIdAndDelete(req.body.messageId);
        redirectBack(req, res, 'status', 'message_deleted');
    } catch (error) { redirectBack(req, res, 'error', 'delete_failed'); }
});

app.post('/admin/message/bulk', adminAuthCheck, async (req, res) => {
    try {
        const { content, targetCompany } = req.body;
        if (!content || !content.trim()) return redirectBack(req, res, 'error', 'missing_fields');
        const query = {};
        if (targetCompany && targetCompany !== 'Tümü') {
            query.company = targetCompany === 'Atanmadı' ? { $in: ['Atanmadı', null, ''] } : targetCompany;
        }
        const candidates = await Candidate.find(query, '_id');
        if (candidates.length === 0) return redirectBack(req, res, 'error', 'no_candidates');
        await Message.insertMany(candidates.map(c => ({ candidateId: c._id, content: content.trim(), sender: 'Admin', isRead: false, date: new Date() })));
        redirectBack(req, res, 'status', 'bulk_success');
    } catch (error) { redirectBack(req, res, 'error', 'bulk_failed'); }
});

app.post('/admin/message/email', adminAuthCheck, async (req, res) => {
    try {
        const candidate = await Candidate.findById(req.body.candidateId);
        if (!candidate || !candidate.email || !candidate.email.trim()) return redirectBack(req, res, 'error', 'mail_yok');
        await transporter.sendMail({
            from: MAIL_FROM,
            to: candidate.email.trim(),
            subject: req.body.subject || 'Bilgilendirme',
            html: mailTemplate(candidate.firstName, req.body.content || '')
        });
        redirectBack(req, res, 'status', 'mail_success');
    } catch (error) {
        console.error('Mail hatası:', error.message);
        redirectBack(req, res, 'error', 'mail_fail');
    }
});

// Şirkete göre filtreli toplu mail
app.post('/admin/message/email/bulk', adminAuthCheck, async (req, res) => {
    const { subject, content, targetCompany } = req.body;
    try {
        const query = { email: { $exists: true, $nin: ['', null] } };
        if (targetCompany && targetCompany !== 'Tümü') {
            query.company = targetCompany === 'Atanmadı' ? { $in: ['Atanmadı', null, ''] } : targetCompany;
        }
        const candidates = await Candidate.find(query);
        if (candidates.length === 0) return redirectBack(req, res, 'error', 'no_candidates');

        let sent = 0, failed = 0;
        // Sunucuyu boğmamak için 5'erli gruplar halinde gönder
        for (let i = 0; i < candidates.length; i += 5) {
            const batch = candidates.slice(i, i + 5);
            const results = await Promise.allSettled(batch.map(c => transporter.sendMail({
                from: MAIL_FROM,
                to: c.email.trim(),
                subject: subject || 'Duyuru',
                html: mailTemplate(c.firstName, content || '')
            })));
            results.forEach(r => r.status === 'fulfilled' ? sent++ : failed++);
        }
        if (sent === 0) return redirectBack(req, res, 'error', 'bulk_mail_fail');
        redirectBack(req, res, 'status', failed ? `bulk_mail_partial_${sent}_${failed}` : 'bulk_mail_success');
    } catch (error) { redirectBack(req, res, 'error', 'bulk_mail_fail'); }
});

app.get('/admin/sync-drive-files', adminAuthCheck, async (req, res) => {
    try {
        const oldAuth = new google.auth.OAuth2(process.env.OLD_CLIENT_ID, process.env.OLD_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
        oldAuth.setCredentials({ refresh_token: process.env.OLD_REFRESH_TOKEN });
        const drive = google.drive({ version: 'v3', auth: oldAuth });

        const response = await drive.files.list({ q: `'${process.env.OLD_DRIVE_FOLDER_ID}' in parents and trashed = false`, fields: 'files(id, name, webViewLink, createdTime)', pageSize: 1000 });
        const driveFiles = response.data.files;
        if (!driveFiles || driveFiles.length === 0) return res.redirect('/admin?error=drive_empty');

        const norm = s => (s || '').toLocaleLowerCase('tr-TR').replace(/ğ/g, 'g').replace(/ü/g, 'u').replace(/ş/g, 's').replace(/ı/g, 'i').replace(/ö/g, 'o').replace(/ç/g, 'c');
        const candidates = await Candidate.find();
        let matchCount = 0;

        for (const candidate of candidates) {
            const searchName = norm(candidate.firstName);
            const searchSurname = norm(candidate.lastName);
            if (!searchName || !searchSurname) continue;
            // Hem ad hem soyad geçmeli (yanlış eşleşmeleri azaltır)
            const matchingFiles = driveFiles.filter(file => {
                const fileName = norm(file.name);
                return fileName.includes(searchName) && fileName.includes(searchSurname);
            });
            if (matchingFiles.length > 0) {
                const existingFileIds = candidate.documents.map(d => d.fileId);
                for (const file of matchingFiles) {
                    if (!existingFileIds.includes(file.id)) {
                        await Candidate.findByIdAndUpdate(candidate._id, { $push: { documents: { name: 'Otomatik Eşleşen: ' + file.name, filename: file.name, driveLink: file.webViewLink, fileId: file.id, status: 'İnceleniyor', date: file.createdTime || new Date() } } });
                        matchCount++;
                    }
                }
            }
        }
        res.redirect(`/admin?status=sync_${matchCount}`);
    } catch (error) {
        console.error('Drive eşitleme hatası:', error.message);
        res.redirect('/admin?error=sync_failed');
    }
});
// Seed Data
app.get('/seed-candidates-full', adminAuthCheck, async (req, res) => {
    const rawData = [
       { id: 1, ad: "Veysi Irğar", meslek: "Kurye", durumId: 5, lokasyon: "Mardin", basvuruNo: "BER-2026-001", pasaport: "U27192985", telefon: "+90 555 555 55 55", email: "veysi@email.com", puan: 85 },
       { id: 2, ad: "Umut Balkış", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Denizli", basvuruNo: "MUN-2026-002", pasaport: "U36039583", telefon: "+90 555 555 55 55", email: "umut@email.com", puan: 88 },
       { id: 3, ad: "Sami Koca", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Konya", basvuruNo: "HAM-2026-003", pasaport: "U36837917", telefon: "+90 555 555 55 55", email: "sami@email.com", puan: 90 },
       { id: 4, ad: "Mücahit Dinçer", meslek: "Tır Şoförü", durumId: 5, lokasyon: "istanbul", basvuruNo: "KOL-2026-004", pasaport: "U28059476", telefon: "+90 555 555 55 55", email: "mucahit@email.com", puan: 82 },
       { id: 5, ad: "Muammer Arslan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "FRA-2026-005", pasaport: "U38138827", telefon: "+90 555 555 55 55", email: "muammer@email.com", puan: 88 },
       { id: 6, ad: "Mehmet Ozan Özmen", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "STU-2026-006", pasaport: "U22433028", telefon: "+90 555 555 55 55", email: "mehmet.ozan@email.com", puan: 95 },
       { id: 7, ad: "Mehmet Emin Yaman", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "DUS-2026-007", pasaport: "U35565318", telefon: "+90 555 555 55 55", email: "mehmet.emin@email.com", puan: 92 },
       { id: 8, ad: "Mahmut Sürhan Karadal", meslek: "Kurye", durumId: 5, lokasyon: "Adana", basvuruNo: "DOR-2026-008", pasaport: "U23636576", telefon: "+90 555 555 55 55", email:"surhankaradal27@gmail.com", puan: 90 },
       { id: 9, ad: "Kerim İpek", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Niğde", basvuruNo: "ESS-2026-009", pasaport: "U25148300", telefon: "+90 555 555 55 55", email: "kerim@email.com", puan: 85 },
       { id: 10, ad: "İsrafil Yılmaz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Mersin", basvuruNo: "LEI-2026-010", pasaport: "U88050133", telefon: "+90 555 555 55 55", email: "israfil@email.com", puan: 89 },
       { id: 11, ad: "İbrahim Can Eser", meslek: "Kurye", durumId: 5 , lokasyon: "Ankara", basvuruNo: "BRE-2026-011", pasaport: "U27946181", telefon: "+90 555 555 55 55", email: "ibrahim@email.com", puan: 99 },
       { id: 12, ad: "Halil İbrahim Aras", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Diyarbakır", basvuruNo: "DRE-2026-012", pasaport: "U37493231", telefon: "+90 555 555 55 55", email: "halil@email.com", puan: 81 },
       { id: 13, ad: "Hakan Yiğit", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adana", basvuruNo: "HAN-2026-013", pasaport: "U28910675", telefon: "+90 555 555 55 55", email: "hakan@email.com", puan: 83 },
       { id: 14, ad: "Fatih Mustafa Alıravcı", meslek: "Kurye", durumId: 5, lokasyon: "İstanbul", basvuruNo: "NUR-2026-014", pasaport: "U23981375", telefon: "+90 555 555 55 55", email: "fatih@email.com", puan: 86 },
       { id: 15, ad: "Ercan Ayata", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Osmaniye", basvuruNo: "DUI-2026-015", pasaport: "U15981690", telefon: "+90 555 555 55 55", email: "ercan@email.com", puan: 87 },
       { id: 16, ad: "Doğan Bozkurt", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Antalya", basvuruNo: "BOC-2026-016", pasaport: "U26435423", telefon: "+90 555 555 55 55", email: "dogan@email.com", puan: 91 },
       { id: 17, ad: "Burhanettin Irğar", meslek: "Kurye", durumId: 5, lokasyon: "Mardin", basvuruNo: "WUP-2026-017", pasaport: "U30274584", telefon: "+90 555 555 55 55", email: "burhanirgar@gmail.com", puan: 84 },
       { id: 18, ad: "Ali Yılmaz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Gaziantep", basvuruNo: "BIE-2026-018", pasaport: "U32781709", telefon: "+90 555 555 55 55", email: "aliyl14531453@gmail.com", puan: 92 },
       { id: 19, ad: "Ahmet Gök", meslek: "Kurye", durumId: 5, lokasyon: "Adana", basvuruNo: "BON-2026-019", pasaport: "U22798501", telefon: "+90 555 555 55 55", email: "ahmetgok.12@gmail.com", puan: 89 },
       { id: 20, ad: "Murat Koçcu", meslek: "Tır Şoförü", durumId: 4, lokasyon: "Konya", basvuruNo: "MUN-2026-020", pasaport: "U29925245", telefon: "+90 555 555 55 55", email: "muratkoccuu@gmail.com", puan: 86 },
       { id: 21, ad: "Senai Kılıç", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Diyarbakır", basvuruNo: "KAR-2026-021", pasaport: "U88384327", telefon: "+90 555 555 55 55", email: "djbmdy@gmail.com", puan: 85 },
       { id: 22, ad: "Can Yiğit Deveci", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "MAN-2026-022", pasaport: "U35459456", telefon: "+90 555 555 55 55", email: "canyigitdeveci@gmail.com", puan: 87 },
       { id: 23, ad: "Emrah Ocak", meslek: "Kurye", durumId: 5, lokasyon: "Ordo", basvuruNo: "AUG-2026-023", pasaport: "U26894356", telefon: "+90 555 555 55 55", email: "ocakemrah052@gmail.com", puan: 90 },
       { id: 24, ad: "Turgay Yiğit", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "WIE-2026-024", pasaport: "U88024920", telefon: "+90 555 555 55 55", email: "turgayygt35@gmail.com", puan: 93 },
       { id: 25, ad: "Orkun Misket", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Aydın", basvuruNo: "GEL-2026-025", pasaport: "U38466149", telefon: "+90 555 555 55 55", email: "orkunmisket@gmail.com", puan: 88 },
       { id: 26, ad: "Enes Uzun", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstabul", basvuruNo: "MON-2026-026", pasaport: "U24465019", telefon: "+90 555 555 55 55", email: "muhammedhamza5555@gmail.com", puan: 82 },
       { id: 27, ad: "Uğur Küçükhurman", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Manisa", basvuruNo: "BRA-2026-027", pasaport: "U23716873", telefon: "+90 555 555 55 55", email: "ugur_kucuk_hurman@hotmail.com", puan: 84 },
       { id: 28, ad: "Cabbar Balkır", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "CHE-2026-028", pasaport: "U88277528", telefon: "+90 555 555 55 55", email: "cabbarbalkir01@gmail.com", puan: 86 },
       { id: 29, ad: "Erdal Arslan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adıyaman", basvuruNo: "KIE-2026-029", pasaport: "U38115169", telefon: "+90 555 555 55 55", email: "yasin.arslan02@hotmail.com", puan: 88 },
       { id: 30, ad: "Yılmaz Akdeniz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "MAG-2026-030", pasaport: "U29596300", telefon: "+90 555 555 55 55", email: "akdenizyilmaz1@gmail.com", puan: 90 },
       { id: 31, ad: "Muhammed Kürşad Demirci", meslek: "Kurye", durumId: 5, lokasyon: "Sivas", basvuruNo: "OBE-2026-031", pasaport: "U33945199", telefon: "+90 555 555 55 55", email: "kursqd.arslan@outlook.com", puan: 85 },
       { id: 32, ad: "Onur Orhan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Kocaeli", basvuruNo: "LUB-2026-032", pasaport: "U88013159", telefon: "+90 555 555 55 55", email: "okyanustabirdamla34@gmail.com", puan: 86 },
       { id: 33, ad: "Alper Gümüş", meslek: "Kurye", durumId: 5, lokasyon: "Denizli", basvuruNo: "FRE-2026-033", pasaport: "U36125073", telefon: "+90 555 555 55 55", email: "alperengumus@hotmail.com", puan: 89 },
       { id: 34, ad: "Ferhat Konuk", meslek: "Kurye", durumId: 5, lokasyon: "İzmir", basvuruNo: "HAG-2026-034", pasaport: "U34437396", telefon: "+90 555 555 55 55", email: "ferhatkonuk35@hotmail.com", puan: 86 },
       { id: 35, ad: "Buket Atasayar", meslek: "Kurye", durumId: 5, lokasyon: "Bursa", basvuruNo: "ROS-2026-035", pasaport: "U30862420", telefon: "+90 555 555 55 55", email: "buketatasayar10@gmail.com", puan: 83 },
       { id: 36, ad: "Ahmet Adın", meslek: "Kurye", durumId: 5, lokasyon: "Niğde", basvuruNo: "KAS-2026-036", pasaport: "U37396044", telefon: "+90 555 555 55 55", email: "ahmetadin62@gmail.com", puan: 91 },
       { id: 37, ad: "Alper Koptur", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "SAA-2026-037", pasaport: "U27276436", telefon: "+90 555 555 55 55", email: "alperkoptur06@gmail.com", puan: 88 },
       { id: 38, ad: "Ramazan Gökhan Kına", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "HAM-2026-038", pasaport: "U36187035", telefon: "+90 555 555 55 55", email: "kina.gokhann@hotmail.com", puan: 87 },
       { id: 39, ad: "Yasin Kavak", meslek: "Kurye", durumId: 5, lokasyon: "Konya", basvuruNo: "MUL-2026-039", pasaport: "U37950988", telefon: "+90 555 555 55 55", email: "yasin1453442@gmail.com", puan: 84 },
       { id: 40, ad: "Kaan Özkal", meslek: "Kurye", durumId: 4, lokasyon: "Ankara", basvuruNo: "MUL-2026-040", pasaport: "U12345678", telefon: "+90 555 555 55 55", email: "ozkalkaan490@gmail.com", puan: 100 },
       { id: 41, ad: "Osman Çakmak", meslek: "Tır Şoförü", durumId: 7, lokasyon: "İzmir", basvuruNo: "BER-2026-041", pasaport: "U26401554", telefon: "+90 542 655 70 70", email: "cel130ce@gmail.com", puan: 89 },
       { id: 42, ad: "Mehmet Hıdır Kılıç", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "BER-2026-042", pasaport: "U12345679", telefon: "+90 534 238 79 47", email: "kilicmehmethidir@gmail.com", puan: 88 },
       { id: 43, ad: "Doğukan Yıldız", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Ankara", basvuruNo: "BER-2026-043", pasaport: "U12345680", telefon: "+90 544 364 42 06", email: "dogukanyildizxii@gmail.com", puan: 87 },
        { id: 44, ad: "Süheyl Selçuk Çakır", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Ankara", basvuruNo: "BER-2026-044", pasaport: "U20165209", telefon: "+90 536 749 66 46", email: "selcuk3010@gmail.com", puan: 93 },
        { id: 45, ad: "Gökhan Taçyıldız", meslek: "Tır Şoförü", durumId: 8, lokasyon: "Almanya", basvuruNo: "BER-2026-045", pasaport: "U36684821", telefon: "+90 545 717 28 85", email: "tacyildiz_31b0510@hotmail.com", puan: 88 },
        { id: 46, ad: "Salih Atasoy", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Almanya", basvuruNo: "BER-2026-046", pasaport: "U37558617", telefon: "+90 532 359 81 96", email: "slhatasoy84@gmail.com", puan: 87 },
        { id: 47, ad: "Erçin Üzüm", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Almanya", basvuruNo: "BER-2026-047", pasaport: "U31056981", telefon: "+90 536 212 03 02", email: "ercin_uzum@live.com", puan: 86 },
        { id: 48, ad: "Celalettin Akselek", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Almanya", basvuruNo: "BER-2026-048", pasaport: "U33998167", telefon: "+90 506 500 42 83", email: "celalnursah@gmail.com", puan: 85 },
        { id: 49, ad: "Veysel Kadir Dayı", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Elazığ", basvuruNo: "BER-2026-049", pasaport: "U25255845", telefon: " +90 532 695 69 99", email: "veysel.dayi@gmail.com", puan: 84 },
        { id: 50, ad: "Mustafa Alyelken", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Almanya", basvuruNo: "BER-2026-050", pasaport: "U33146095", telefon: "+90 507 331 48 24", email: "mustafaalyelkenn@gmail.com", puan: 83 },
        { id: 51, ad: "Enver Öcal", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Almanya", basvuruNo: "BER-2026-051", pasaport: "S36583645", telefon: "+90 541 549 98 28", email: "enverocal@hotmail.com", puan: 82 },
        { id: 52, ad: "Şaban Ögel", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Ankara", basvuruNo: "BER-2026-052", pasaport: "U31501597", telefon: "+90 541 791 34 47", email: "ogel_saban@hotmail.com", puan: 81 },
        { id: 53, ad: "Mehmet Baran Konar", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Elazığ", basvuruNo: "BER-2026-053", pasaport: "U39868578", telefon: "+90 535 774 2528", email: "barankonar23@icloud.com", puan: 81 },
        { id: 54, ad: "Enuş Demir", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Diyarbakır", basvuruNo: "BER-2026-054", pasaport: "U39719038", telefon: "+90 535 609 7521", email: "umittergul@gmail.com", puan: 81 },
        { id: 55, ad: "Derviş Kına", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "BER-2026-055", pasaport: "U24608138", telefon: "+90 532 466 4047", email: "derviskina47@icloud.com", puan: 81 },
        { id: 56, ad: "İsmail Baran Karasu", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Bursa", basvuruNo: "BER-2026-056", pasaport: "U34678907", telefon: "+90 552 789 0416", email: "ismailbaran04@gmail.com", puan: 81 },
        { id: 57, ad: "Harun Reşit", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Gaziantep", basvuruNo: "BER-2026-057", pasaport: "U88315558", telefon: "+90 538 202 10 72", email: " harunresitoksuz@gmail.com", puan: 81 },
        { id: 58, ad: "Hasan Burak Ergiçay", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adıyaman", basvuruNo: "BER-2026-058", pasaport: "U35195909", telefon: "+90 538 777 86 56", email: "burakergicay@hotmail.com", puan: 81 },
        { id: 59, ad: "Hasan Burak Ergiçay", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adıyaman", basvuruNo: "BER-2026-058", pasaport: "U35195909", telefon: "+90 538 777 86 56", email: "burakergicay@hotmail.com", puan: 81 },
        {id: 60, ad: "Melih Çopuroğlu", meslek: "Tır Şoförü", durumId: 8, lokasyon: "Almanya", basvuruNo: "BER-2026-060", pasaport: "U32999180", telefon: "+90 555 555 55 55", email: "melih.copuroglu@gmail.com", puan: 90 }
    ];

    const stageMap = { 4: "Vize Ön Onay", 5: "Vize Başvurusu" };

    const formattedCandidates = rawData.map(item => {
        const parts = item.ad.trim().split(' ');
        const lastName = parts.pop();
        const firstName = parts.join(' ');
        const email = item.email === "@email.com" 
            ? `${firstName.toLowerCase().replace(/\s/g,'.')}.${lastName.toLowerCase()}@berliner.com`
            : item.email;

        return {
            firstName: firstName,
            lastName: lastName,
            passportNo: item.pasaport,
            email: email,
            phone: item.telefon,
            job: item.meslek,
            location: item.lokasyon,
            currentStage: stageMap[item.durumId] || "Başvuru Alındı",
            applicationDate: new Date(),
            password: "123456"
        };
    });

    try {
        await Candidate.deleteMany({});
        await Candidate.insertMany(formattedCandidates);
        res.send('✅ Adaylar yüklendi!');
    } catch (error) {
        res.send("Hata: " + error.message);
    }
});

app.get('/puanlari-duzelt', adminAuthCheck, async (req, res) => {
    try {
        await Candidate.updateMany({}, { $set: { score: 90 } });
        res.send('<h1>✅ herkes 90 puan oldu </h1><a href="/admin">Panele Dön</a>');
    } catch (error) {
        res.send("Hata: " + error.message);
    }
});

app.get('/cv-builder', authCheck, (req, res) => {
    res.render('cv_builder', { user: req.user, page: 'cv-builder' });
});

app.post('/cv-builder/save', authCheck, upload.single('photo'), async (req, res) => {
    try {
        const body = req.body;

        let profilePhoto = req.user.cvDetails?.profilePhoto || "";
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString('base64');
            profilePhoto = `data:${req.file.mimetype};base64,${b64}`;
        }

        let processedLanguages = body.languages;
        if (Array.isArray(body.languages)) {
            processedLanguages = body.languages.join(', ');
        }

        const cvData = {
            profilePhoto,
            email: body.email || req.user.email,
            phone: body.phone || req.user.phone,
            address: body.address || req.user.location,
            birthDate: body.birthDate,
            nationality: body.nationality,
            drivingLicense: body.drivingLicense,
            linkedin: body.linkedin,
            
            summary: body.summary,
            skills: body.skills,
            languages: processedLanguages,
            technicalSkills: body.technicalSkills,
            softSkills: body.softSkills,

            experience1: { 
                title: body.exp1_title, company: body.exp1_company, 
                date: body.exp1_date, location: body.exp1_location, desc: body.exp1_desc 
            },
            experience2: { 
                title: body.exp2_title, company: body.exp2_company, 
                date: body.exp2_date, location: body.exp2_location, desc: body.exp2_desc 
            },

            exp_additional_title: body.exp_additional_title,
            exp_additional_company: body.exp_additional_company,
            exp_additional_date: body.exp_additional_date,
            exp_additional_location: body.exp_additional_location,
            exp_additional_desc: body.exp_additional_desc,

            education1: { 
                school: body.edu1_school, degree: body.edu1_degree, 
                date: body.edu1_date, location: body.edu1_location, achievements: body.edu1_achievements 
            },

            edu_additional_school: body.edu_additional_school,
            edu_additional_degree: body.edu_additional_degree,
            edu_additional_date: body.edu_additional_date,
            edu_additional_location: body.edu_additional_location,

            certificate1: body.certificate1,
            certificate1_issuer: body.certificate1_issuer,
            certificate1_date: body.certificate1_date,
            certificate1_validity: body.certificate1_validity,

            cert_additional_name: body.cert_additional_name,
            cert_additional_issuer: body.cert_additional_issuer,
            cert_additional_date: body.cert_additional_date,
            cert_additional_validity: body.cert_additional_validity,

            reference1_name: body.reference1_name,
            reference1_position: body.reference1_position,
            reference1_company: body.reference1_company,
            reference1_contact: body.reference1_contact,

            cvColor: body.cvColor || '#0f172a',
            themeName: body.themeName || 'Koyu Profesyonel'
        };

        await Candidate.findByIdAndUpdate(req.user._id, {
            $set: { cvDetails: cvData }
        });

        res.redirect('/cv-builder?status=saved');
        
    } catch (error) {
        console.error('CV kaydetme hatası:', error);
        res.redirect('/cv-builder?status=error');
    }
});
app.get('/cv-print', authCheck, (req, res) => {
    res.render('cv_print', { user: req.user });
});
app.get('/application-form', authCheck, (req, res) => {
    res.render('application_form', { user: req.user });
});
// --- BAŞVURU FORMU KAYDET & İNDİR (MODERN TASARIM v2) ---
app.post('/application-form/save', authCheck, async (req, res) => {
    try {
        const formData = req.body;

        await Candidate.findByIdAndUpdate(req.user._id, { applicationForm: formData });

        const doc = new PDFDocument({ margin: 0, size: 'A4', bufferPages: true });
        const fileName = `Basvuru_${req.user.firstName}_${req.user.lastName}.pdf`;
        const filePath = path.join(__dirname, '../public/uploads', fileName);

        if (!fs.existsSync(path.join(__dirname, '../public/uploads'))) {
            fs.mkdirSync(path.join(__dirname, '../public/uploads'), { recursive: true });
        }

        const fileStream = fs.createWriteStream(filePath);
        doc.pipe(fileStream);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        doc.pipe(res);

        const colors = {
            primary: '#4f46e5', 
            secondary: '#1e293b', 
            lightBg: '#f8fafc', 
            border: '#e2e8f0',  
            white: '#ffffff'
        };

        const cleanText = (text) => {
            if (!text) return 'Belirtilmedi';
            return text.trim()
                .replace(/ğ/g, 'g').replace(/Ğ/g, 'G')
                .replace(/ş/g, 's').replace(/Ş/g, 'S')
                .replace(/ı/g, 'i').replace(/İ/g, 'I')
                .replace(/ö/g, 'o').replace(/Ö/g, 'O')
                .replace(/ç/g, 'c').replace(/Ç/g, 'C')
                .replace(/ü/g, 'u').replace(/Ü/g, 'U');
        };

        const drawHeader = () => {
            doc.rect(0, 0, 595.28, 100).fill(colors.primary);
            
            doc.font('Helvetica-Bold').fontSize(22).fill(colors.white)
               .text('BASVURU VE MOTIVASYON FORMU', 50, 35);
            
            doc.font('Helvetica').fontSize(12).fill(colors.white)
               .text(`Aday: ${cleanText(req.user.firstName)} ${cleanText(req.user.lastName)}`, 50, 65);
            
            doc.text(`Tarih: ${new Date().toLocaleDateString('tr-TR')}`, 450, 65, { align: 'right' });
        };

        const drawFooter = (pageNumber) => {
            const bottom = 800;
            doc.moveTo(50, bottom).lineTo(545, bottom).strokeColor(colors.border).stroke();
            doc.fontSize(8).fill(colors.secondary)
               .text('BERLINER - Resmi Basvuru Belgesidir', 50, bottom + 10);
            doc.text(`Sayfa ${pageNumber}`, 500, bottom + 10, { align: 'right' });
        };

        const drawSectionTitle = (title) => {
            doc.moveDown(1.5);
            const y = doc.y;
            doc.rect(50, y, 5, 20).fill(colors.primary);
            doc.fontSize(14).font('Helvetica-Bold').fill(colors.primary)
               .text(title.toUpperCase(), 65, y + 2);
            doc.moveDown(0.5);
        };

        const drawField = (label, value) => {
            if (doc.y > 720) {
                doc.addPage();
                drawHeader();
                doc.y = 120; 
            }

            const startY = doc.y;
            const content = cleanText(value);
            
            doc.fontSize(9).font('Helvetica-Bold').fill('#64748b').text(label, 50, startY);
            
            const boxTop = doc.y + 5;
            
            doc.fontSize(11).font('Helvetica');
            const textHeight = doc.heightOfString(content, { width: 470 });
            const boxHeight = textHeight + 20;

            doc.roundedRect(50, boxTop, 495, boxHeight, 5).fill(colors.lightBg);
            
            doc.fill(colors.secondary).text(content, 62, boxTop + 10, { width: 470 });
            
            doc.y = boxTop + boxHeight + 15;
        };

        drawHeader();
        doc.y = 120; 

        drawSectionTitle('A. Kisisel Bilgiler');
        drawField('Dogum Yeri ve Tarihi', formData.birthPlace);
        drawField('Medeni Hali', formData.maritalStatus);
        drawField('Adres / Iletisim', formData.address);
        drawField('Askerlik Durumu', formData.militaryService);
        drawField('Surucu Belgesi Sinifi', formData.drivingLicenseClass);

        drawSectionTitle('B. Egitim ve Is Gecmisi');
        drawField('Mezun Olunan Lise', formData.highSchool);
        drawField('Mezun Olunan Yuksekokul', formData.university);
        drawField('Gecmis Is Tecrubeleri', formData.workHistory);

        drawSectionTitle('C. Mesleki Motivasyon');
        drawField('Meslegin Anlami', formData.meaningOfJob);
        drawField('Bir Calisma Gunu', formData.dailyRoutine);
        drawField('Almanya Istegi', formData.germanyDesire);
        drawField('Turkiye-Almanya Farklari', formData.definitionDiff);
        drawField('Karsilasilacak Zorluklar', formData.challenges);
        drawField('Dilin Onemi', formData.languageImportance);
        drawField('Almanya\'daki Tanidiklar', formData.friendsInGermany);

        drawSectionTitle('D. Almanca Dil Bilgisi');
        drawField('Mevcut Seviye', formData.germanLevel);
        drawField('Egitim Yeri', formData.germanEducationPlace);
        drawField('Seviye Farkindaligi', formData.levelAwareness);
        drawField('Ogrenme Plani', formData.languagePlan);
        drawField('Kurs Butcesi', formData.budgetForCourse);
        drawField('Aile Dil Durumu', formData.familyLanguage);

        drawSectionTitle('E. Almanya Vizyonu');
        drawField('Goc Dusuncesi', formData.migrationTime);
        drawField('Sehir Tercihi', formData.cityChoice);
        drawField('Sehir Esnekligi', formData.cityFlexibility);
        drawField('Uzmanlik Alani', formData.expertiseArea);
        drawField('Almanya Bilgisi', formData.germanyKnowledge);
        drawField('Aile Plani', formData.familyBring);
        drawField('Konaklama', formData.accommodation);
        drawField('Goc Butcesi', formData.migrationBudget);
        drawField('Ziyaret Gecmisi', formData.visitHistory);

        drawSectionTitle('F. BERLINER ');
        drawField('Tanisma Hikayesi', formData.berlinerMeet);
        drawField('Guven Dusuncesi', formData.berlinerTrust);

        const range = doc.bufferedPageRange();
        for (let i = 0; i < range.count; i++) {
            doc.switchToPage(i);
            drawFooter(i + 1);
        }

        doc.end();

        fileStream.on('finish', async () => {
            await Candidate.findByIdAndUpdate(req.user._id, {
                $push: { 
                    uploadedDocuments: { 
                        name: 'Resmi Başvuru Formu', 
                        path: fileName, 
                        date: new Date() 
                    } 
                }
            });
        });

    } catch (error) {
        console.error('PDF Hatası:', error);
        res.redirect('/application-form?error=pdf_failed');
    }
});

app.get('/seed-german', adminAuthCheck, async (req, res) => {
    try {
        const sentences = [
            { 
                german: "Fracht", 
                turkish: "Yük / Kargo", 
                category: "Lojistik",
                exampleGerman: "Die Fracht muss pünktlich sein.", 
                exampleTurkish: "Yük zamanında olmalı." 
            },
            { 
                german: "Gabelstapler", 
                turkish: "Forklift", 
                category: "Depo",
                exampleGerman: "Der Gabelstapler hebt die schwere Palette.", 
                exampleTurkish: "Forklift ağır paleti kaldırıyor." 
            },
            { 
                german: "Spiegel einstellen", 
                turkish: "Aynaları ayarlamak", 
                category: "Araç",
                exampleGerman: "Stellen Sie die Spiegel vor der Fahrt ein.", 
                exampleTurkish: "Sürüşten önce aynaları ayarlayın." 
            },
            { 
                german: "Polizei", 
                turkish: "Polis", 
                category: "Acil",
                exampleGerman: "Rufen Sie bitte die Polizei.", 
                exampleTurkish: "Lütfen polisi arayın." 
            },
            { 
                german: "Erste-Hilfe", 
                turkish: "İlk Yardım", 
                category: "Acil",
                exampleGerman: "Wo ist der Erste-Hilfe-Kasten?", 
                exampleTurkish: "İlk yardım çantası nerede?" 
            },
            { 
                german: "Ausfahrt", 
                turkish: "Çıkış", 
                category: "Trafik",
                exampleGerman: "Nehmen Sie die nächste Ausfahrt.", 
                exampleTurkish: "Bir sonraki çıkıştan çıkın." 
            }
        ];

        if (mongoose.models.LogisticsWord) {
            await mongoose.model('LogisticsWord').deleteMany({});
            await mongoose.model('LogisticsWord').insertMany(sentences);
        }

        res.send(`
            <div style="text-align:center; padding:50px; font-family:sans-serif;">
                <h1 style="color:green;">✅ Almanca Veriler Güncellendi!</h1>
                <p>Eklenen Cümle Sayısı: ${sentences.length}</p>
                <p style="color:gray;">"Stellen Sie die Spiegel..." cümlesi eklendi.</p>
                <br>
                <a href="/german" style="background:#333; color:white; padding:10px 20px; text-decoration:none; border-radius:5px;">Sayfaya Dön</a>
            </div>
        `);

    } catch (error) {
        res.send("Hata: " + error.message);
    }
});
app.get('/life-in-germany', authCheck, (req, res) => {
    
    const trafficSigns = [
        { 
            title: "Vorfahrt gewähren", 
            desc: "Yol Ver! Ana yoldan gelen araca kesinlikle yol vermelisiniz.", 
            image: "/images/traffic/yolver.jpg" 
        },
        { 
            title: "Vorfahrtstraße", 
            desc: "Geçiş Üstünlüğü. Bu sarı baklava dilimini görüyorsan yol senindir.", 
            image: "/images/traffic/gecisustunlugu.jpg" 
        },
        { 
            title: "Einbahnstraße", 
            desc: "Tek Yön. Ok yönünün tersine girmek yasaktır.", 
            image: "/images/traffic/tekyon.jpg" 
        },
        { 
            title: "Stop", 
            desc: "DUR! Tekerlekler tam olarak durmalı (3 saniye kuralı).", 
            image: "/images/traffic/stop.jpg" 
        },
        { 
            title: "Absolutes Halteverbot", 
            desc: "Duraklamak ve Park Etmek Yasaktır.", 
            image: "/images/traffic/yasak.png" 
        },
        { 
            title: "Umweltzone", 
            desc: "Çevre Bölgesi. Yeşil etiketi olmayan araç giremez.", 
            image: "/images/traffic/cevrebolgesi.webp" 
        },
        { 
            title: "Autobahn", 
            desc: "Otoban. Hız sınırı genelde yoktur ama önerilen hız 130 km/s'dir.", 
            image: "/images/traffic/hiz.jpeg" 
        },
        { 
            title: "Spielstraße", 
            desc: "Oyun Sokağı. Araçlar adım hızında (7 km/s) gitmek zorundadır.", 
            image: "/images/traffic/oyun.png" 
        },
        { 
            title: "Ende aller Streckenverbote", 
            desc: "Tüm kısıtlamaların sonu (tüm önceki hız ve yasaklar sona erer)", 
            image: "/images/traffic/nolimit.webp" 
        },
        { 
            title: "Mindestgeschwindigkeit", 
            desc: "Asgari hız limiti – belirlenen minimum hız zorunluluğu (örneğin mavi daire içinde sayı)", 
            image: "/images/traffic/asgerihiz.png" 
        },
        { 
            title: "Umleitung", 
            desc: "Alternatif/kaçış yolu (özellikle otoyolda, “U” ile numaralı geçici ya da kalıcı sapma rotası).", 
            image: "/images/traffic/kacis.jpg" 
        },
    ];

    const unwrittenRules = [
        { title: "Pazar Sessizliği (Sonntagsruhe)", desc: "Pazar günleri kutsaldır. Matkap çalıştırmak, çim biçmek, gürültülü temizlik yapmak veya cam şişeleri dışarıdaki kumbaraya atmak komşular tarafından polise şikayet sebebidir." },
        { title: "Selektör Yapmak (Lichthupe) ⚠️", desc: "Çok Dikkat! Türkiye'de selektör 'Çekil yol benim' demektir. Almanya'da ise tam tersi 'Buyur geç, sana yol veriyorum' demektir. Otobanda öndekine sürekli selektör yapmak suçtur (Nötigung - Taciz)." },
        { title: "Sarı Melekler (ADAC)", desc: "Almanya'da yolda kalırsanız çekici masrafı çok yüksektir. Bu yüzden neredeyse herkes 'Sarı Melekler' olarak bilinen ADAC'a üyedir. Arıza durumunda her yere gelirler." },
        { title: "Kavşak İçi Boş Kalmalı (Kreuzung freihalten) 🚦", desc: "Çok Önemli! Size yeşil ışık yansa bile, eğer gideceğiniz yol tıkalıysa kavşağın ortasına asla girmeyin. Trafik açılana kadar çizginin gerisinde bekleyin. Kavşağı tıkamak büyük saygısızlıktır." },
        { title: "Kırmızı Işık Kuralı", desc: "Gece saat 03:00 olsa ve hiç araba geçmese bile yaya kırmızı ışığında BEKLENİR. Özellikle yanınızda çocuk varsa geçmek büyük ayıptır." },
        { title: "Nakit Kraldır (Nur Bares)", desc: "Her yerde kredi kartı geçmez. Fırınlar, büfeler (Imbiss) ve bazı restoranlar sadece nakit (Bargeld) kabul eder. Yanınızda hep Euro taşıyın." },
        { title: "Dakiklik (Pünktlichkeit)", desc: "Almanya'da '5 dakika geç kalmak' diye bir şey yoktur. Randevu 10:00'da ise 09:55'te orada olmalısınız." },
        { title: "Doğum Günü Pastası", desc: "Türkiye'nin aksine, Almanya'da doğum günü olan kişi arkadaşlarına pasta veya yemek ısmarlar. " },
        { title: "Havalandırma (Stoßlüften)", desc: "Almanlar temiz havaya takıntılıdır. Kışın ortasında bile pencereleri sonuna kadar açıp 5-10 dakika evi havalandırırlar (Stoßlüften)." },
        { title: "Selamlaşma ve Göz Teması", desc: "Biriyle el sıkışırken mutlaka gözlerinin içine bakın. Göz kaçırmak güvensizlik veya saklanan bir şey varmış gibi algılanır." },
    ];

    const practicalInfo = [
        { title: "Pfand (Depozito)", desc: "Şişeleri atmayın! Marketlerdeki makinelere atıp para fişi alın.", icon: "recycle" },
        { title: "Posta Kutusu İsmi", desc: "Posta kutusuna soyadınızı yapıştırmazsanız banka kartınız dahil hiçbir mektup gelmez.", icon: "mail-bulk" },
        { title: "Çöp Ayrıştırma", desc: "Sarı (Plastik), Mavi (Kağıt), Kahverengi (Bio). Yanlış atarsanız ceza yiyebilirsiniz.", icon: "trash-alt" },
        { title: "Radyo Vergisi", desc: "Eve taşınınca TV'niz olmasa bile aylık Radyo Vergisi (GEZ) ödemek zorundasınız.", icon: "tv" },
        { title: "Musluk Suyu", desc: "Musluk suyu içilebilir. Restoranda su paralıdır ve genelde gazlı (Sprudel) gelir.", icon: "faucet" },
        { title: "Bisiklet Yolları", desc: "Kaldırımdaki kırmızı alana basmayın, bisiklet yolu yayalar için değildir.", icon: "bicycle" }
    ];

    res.render('life_germany', {
        user: req.user,
        page: 'life_germany',
        trafficSigns,
        unwrittenRules,
        practicalInfo
    });
});
// --- PORT ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Sunucu ${PORT} portunda çalışıyor`);
});