const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const nodemailer = require('nodemailer');
const path = require('path');
const { google } = require('googleapis');
const stream = require('stream');
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
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB Limit
});
// --- GOOGLE DRIVE YÜKLEME FONKSİYONU ---
const uploadToGoogleDrive = async (fileObject) => {
    try {
        const auth = new google.auth.GoogleAuth({
            credentials: JSON.parse(process.env.GOOGLE_CREDENTIALS), // Render'dan oku
            scopes: ['https://www.googleapis.com/auth/drive.file'],
        });
        const driveService = google.drive({ version: 'v3', auth });

        const bufferStream = new stream.PassThrough();
        bufferStream.end(fileObject.buffer);

        const response = await driveService.files.create({
            media: {
                mimeType: fileObject.mimetype,
                body: bufferStream,
            },
            requestBody: {
                name: fileObject.originalname,
                parents: [process.env.DRIVE_FOLDER_ID], // Render'daki Klasör ID
            },
            fields: 'id, name, webViewLink',
        });

        return response.data; // { id: '...', webViewLink: '...' }
    } catch (error) {
        console.error('Drive Yükleme Hatası:', error);
        throw error;
    }
};

// --- BREVO (SENDINBLUE) MAİL AYARLARI (GÜÇLENDİRİLMİŞ) ---
const transporter = nodemailer.createTransport({
    host: 'smtp-relay.brevo.com',
    port: 2525, // 587 yerine 2525 deneyelim (Alternatif port)
    secure: false, 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS
    },
    // 👇 HATAYI ÇÖZECEK SİHİRLİ KODLAR 👇
    family: 4, // Sadece IPv4 kullan (Render hatasını çözer)
    connectionTimeout: 10000, // 10 saniye bekle
    greetingTimeout: 5000 // Selamlaşma için 5 saniye bekle
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

    try {
        console.log("Drive'a yükleniyor...");
        const driveFile = await uploadToGoogleDrive(req.file);
        
        // Veritabanına dosyanın Drive Linkini kaydediyoruz
        await Candidate.findByIdAndUpdate(req.user._id, { 
            $push: { 
                documents: { 
                    name: req.body.docType, 
                    filename: driveFile.name, // Dosya adı
                    driveLink: driveFile.webViewLink, // Tıklanabilir link
                    fileId: driveFile.id, 
                    status: 'İnceleniyor', 
                    date: new Date() 
                } 
            } 
        });
        
        res.redirect('/documents');
    } catch (error) {
        res.send("Dosya yüklenirken hata oluştu: " + error.message);
    }
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

// --- GÜÇLENDİRİLMİŞ MAİL GÖNDERME ROTASI ---
app.post('/admin/message/email', adminAuthCheck, async (req, res) => {
    try {
        console.log("📨 Mail gönderimi başlatılıyor...");
        
        // 1. Adayı bul
        const candidate = await Candidate.findById(req.body.candidateId);
        
        if (!candidate) {
            console.log("❌ Aday bulunamadı.");
            return res.redirect('/admin?error=aday_yok');
        }

        if (!candidate.email) {
            console.log("❌ Adayın mail adresi yok.");
            return res.redirect('/admin?error=mail_yok');
        }

        // 2. Maili gönder
        await transporter.sendMail({
            from: `"Almanya Kariyer" <${process.env.EMAIL_USER}>`,
            to: candidate.email,
            subject: req.body.subject || 'Bilgilendirme',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd;">
                    <h2 style="color: #333;">Sayın ${candidate.firstName} ${candidate.lastName},</h2>
                    <p style="font-size: 16px; color: #555;">${req.body.content}</p>
                    <hr>
                    <p style="font-size: 12px; color: #999;">Bu mesaj otomatik olarak gönderilmiştir.</p>
                </div>
            `
        });

        console.log(`✅ Mail başarıyla gönderildi: ${candidate.email}`);
        res.redirect('/admin?status=mail_success');

    } catch (error) {
        // BURASI ÇÖKMEYİ ENGELLER
        console.error("🚨 MAİL GÖNDERME HATASI:", error);
        // Hata olsa bile site çalışmaya devam etsin:
        res.redirect('/admin?error=mail_fail'); 
    }
});

app.get('/seed-german-words', async (req, res) => {
    await LogisticsWord.deleteMany({}); 
    // ... kelimeler ...
    res.send('✅ Kelimeler eklendi.');
});
// --- 40 KİŞİLİK TOPLU ADAY EKLEME ROTASI ---
app.get('/seed-candidates-full', async (req, res) => {
    // 1. Senin gönderdiğin ham veri
    const rawData = [
       { id: 1, ad: "Veysi Irğar", meslek: "Kurye", durumId: 5, lokasyon: "Mardin", basvuruNo: "BER-2026-001", pasaport: "U27192985", telefon: "+90 555 555 55 55", email: "veysi@email.com", puan: 85 },
       { id: 2, ad: "Umut Balkış", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Denizli", basvuruNo: "MUN-2026-002", pasaport: "U36039583", telefon: "+90 555 555 55 55", email: "umut@email.com", puan: 88 },
       { id: 3, ad: "Sami Koca", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Konya", basvuruNo: "HAM-2026-003", pasaport: "U36837917", telefon: "+90 555 555 55 55", email: "sami@email.com", puan: 90 },
       { id: 4, ad: "Mücahit Dinçer", meslek: "Tır Şoförü", durumId: 5, lokasyon: "istanbul", basvuruNo: "KOL-2026-004", pasaport: "U28059476", telefon: "+90 555 555 55 55", email: "mucahit@email.com", puan: 82 },
       { id: 5, ad: "Muammer Arslan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "FRA-2026-005", pasaport: "U38138827", telefon: "+90 555 555 55 55", email: "muammer@email.com", puan: 88 },
       { id: 6, ad: "Mehmet Ozan Özmen", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "STU-2026-006", pasaport: "U22433028", telefon: "+90 555 555 55 55", email: "mehmet.ozan@email.com", puan: 95 },
       { id: 7, ad: "Mehmet Emin Yaman", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "DUS-2026-007", pasaport: "U35565318", telefon: "+90 555 555 55 55", email: "mehmet.emin@email.com", puan: 92 },
       { id: 8, ad: "Mahmut Sürhan Karadal", meslek: "Kurye", durumId: 5, lokasyon: "Adana", basvuruNo: "DOR-2026-008", pasaport: "U23636576", telefon: "+90 555 555 55 55", email: "mahmut@email.com", puan: 90 },
       { id: 9, ad: "Kerim İpek", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Niğde", basvuruNo: "ESS-2026-009", pasaport: "U25148300", telefon: "+90 555 555 55 55", email: "kerim@email.com", puan: 85 },
       { id: 10, ad: "İsrafil Yılmaz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Mersin", basvuruNo: "LEI-2026-010", pasaport: "U88050133", telefon: "+90 555 555 55 55", email: "israfil@email.com", puan: 89 },
       { id: 11, ad: "İbrahim Can Eser", meslek: "Kurye", durumId: 5 , lokasyon: "Ankara", basvuruNo: "BRE-2026-011", pasaport: "U27946181", telefon: "+90 555 555 55 55", email: "ibrahim@email.com", puan: 99 },
       { id: 12, ad: "Halil İbrahim Aras", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Diyarbakır", basvuruNo: "DRE-2026-012", pasaport: "U37493231", telefon: "+90 555 555 55 55", email: "halil@email.com", puan: 81 },
       { id: 13, ad: "Hakan Yiğit", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adana", basvuruNo: "HAN-2026-013", pasaport: "U28910675", telefon: "+90 555 555 55 55", email: "hakan@email.com", puan: 83 },
       { id: 14, ad: "Fatih Mustafa Alıravcı", meslek: "Kurye", durumId: 5, lokasyon: "İstanbul", basvuruNo: "NUR-2026-014", pasaport: "U23981375", telefon: "+90 555 555 55 55", email: "fatih@email.com", puan: 86 },
       { id: 15, ad: "Ercan Ayata", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Osmaniye", basvuruNo: "DUI-2026-015", pasaport: "U15981690", telefon: "+90 555 555 55 55", email: "ercan@email.com", puan: 87 },
       { id: 16, ad: "Doğan Bozkurt", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Antalya", basvuruNo: "BOC-2026-016", pasaport: "U26435423", telefon: "+90 555 555 55 55", email: "dogan@email.com", puan: 91 },
       { id: 17, ad: "Burhanettin Irğar", meslek: "Kurye", durumId: 5, lokasyon: "Mardin", basvuruNo: "WUP-2026-017", pasaport: "U30274584", telefon: "+90 555 555 55 55", email: "burhanettin@email.com", puan: 84 },
       { id: 18, ad: "Ali Yılmaz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Gaziantep", basvuruNo: "BIE-2026-018", pasaport: "U32781709", telefon: "+90 555 555 55 55", email: "ali@email.com", puan: 92 },
       { id: 19, ad: "Ahmet Gök", meslek: "Kurye", durumId: 5, lokasyon: "Adana", basvuruNo: "BON-2026-019", pasaport: "U22798501", telefon: "+90 555 555 55 55", email: "ahmet@email.com", puan: 89 },
       { id: 20, ad: "Murat Koçcu", meslek: "Tır Şoförü", durumId: 4, lokasyon: "Konya", basvuruNo: "MUN-2026-020", pasaport: "U29925245", telefon: "+90 555 555 55 55", email: "murat@email.com", puan: 86 },
       { id: 21, ad: "Senai Kılıç", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Diyarbakır", basvuruNo: "KAR-2026-021", pasaport: "U88384327", telefon: "+90 555 555 55 55", email: "senai@email.com", puan: 85 },
       { id: 22, ad: "Can Yiğit Deveci", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "MAN-2026-022", pasaport: "U35459456", telefon: "+90 555 555 55 55", email: "can@email.com", puan: 87 },
       { id: 23, ad: "Emrah Ocak", meslek: "Kurye", durumId: 5, lokasyon: "Ordo", basvuruNo: "AUG-2026-023", pasaport: "U26894356", telefon: "+90 555 555 55 55", email: "emrah@email.com", puan: 90 },
       { id: 24, ad: "Turgay Yiğit", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "WIE-2026-024", pasaport: "U88024920", telefon: "+90 555 555 55 55", email: "turgay@email.com", puan: 93 },
       { id: 25, ad: "Orkun Misket", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Aydın", basvuruNo: "GEL-2026-025", pasaport: "U38466149", telefon: "+90 555 555 55 55", email: "orkun@email.com", puan: 88 },
       { id: 26, ad: "Enes Uzun", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstabul", basvuruNo: "MON-2026-026", pasaport: "U24465019", telefon: "+90 555 555 55 55", email: "enes@email.com", puan: 82 },
       { id: 27, ad: "Uğur Küçükhurman", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Manisa", basvuruNo: "BRA-2026-027", pasaport: "U23716873", telefon: "+90 555 555 55 55", email: "ugur@email.com", puan: 84 },
       { id: 28, ad: "Cabbar Balkır", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İzmir", basvuruNo: "CHE-2026-028", pasaport: "U88277528", telefon: "+90 555 555 55 55", email: "cabbar@email.com", puan: 86 },
       { id: 29, ad: "Erdal Arslan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Adıyaman", basvuruNo: "KIE-2026-029", pasaport: "U38115169", telefon: "+90 555 555 55 55", email: "erdal@email.com", puan: 88 },
       { id: 30, ad: "Yılmaz Akdeniz", meslek: "Tır Şoförü", durumId: 5, lokasyon: "İstanbul", basvuruNo: "MAG-2026-030", pasaport: "U29596300", telefon: "+90 555 555 55 55", email: "yilmaz@email.com", puan: 90 },
       { id: 31, ad: "Muhammed Kürşad Demirci", meslek: "Kurye", durumId: 5, lokasyon: "Sivas", basvuruNo: "OBE-2026-031", pasaport: "U33945199", telefon: "+90 555 555 55 55", email: "muhammed@email.com", puan: 85 },
       { id: 32, ad: "Onur Orhan", meslek: "Tır Şoförü", durumId: 5, lokasyon: "Kocaeli", basvuruNo: "LUB-2026-032", pasaport: "U88013159", telefon: "+90 555 555 55 55", email: "onur@email.com", puan: 86 },
       { id: 33, ad: "Alper Gümüş", meslek: "Kurye", durumId: 5, lokasyon: "Denizli", basvuruNo: "FRE-2026-033", pasaport: "U36125073", telefon: "+90 555 555 55 55", email: "alper@email.com", puan: 89 },
       { id: 34, ad: "Ferhat Konuk", meslek: "Kurye", durumId: 5, lokasyon: "İzmir", basvuruNo: "HAG-2026-034", pasaport: "U34437396", telefon: "+90 555 555 55 55", email: "ferhat@email.com", puan: 86 },
       { id: 35, ad: "Buket Atasayar", meslek: "Kurye", durumId: 5, lokasyon: "Bursa", basvuruNo: "ROS-2026-035", pasaport: "U30862420", telefon: "+90 555 555 55 55", email: "buket@email.com", puan: 83 },
       { id: 36, ad: "Ahmet Adın", meslek: "Kurye", durumId: 5, lokasyon: "Niğde", basvuruNo: "KAS-2026-036", pasaport: "U37396044", telefon: "+90 555 555 55 55", email: "ahmet.adin@email.com", puan: 91 },
       { id: 37, ad: "Alper Koptur", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "SAA-2026-037", pasaport: "U27276436", telefon: "+90 555 555 55 55", email: "alper.koptur@email.com", puan: 88 },
       { id: 38, ad: "Ramazan Gökhan Kına", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "HAM-2026-038", pasaport: "U36187035", telefon: "+90 555 555 55 55", email: "ramazan@email.com", puan: 87 },
       { id: 39, ad: "Yasin Kavak", meslek: "Kurye", durumId: 5, lokasyon: "Konya", basvuruNo: "MUL-2026-039", pasaport: "U37950988", telefon: "+90 555 555 55 55", email: "yasin@email.com", puan: 84 },
       { id: 40, ad: "Kaan Özkal", meslek: "Kurye", durumId: 5, lokasyon: "Ankara", basvuruNo: "MUL-2026-040", pasaport: "U12345678", telefon: "+90 555 555 55 55", email: "kaan@email.com", puan: 100 }
    ];

    // 2. Durum (Stage) Haritası (Senin 5 numaranın karşılığı)
    const stageMap = {
        4: "Vize Hazırlığı",
        5: "Vize Başvurusu" 
    };

    // 3. Veriyi dönüştür (Ad Soyad ayır, formatla)
    const formattedCandidates = rawData.map(item => {
        // İsim ayırma mantığı (Son kelime soyad, gerisi ad)
        const parts = item.ad.trim().split(' ');
        const lastName = parts.pop();
        const firstName = parts.join(' ');

        // Email boşsa otomatik oluştur
        const email = item.email === "@email.com" 
            ? `${firstName.toLowerCase().replace(/\s/g,'.')}.${lastName.toLowerCase()}@berliner.com`.replace(/ğ/g,'g').replace(/ü/g,'u').replace(/ş/g,'s').replace(/ı/g,'i').replace(/ö/g,'o').replace(/ç/g,'c')
            : item.email;

        return {
            firstName: firstName,
            lastName: lastName,
            passportNo: item.pasaport,
            email: email,
            phone: item.telefon,
            job: item.meslek,
            location: item.lokasyon,
            currentStage: stageMap[item.durumId] || "Başvuru Alındı", // Bilinmeyen ID varsa başa atar
            applicationDate: new Date()
        };
    });

    try {
        await Candidate.insertMany(formattedCandidates);
        res.send(`<h1 style="color:green; font-family:sans-serif; text-align:center; margin-top:50px;">✅ 40 Aday Başarıyla Eklendi!</h1><p style="text-align:center"><a href="/admin">Admin Paneline Git</a></p>`);
    } catch (error) {
        console.error("Seed hatası:", error);
        res.send(`<h1 style="color:red">Hata:</h1> <p>${error.message}</p>`);
    }
});
// --- ALMANCA KELİME & CÜMLELERİ YÜKLEME ROTASI ---
app.get('/seed-german-full', async (req, res) => {
    
    // Lojistik Sektörüne Özel Kelime Listesi
    const kelimeListesi = [
        // 1. KATEGORİ: DEPO & LOJİSTİK
        { category: 'Depo', german: 'der Gabelstapler', turkish: 'Forklift', exampleGerman: 'Der Gabelstapler hebt die schwere Palette.' },
        { category: 'Depo', german: 'das Lager', turkish: 'Depo / Ardiye', exampleGerman: 'Die Ware muss im Lager sortiert werden.' },
        { category: 'Depo', german: 'die Fracht', turkish: 'Yük / Kargo', exampleGerman: 'Die Fracht ist pünktlich angekommen.' },
        { category: 'Depo', german: 'beladen', turkish: 'Yüklemek', exampleGerman: 'Wir müssen den LKW schnell beladen.' },
        { category: 'Depo', german: 'entladen', turkish: 'Boşaltmak', exampleGerman: 'Der Fahrer entlädt die Kisten an Rampe 5.' },
        { category: 'Depo', german: 'der Lieferschein', turkish: 'İrsaliye', exampleGerman: 'Bitte unterschreiben Sie den Lieferschein.' },
        { category: 'Depo', german: 'die Verpackung', turkish: 'Paketleme', exampleGerman: 'Die Verpackung ist beschädigt.' },

        // 2. KATEGORİ: ARAÇ PARÇALARI
        { category: 'Arac', german: 'der Reifen', turkish: 'Lastik', exampleGerman: 'Der rechte Vorderreifen hat wenig Luft.' },
        { category: 'Arac', german: 'der Motor', turkish: 'Motor', exampleGerman: 'Der Motor macht seltsame Geräusche.' },
        { category: 'Arac', german: 'die Bremse', turkish: 'Fren', exampleGerman: 'Die Bremsen müssen überprüft werden.' },
        { category: 'Arac', german: 'der Spiegel', turkish: 'Ayna', exampleGerman: 'Stellen Sie die Spiegel vor der Fahrt ein.' },
        { category: 'Arac', german: 'das Lenkrad', turkish: 'Direksiyon', exampleGerman: 'Halten Sie das Lenkrad mit beiden Händen.' },
        { category: 'Arac', german: 'der Tank', turkish: 'Depo (Yakıt)', exampleGerman: 'Der Tank ist fast leer, wir müssen tanken.' },
        { category: 'Arac', german: 'das Nummernschild', turkish: 'Plaka', exampleGerman: 'Das Nummernschild ist schmutzig.' },

        // 3. KATEGORİ: ACİL DURUMLAR
        { category: 'Acil', german: 'der Unfall', turkish: 'Kaza', exampleGerman: 'Es gab einen Unfall auf der A7.' },
        { category: 'Acil', german: 'die Panne', turkish: 'Arıza', exampleGerman: 'Mein LKW hat eine Panne, ich brauche Hilfe.' },
        { category: 'Acil', german: 'der Notruf', turkish: 'Acil Çağrı', exampleGerman: 'Wählen Sie im Notfall die 112.' },
        { category: 'Acil', german: 'die Polizei', turkish: 'Polis', exampleGerman: 'Die Polizei kontrolliert den Verkehr.' },
        { category: 'Acil', german: 'Erste Hilfe', turkish: 'İlk Yardım', exampleGerman: 'Der Verbandskasten ist für Erste Hilfe.' },
        { category: 'Acil', german: 'Vorsicht!', turkish: 'Dikkat!', exampleGerman: 'Vorsicht! Die Straße ist glatt.' },

        // 4. KATEGORİ: TRAFİK & YOL
        { category: 'Trafik', german: 'der Stau', turkish: 'Trafik Sıkışıklığı', exampleGerman: 'Wir stehen seit einer Stunde im Stau.' },
        { category: 'Trafik', german: 'die Ausfahrt', turkish: 'Çıkış (Otoban)', exampleGerman: 'Nehmen Sie die nächste Ausfahrt rechts.' },
        { category: 'Trafik', german: 'die Umleitung', turkish: 'Yol Çalışması / Yönlendirme', exampleGerman: 'Wegen Bauarbeiten gibt es eine Umleitung.' },
        { category: 'Trafik', german: 'die Maut', turkish: 'Otoban Ücreti', exampleGerman: 'In Deutschland müssen LKWs Maut bezahlen.' },
        { category: 'Trafik', german: 'die Geschwindigkeit', turkish: 'Hız', exampleGerman: 'Beachten Sie die zulässige Geschwindigkeit.' },
        { category: 'Trafik', german: 'die Ampel', turkish: 'Trafik Işığı', exampleGerman: 'Die Ampel ist rot, bitte halten Sie an.' },
        { category: 'Trafik', german: 'rechts / links', turkish: 'Sağ / Sol', exampleGerman: 'Biegen Sie an der Kreuzung links ab.' }
    ];

    try {
        // Önce eskileri temizle (Tekrar tekrar eklenmesin diye)
        await LogisticsWord.deleteMany({});
        
        // Yenileri ekle
        await LogisticsWord.insertMany(kelimeListesi);
        
        res.send(`<h1 style="color:green; text-align:center; font-family:sans-serif; margin-top:50px;">✅ Almanca Kelimeler ve Cümleler Yüklendi!</h1><p style="text-align:center"><a href="/german">Almanca Sayfasına Git</a></p>`);
    } catch (error) {
        console.error("Kelime yükleme hatası:", error);
        res.send("Hata: " + error.message);
    }
});

// --- PORT AYARI (Render için gerekli) ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('------------------------------------------------');
    console.log(`🚀 Sunucu ${PORT} portunda çalışıyor`);
    console.log('------------------------------------------------');
});