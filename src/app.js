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

// --- YENİ MODEL: ORTAK DOSYALAR ---
const GlobalFileSchema = new mongoose.Schema({
    name: String,       // Dosya adı (Örn: Vize Rehberi)
    filename: String,   // Sunucudaki adı
    date: { type: Date, default: Date.now }
});
const GlobalFile = mongoose.model('GlobalFile', GlobalFileSchema);


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

        // 1. ÖNCE ADAYIN KLASÖRÜNÜ ARA
        const searchRes = await driveService.files.list({
            q: `mimeType='application/vnd.google-apps.folder' and name='${folderName}' and '${process.env.DRIVE_FOLDER_ID}' in parents and trashed=false`,
            fields: 'files(id, name)',
        });

        let targetFolderId;

        // 2. KLASÖR YOKSA OLUŞTUR, VARSA ID'SİNİ AL
        if (searchRes.data.files.length > 0) {
            // Klasör zaten varmış, onu kullan
            targetFolderId = searchRes.data.files[0].id;
        } else {
            // Klasör yok, yeni oluştur
            const folderMeta = {
                name: folderName,
                mimeType: 'application/vnd.google-apps.folder',
                parents: [process.env.DRIVE_FOLDER_ID] // Ana klasörün içine oluştur
            };
            const folder = await driveService.files.create({
                resource: folderMeta,
                fields: 'id'
            });
            targetFolderId = folder.data.id;
        }

        // 3. DOSYAYI O KLASÖRÜN İÇİNE YÜKLE
        const bufferStream = new stream.PassThrough();
        bufferStream.end(fileObject.buffer);

        const response = await driveService.files.create({
            media: {
                mimeType: fileObject.mimetype,
                body: bufferStream,
            },
            requestBody: {
                name: fileObject.originalname,
                parents: [targetFolderId], // <--- ARTIK ADAYIN KLASÖRÜNE GİDİYOR
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
    port: 2525, 
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

// --- SABİT VERİLER (GÜNCELLENDİ) ---
const STAGES = [
    'Başvuru Alındı', 
    'Evrak Kontrolü', 
    'Tercüme Süreci', 
    'İşveren Onayı', 
    'Vize Hazırlığı',  // <--- İŞTE EKSİK OLAN BUYDU! EKLENDİ.
    'Vize Ön Onay', 
    'Vize Başvurusu', 
    'Seyahat Planı', 
    'Almanya\'da'
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

app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
    const { firstName, lastName, passportNo } = req.body;
    const user = await Candidate.findOne({ 
        firstName: firstName.trim(), 
        lastName: lastName.trim(), 
        passportNo: passportNo.trim() 
    });
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

// --- ADMIN LOGIN ---
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

app.get('/panel', authCheck, async (req, res) => {
    const dailyWords = await LogisticsWord.aggregate([{ $sample: { size: 5 } }]);
    const messages = await Message.find({ candidateId: req.user._id }).sort({ date: -1 });
    const targetStateInfo = req.user.targetState ? STATE_DATA[req.user.targetState] : null;

    // 👇 BU SATIRI EKLE (Dosyaları Çekiyoruz)
    const globalFiles = await GlobalFile.find().sort({ date: -1 });

    // İlerleme Hesabı... (Mevcut kodların)
    const currentIndex = STAGES.indexOf(req.user.currentStage);
    let progress = 0;
    if (currentIndex !== -1) {
        progress = Math.round(((currentIndex + 1) / STAGES.length) * 110);
    }

    res.render('dashboard', { 
        user: req.user, 
        stages: STAGES, 
        dailyWords, 
        messages, 
        targetStateInfo, 
        progress,
        globalFiles, // 👈 BUNU DA RENDER İÇİNE EKLE
        page: 'panel' 
    });
});
app.get('/profile', authCheck, (req, res) => res.render('profile', { user: req.user, page: 'profile' }));

app.post('/profile/update', authCheck, async (req, res) => {
    const { email, phone, job, location, targetState } = req.body;
    await Candidate.findByIdAndUpdate(req.user._id, { email, phone, job, location, targetState });
    res.redirect('/profile?status=success');
});

app.get('/documents', authCheck, (req, res) => res.render('documents', { user: req.user, page: 'documents' }));

app.post('/documents/upload', authCheck, upload.single('file'), async (req, res) => {
    if (!req.file) return res.send('Dosya seçin.');
    try {
        // Adayın Adı ve Soyadını birleştirip klasör adı yapıyoruz
        const candidateFolderName = `${req.user.firstName} ${req.user.lastName}`;

        // Fonksiyona hem dosyayı hem de klasör adını gönderiyoruz
        const driveFile = await uploadToGoogleDrive(req.file, candidateFolderName);

        await Candidate.findByIdAndUpdate(req.user._id, { 
            $push: { 
                documents: { 
                    name: req.body.docType, 
                    filename: driveFile.name, 
                    driveLink: driveFile.webViewLink, 
                    fileId: driveFile.id, 
                    status: 'İnceleniyor', 
                    date: new Date() 
                } 
            } 
        });
        res.redirect('/documents');
    } catch (error) {
        res.send("Hata: " + error.message);
    }
});

app.get('/documents/delete/:docId', authCheck, async (req, res) => {
    await Candidate.findByIdAndUpdate(req.user._id, { $pull: { documents: { _id: req.params.docId } } });
    res.redirect('/documents');
});

// ============================================
//  DRIVE DOSYA GÖRÜNTÜLEME ROTASI (YENİ EKLENDİ)
// ============================================
app.get('/documents/view/:docId', async (req, res) => {
    // Hem admin hem aday görebilsin diye genel bir yetki kontrolü
    if (!req.session.userId && !req.session.isAdmin) {
        return res.redirect('/login');
    }

    try {
        const docId = req.params.docId;
        let fileId = null;

        // Dokümanı adaylar tablosunda ara
        const candidate = await Candidate.findOne({ "documents._id": docId }, { "documents.$": 1 });
        
        if (candidate && candidate.documents && candidate.documents.length > 0) {
            fileId = candidate.documents[0].fileId;
        }

        if (!fileId) {
            return res.status(404).send('Belge bulunamadı veya dosya kimliği eksik.');
        }

        // Google Drive Yetkilendirme
        const auth = new google.auth.OAuth2(
            process.env.CLIENT_ID,
            process.env.CLIENT_SECRET,
            process.env.GOOGLE_REDIRECT_URI
        );
        auth.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
        const driveService = google.drive({ version: 'v3', auth });

        // 1. Dosyanın MIME türünü ve adını al (Tarayıcının doğru formatta açması için)
        const fileMeta = await driveService.files.get({
            fileId: fileId,
            fields: 'mimeType, name'
        });

        // 2. Başlıkları ayarla (inline: tarayıcı içinde görüntüler, indirmeye zorlamaz)
        res.setHeader('Content-Type', fileMeta.data.mimeType);
        res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(fileMeta.data.name)}"`);

        // 3. Dosyayı Drive'dan akış (stream) olarak çek
        const response = await driveService.files.get(
            { fileId: fileId, alt: 'media' },
            { responseType: 'stream' }
        );

        // 4. İstemciye (tarayıcıya) aktar
        response.data.on('error', err => {
            console.error('Drive Stream Hatası:', err);
            if (!res.headersSent) res.status(500).send('Dosya okuma hatası.');
        }).pipe(res);

    } catch (error) {
        console.error('Dosya Görüntüleme Hatası:', error);
        res.status(500).send('Dosya görüntülenemedi: ' + error.message);
    }
});
// ============================================

app.get('/german', authCheck, async (req, res) => {
    const dailyWord = await LogisticsWord.findOne().sort({ date: -1 });
    const dailySentences = await LogisticsWord.aggregate([{ $match: { exampleGerman: { $exists: true, $ne: "" } } }, { $sample: { size: 5 } }]);
    res.render('german', { user: req.user, dailyWord, dailySentences, page: 'german' });
});

app.get('/german/category/:catName', authCheck, async (req, res) => {
    const words = await LogisticsWord.find({ category: req.params.catName });
    res.render('german_list', { user: req.user, words, categoryTitle: req.params.catName, page: 'german' });
});

// --- ADAY RANDEVU SAYFASI (CANLI İÇİN KESİN ÇÖZÜM) ---
app.get('/appointments', authCheck, async (req, res) => {
    try {
        // 1. Adayın ID'sine ait randevuları 'Appointment' (Ortak) tablosundan çekiyoruz.
        // Bu sayede Admin'in yaptığı değişiklik ANINDA buraya yansır.
        const myAppointments = await Appointment.find({ candidateId: req.user._id })
                                                .sort({ createdAt: -1 }); // En yenisi en üstte

        // 2. Sayfayı aç
        res.render('appointments', { 
            user: req.user, 
            page: 'appointments', // Sidebar'da 'active' olması için gerekli
            appointments: myAppointments 
        });
    } catch (error) {
        console.error("Randevu Sayfası Hatası:", error);
        res.redirect('/panel');
    }
});

// --- RANDEVU OLUŞTURMA (DÜZELTİLMİŞ) ---
app.post('/appointments/create', authCheck, async (req, res) => {
    try {
        console.log("Randevu oluşturuluyor...", req.body);

        // 1. ORTAK KUTUYA EKLE (Admin görsün diye)
        await Appointment.create({
            candidateId: req.user._id,
            date: req.body.date,
            time: req.body.time,
            type: req.body.type,
            status: 'Beklemede'
        });

        // 2. ADAYIN CEBİNE EKLE (Kendi panelinde görsün diye)
        await Candidate.findByIdAndUpdate(req.user._id, { 
            $push: { 
                appointments: { 
                    date: req.body.date, 
                    time: req.body.time, 
                    type: req.body.type, 
                    status: 'Beklemede', 
                    createdAt: new Date() 
                } 
            } 
        });

        res.redirect('/appointments?status=success');
    } catch (error) {
        console.error("Randevu Hatası:", error);
        res.redirect('/appointments?error=failed');
    }
});

app.get('/processes', authCheck, (req, res) => {
    const processDetails = [
        { name: 'Başvuru Alındı', time: 'Tamamlandı', icon: 'fa-file-signature', desc: 'Başvurunuz alındı.' },
        { name: 'Evrak Kontrolü', time: '1-3 Gün', icon: 'fa-search', desc: 'Belgeleriniz inceleniyor.' },
        { name: 'Tercüme Süreci', time: '3-5 Gün', icon: 'fa-language', desc: 'Yeminli tercüme yapılıyor.' },
        { name: 'İşveren Onayı', time: '1-2 Hafta', icon: 'fa-handshake', desc: 'İşveren onayı bekleniyor.' },
        { name: 'Vize Ön Onay', time: 'Değişken', icon: 'fa-stamp', desc: 'Ön onay belgesi bekleniyor.' },
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

// --- ADMIN PANELİ ---
app.get('/admin', adminAuthCheck, async (req, res) => {
    try {
        const candidates = await Candidate.find().sort({ createdAt: -1 });
        
        // Randevuları ORTAK KUTUDAN (Appointment) çekiyoruz
        const appointments = await Appointment.find({ status: 'Beklemede' })
                                              .populate('candidateId')
                                              .sort({ date: 1 });

        res.render('admin', { 
            candidates, 
            stages: STAGES, 
            appointments, // EJS'ye gönderiyoruz
            user: { firstName: 'Admin' } 
        });
    } catch (error) {
        console.error(error);
        res.render('admin_login');
    }
});

// --- ADMIN İŞLEMLERİ ---
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

// --- RANDEVU DURUMU GÜNCELLEME (TAM SENKRONİZE) ---
app.post('/admin/appointment/status', adminAuthCheck, async (req, res) => {
    try {
        const { appId, candidateId, status } = req.body;

        console.log(`🔄 Güncelleme Başladı: ID: ${appId} -> Yeni Durum: ${status}`);

        // 1. Önce Adminin Listesindeki (Ortak) Randevuyu Bul ve Güncelle
        // 'new: true' diyerek güncellenmiş halini elimize alıyoruz.
        const appointment = await Appointment.findByIdAndUpdate(appId, { status: status }, { new: true });

        if (!appointment) {
            console.log("❌ Admin tablosunda randevu bulunamadı!");
            return res.redirect('/admin?error=not_found');
        }

        // 2. Şimdi Adayın Kendi İçindeki (Gömülü) Randevuyu Bul ve Güncelle
        // Tarih ve Saat bilgisini referans alarak adayın içindeki doğru kaydı buluyoruz.
        const updateResult = await Candidate.updateOne(
            { 
                _id: candidateId, 
                "appointments.date": appointment.date, 
                "appointments.time": appointment.time 
            },
            { 
                $set: { "appointments.$.status": status } 
            }
        );

        console.log("✅ Aday Profili Güncellendi:", updateResult.modifiedCount > 0 ? "Başarılı" : "Değişiklik Yok");

        // İşlem tamam, panele dön
        res.redirect('/admin?status=appointment_updated');

    } catch (error) {
        console.error("❌ Randevu Güncelleme Hatası:", error);
        res.redirect('/admin?error=update_failed');
    }
});
app.post('/admin/message/internal', adminAuthCheck, async (req, res) => {
    await Message.create({ candidateId: req.body.candidateId, content: req.body.content, sender: 'Admin', date: new Date(), isRead: false });
    res.redirect('/admin');
});

// --- MAİL GÖNDERME ---
app.post('/admin/message/email', adminAuthCheck, async (req, res) => {
    try {
        const candidate = await Candidate.findById(req.body.candidateId);
        if (!candidate || !candidate.email) return res.redirect('/admin?error=mail_yok');

        await transporter.sendMail({
            from: '"BERLINER" <proje@berliner.com.tr>', 
            to: candidate.email,
            subject: req.body.subject || 'Bilgilendirme',
            html: `<div style="padding: 20px;"><h3>Sayın ${candidate.firstName},</h3><p>${req.body.content}</p><hr><small>BERLINER </small></div>`
        });
        res.redirect('/admin?status=mail_success');
    } catch (error) {
        res.redirect('/admin?error=mail_fail'); 
    }
});

app.post('/admin/message/email/bulk', adminAuthCheck, async (req, res) => {
    const { subject, content } = req.body;
    try {
        const candidates = await Candidate.find({ email: { $exists: true, $ne: "" } });
        if (candidates.length === 0) return res.redirect('/admin?error=no_candidates');

        const emailPromises = candidates.map(candidate => {
            return transporter.sendMail({
                from: '"BERLINER" <proje@berliner.com.tr>',
                to: candidate.email,
                subject: subject || 'Duyuru',
                html: `<div style="padding: 20px;"><h3>Sayın ${candidate.firstName},</h3><p>${content}</p><hr><small>BERLINER </small></div>`
            }).catch(err => console.error(err));
        });

        await Promise.all(emailPromises);
        res.redirect('/admin?status=bulk_mail_success');
    } catch (error) {
        res.redirect('/admin?error=bulk_mail_fail');
    }
});

// --- NOT SİSTEMİ (EKLENDİ) ---
app.post('/admin/candidate/add-note', adminAuthCheck, async (req, res) => {
    try {
        const { candidateId, noteContent } = req.body;
        if (!noteContent.trim()) return res.redirect('/admin');

        await Candidate.findByIdAndUpdate(candidateId, {
            $push: { 
                notes: { 
                    content: noteContent, 
                    date: new Date(),
                    author: 'Admin' 
                } 
            }
        });
        res.redirect('/admin?status=note_added');
    } catch (error) {
        res.redirect('/admin?error=note_failed');
    }
});

// 2. Aday Detay Sayfası (DÜZELTİLDİ)
// authCheck YERİNE adminAuthCheck KULLANIYORUZ
app.get('/admin/candidate/:id', adminAuthCheck, async (req, res) => {
    try {
        const candidateId = req.params.id;
        const candidate = await Candidate.findById(candidateId);
        
        if (!candidate) return res.send("Aday bulunamadı.");

        // Bu adaya ait randevular
        let candidateAppointments = [];
        try {
            candidateAppointments = await Appointment.find({ candidateId: candidateId }).sort({ date: 1 });
        } catch (err) {
            console.log("Randevu çekilemedi:", err.message);
        }

        // Admin olduğu için user objesini sahte gönderiyoruz (View hatası olmasın diye)
        res.render('admin_candidate_detail', { 
            user: { firstName: 'Admin', lastName: 'Panel' }, 
            candidate, 
            appointments: candidateAppointments 
        });
    } catch (error) {
        console.error("Detay Sayfası Hatası:", error);
        res.redirect('/admin');
    }
});
// ============================================
// 🔄 ESKİ DRIVE DOSYALARINI EŞLEŞTİRME ROTASI
// ============================================
app.get('/admin/sync-drive-files', adminAuthCheck, async (req, res) => {
    try {
        console.log("🔄 Drive Eşitleme Başlatılıyor...");

        // 1. Eski Projenin Kimlik Bilgileriyle Bağlan
        const oldAuth = new google.auth.OAuth2(
            process.env.OLD_CLIENT_ID,
            process.env.OLD_CLIENT_SECRET,
            process.env.GOOGLE_REDIRECT_URI
        );
        oldAuth.setCredentials({ refresh_token: process.env.OLD_REFRESH_TOKEN });
        const drive = google.drive({ version: 'v3', auth: oldAuth });

        // 2. Klasördeki Dosyaları Listele
        const response = await drive.files.list({
            q: `'${process.env.OLD_DRIVE_FOLDER_ID}' in parents and trashed = false`,
            fields: 'files(id, name, webViewLink, createdTime)',
            pageSize: 1000 // Maksimum 1000 dosya çeker
        });

        const driveFiles = response.data.files;
        if (!driveFiles || driveFiles.length === 0) {
            return res.send("Drive klasöründe dosya bulunamadı.");
        }

        // 3. Veritabanındaki Adayları Çek
        const candidates = await Candidate.find();
        let matchCount = 0;

        // 4. Eşleştirme Döngüsü
        for (const candidate of candidates) {
            // İsimleri temizle (Küçük harf, Türkçe karakter düzeltme)
            const searchName = candidate.firstName.toLowerCase().replace(/ğ/g,'g').replace(/ü/g,'u').replace(/ş/g,'s').replace(/ı/g,'i').replace(/ö/g,'o').replace(/ç/g,'c');
            const searchSurname = candidate.lastName.toLowerCase().replace(/ğ/g,'g').replace(/ü/g,'u').replace(/ş/g,'s').replace(/ı/g,'i').replace(/ö/g,'o').replace(/ç/g,'c');

            // Bu adayın ismini içeren dosyaları bul
            const matchingFiles = driveFiles.filter(file => {
                const fileName = file.name.toLowerCase().replace(/ğ/g,'g').replace(/ü/g,'u').replace(/ş/g,'s').replace(/ı/g,'i').replace(/ö/g,'o').replace(/ç/g,'c');
                return fileName.includes(searchName) || fileName.includes(searchSurname);
            });

            if (matchingFiles.length > 0) {
                // Adayın mevcut dokümanlarını kontrol et (tekrar eklememek için)
                const existingFileIds = candidate.documents.map(d => d.fileId);

                for (const file of matchingFiles) {
                    if (!existingFileIds.includes(file.id)) {
                        // Yeni dosya bulundu, ekle!
                        await Candidate.findByIdAndUpdate(candidate._id, {
                            $push: {
                                documents: {
                                    name: "Otomatik Eşleşen: " + file.name,
                                    filename: file.name,
                                    driveLink: file.webViewLink,
                                    fileId: file.id,
                                    status: 'İnceleniyor',
                                    date: file.createdTime || new Date()
                                }
                            }
                        });
                        matchCount++;
                    }
                }
            }
        }

        res.send(`
            <div style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: green;">✅ Eşitleme Tamamlandı!</h1>
                <p>Toplam <strong>${matchCount}</strong> yeni dosya adaylarla eşleştirildi.</p>
                <a href="/admin" style="background: #333; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Panele Dön</a>
            </div>
        `);

    } catch (error) {
        console.error("Sync Hatası:", error);
        res.send("Hata oluştu: " + error.message);
    }
});

// --- SEED (TOHUMLAMA) ---
app.get('/seed-candidates-full', async (req, res) => {
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
       { id: 40, ad: "Kaan Özkal", meslek: "Kurye", durumId: 4, lokasyon: "Ankara", basvuruNo: "MUL-2026-040", pasaport: "U12345678", telefon: "+90 555 555 55 55", email: "ozkalkaan490@gmail.com", puan: 100 }
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
            applicationDate: new Date()
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

// --- PUANLARI GÜNCELLEME ROTASI ---
app.get('/puanlari-duzelt', async (req, res) => {
    try {
        // Veritabanındaki HERKESİN puanını 90 yap
        await Candidate.updateMany({}, { $set: { score: 90 } });
        res.send('<h1>✅ herkes 90 puan oldu </h1><a href="/admin">Panele Dön</a>');
    } catch (error) {
        res.send("Hata: " + error.message);
    }
});
// --- CV OLUŞTURUCU ROTALARI (GÜNCELLENDİ) ---

app.get('/cv-builder', authCheck, (req, res) => {
    res.render('cv_builder', { user: req.user, page: 'cv-builder' });
});

app.post('/cv-builder/save', authCheck, upload.single('photo'), async (req, res) => {
    try {
        const body = req.body;

        // Fotoğraf İşlemleri
        let profilePhoto = req.user.cvDetails?.profilePhoto || "";
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString('base64');
            profilePhoto = `data:${req.file.mimetype};base64,${b64}`;
        }

        // Dilleri diziye veya stringe çevir
        let processedLanguages = body.languages;
        if (Array.isArray(body.languages)) {
            processedLanguages = body.languages.join(', ');
        }

        // --- VERİTABANI OBJESİ ---
        const cvData = {
            // -- Kişisel --
            profilePhoto,
            email: body.email || req.user.email,
            phone: body.phone || req.user.phone,
            address: body.address || req.user.location,
            birthDate: body.birthDate,
            nationality: body.nationality,
            drivingLicense: body.drivingLicense,
            linkedin: body.linkedin,
            
            // -- Özet & Yetenekler --
            summary: body.summary,
            skills: body.skills,
            languages: processedLanguages,
            technicalSkills: body.technicalSkills,
            softSkills: body.softSkills,

            // -- Sabit Deneyimler --
            experience1: { 
                title: body.exp1_title, company: body.exp1_company, 
                date: body.exp1_date, location: body.exp1_location, desc: body.exp1_desc 
            },
            experience2: { 
                title: body.exp2_title, company: body.exp2_company, 
                date: body.exp2_date, location: body.exp2_location, desc: body.exp2_desc 
            },

            // -- DİNAMİK EK İŞ DENEYİMLERİ (YENİ EKLENDİ) --
            // Eğer tek veri gelirse string olur, çok gelirse array olur.
            // Biz hepsini kaydediyoruz, EJS tarafında düzelteceğiz.
            exp_additional_title: body.exp_additional_title,
            exp_additional_company: body.exp_additional_company,
            exp_additional_date: body.exp_additional_date,
            exp_additional_location: body.exp_additional_location,
            exp_additional_desc: body.exp_additional_desc,

            // -- Sabit Eğitim --
            education1: { 
                school: body.edu1_school, degree: body.edu1_degree, 
                date: body.edu1_date, location: body.edu1_location, achievements: body.edu1_achievements 
            },

            // -- DİNAMİK EK EĞİTİMLER (YENİ EKLENDİ) --
            edu_additional_school: body.edu_additional_school,
            edu_additional_degree: body.edu_additional_degree,
            edu_additional_date: body.edu_additional_date,
            edu_additional_location: body.edu_additional_location,

            // -- Sertifikalar --
            certificate1: body.certificate1,
            certificate1_issuer: body.certificate1_issuer,
            certificate1_date: body.certificate1_date,
            certificate1_validity: body.certificate1_validity,

            // -- DİNAMİK EK SERTİFİKALAR (YENİ EKLENDİ) --
            cert_additional_name: body.cert_additional_name,
            cert_additional_issuer: body.cert_additional_issuer,
            cert_additional_date: body.cert_additional_date,
            cert_additional_validity: body.cert_additional_validity,

            // -- Referanslar (YENİ EKLENDİ) --
            reference1_name: body.reference1_name,
            reference1_position: body.reference1_position,
            reference1_company: body.reference1_company,
            reference1_contact: body.reference1_contact,

            // -- Tema --
            cvColor: body.cvColor || '#0f172a',
            themeName: body.themeName || 'Koyu Profesyonel'
        };

        // Veritabanını Güncelle
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

        // 1. Veritabanını Güncelle
        await Candidate.findByIdAndUpdate(req.user._id, { applicationForm: formData });

        // 2. PDF Ayarları
        const doc = new PDFDocument({ margin: 0, size: 'A4', bufferPages: true });
        const fileName = `Basvuru_${req.user.firstName}_${req.user.lastName}.pdf`;
        const filePath = path.join(__dirname, '../public/uploads', fileName);

        if (!fs.existsSync(path.join(__dirname, '../public/uploads'))) {
            fs.mkdirSync(path.join(__dirname, '../public/uploads'), { recursive: true });
        }

        // Akışları Başlat
        const fileStream = fs.createWriteStream(filePath);
        doc.pipe(fileStream);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        doc.pipe(res);

        // --- TASARIM FONKSİYONLARI ---

        // Renk Paleti
        const colors = {
            primary: '#4f46e5',   // Ana Mavi
            secondary: '#1e293b', // Koyu Gri (Yazı)
            lightBg: '#f8fafc',   // Açık Gri (Kutu Arkaplanı)
            border: '#e2e8f0',    // Çizgi Rengi
            white: '#ffffff'
        };

        // Türkçe Karakter Düzeltici
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

        // Header (Her Sayfa İçin)
        const drawHeader = () => {
            // Mavi Şerit
            doc.rect(0, 0, 595.28, 100).fill(colors.primary);
            
            // Başlık
            doc.font('Helvetica-Bold').fontSize(22).fill(colors.white)
               .text('BASVURU VE MOTIVASYON FORMU', 50, 35);
            
            // Alt Başlık (Aday İsmi)
            doc.font('Helvetica').fontSize(12).fill(colors.white)
               .text(`Aday: ${cleanText(req.user.firstName)} ${cleanText(req.user.lastName)}`, 50, 65);
            
            doc.text(`Tarih: ${new Date().toLocaleDateString('tr-TR')}`, 450, 65, { align: 'right' });
        };

        // Footer (Sayfa Altı)
        const drawFooter = (pageNumber) => {
            const bottom = 800;
            doc.moveTo(50, bottom).lineTo(545, bottom).strokeColor(colors.border).stroke();
            doc.fontSize(8).fill(colors.secondary)
               .text('Berliner - Resmi Basvuru Belgesidir', 50, bottom + 10);
            doc.text(`Sayfa ${pageNumber}`, 500, bottom + 10, { align: 'right' });
        };

        // Bölüm Başlığı
        const drawSectionTitle = (title) => {
            doc.moveDown(1.5);
            const y = doc.y;
            // Sol tarafa mavi çizgi
            doc.rect(50, y, 5, 20).fill(colors.primary);
            doc.fontSize(14).font('Helvetica-Bold').fill(colors.primary)
               .text(title.toUpperCase(), 65, y + 2);
            doc.moveDown(0.5);
        };

        // Soru - Cevap Kartı
        const drawField = (label, value) => {
            // Sayfa sonuna geldik mi kontrolü
            if (doc.y > 720) {
                doc.addPage();
                drawHeader();
                doc.y = 120; // Header'ın altından başla
            }

            const startY = doc.y;
            const content = cleanText(value);
            
            // Soru Başlığı (Label)
            doc.fontSize(9).font('Helvetica-Bold').fill('#64748b').text(label, 50, startY);
            
            // Cevap Kutusu
            const boxTop = doc.y + 5;
            
            // Cevabın uzunluğunu hesapla
            doc.fontSize(11).font('Helvetica');
            const textHeight = doc.heightOfString(content, { width: 470 });
            const boxHeight = textHeight + 20;

            // Arka plan kutusu
            doc.roundedRect(50, boxTop, 495, boxHeight, 5).fill(colors.lightBg);
            
            // Cevap Metni
            doc.fill(colors.secondary).text(content, 62, boxTop + 10, { width: 470 });
            
            // Boşluk bırak
            doc.y = boxTop + boxHeight + 15;
        };

        // --- PDF İÇERİĞİ OLUŞTURMA ---
        
        // İlk Sayfa Header
        drawHeader();
        doc.y = 120; // İçeriğe başlama noktası

        // BÖLÜM A
        drawSectionTitle('A. Kisisel Bilgiler');
        drawField('Dogum Yeri ve Tarihi', formData.birthPlace);
        drawField('Medeni Hali', formData.maritalStatus);
        drawField('Adres / Iletisim', formData.address);
        drawField('Askerlik Durumu', formData.militaryService);
        drawField('Surucu Belgesi Sinifi', formData.drivingLicenseClass);

        // BÖLÜM B
        drawSectionTitle('B. Egitim ve Is Gecmisi');
        drawField('Mezun Olunan Lise', formData.highSchool);
        drawField('Mezun Olunan Yuksekokul', formData.university);
        drawField('Gecmis Is Tecrubeleri', formData.workHistory);

        // BÖLÜM C
        drawSectionTitle('C. Mesleki Motivasyon');
        drawField('Meslegin Anlami', formData.meaningOfJob);
        drawField('Bir Calisma Gunu', formData.dailyRoutine);
        drawField('Almanya Istegi', formData.germanyDesire);
        drawField('Turkiye-Almanya Farklari', formData.definitionDiff);
        drawField('Karsilasilacak Zorluklar', formData.challenges);
        drawField('Dilin Onemi', formData.languageImportance);
        drawField('Almanya\'daki Tanidiklar', formData.friendsInGermany);

        // BÖLÜM D
        drawSectionTitle('D. Almanca Dil Bilgisi');
        drawField('Mevcut Seviye', formData.germanLevel);
        drawField('Egitim Yeri', formData.germanEducationPlace);
        drawField('Seviye Farkindaligi', formData.levelAwareness);
        drawField('Ogrenme Plani', formData.languagePlan);
        drawField('Kurs Butcesi', formData.budgetForCourse);
        drawField('Aile Dil Durumu', formData.familyLanguage);

        // BÖLÜM E
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

        // BÖLÜM F
        drawSectionTitle('F. Berliner ');
        drawField('Tanisma Hikayesi', formData.berlinerMeet);
        drawField('Guven Dusuncesi', formData.berlinerTrust);

        // Footerları ekle (Tüm sayfalara)
        const range = doc.bufferedPageRange();
        for (let i = 0; i < range.count; i++) {
            doc.switchToPage(i);
            drawFooter(i + 1);
        }

        doc.end();

        // Veritabanına Kayıt (Arka Planda)
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
// --- ALMANCA KELİME VE CÜMLELERİ YÜKLEME (TOHUMLAMA) ---
app.get('/seed-german', async (req, res) => {
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

        // Önce temizle, sonra ekle (Çift kayıt olmasın diye)
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

    // 2. YAZILI OLMAYAN KURALLAR (ADAC ve Selektör Eklendi)
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

    // 3. PRATİK BİLGİLER
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