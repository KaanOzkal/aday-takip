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

// --- SABİT VERİLER ---
const STAGES = [
    'Başvuru Alındı', 'Evrak Kontrolü', 'Tercüme Süreci', 
    'İşveren Onayı', 'Vize Ön Onay', 'Vize Başvurusu', 
    'Seyahat Planı', 'Almanya\'da'
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

// --- ADMIN YOLLARI ---
app.get('/admin', adminAuthCheck, async (req, res) => {
    const candidates = await Candidate.find().sort({ applicationDate: -1 });
    res.render('admin', { candidates, stages: STAGES });
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

app.post('/admin/appointment/status', adminAuthCheck, async (req, res) => {
    await Candidate.updateOne({ _id: req.body.candidateId, "appointments._id": req.body.appId }, { $set: { "appointments.$.status": req.body.status } });
    res.redirect('/admin');
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
            html: `<div style="padding: 20px;"><h3>Sayın ${candidate.firstName},</h3><p>${req.body.content}</p><hr><small>BERLINER AKADEMIE</small></div>`
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
                html: `<div style="padding: 20px;"><h3>Sayın ${candidate.firstName},</h3><p>${content}</p><hr><small>BERLINER AKADEMIE</small></div>`
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

app.get('/admin/candidate/delete-note/:candidateId/:noteId', adminAuthCheck, async (req, res) => {
    try {
        await Candidate.findByIdAndUpdate(req.params.candidateId, {
            $pull: { notes: { _id: req.params.noteId } }
        });
        res.redirect('/admin?status=note_deleted');
    } catch (error) {
        res.redirect('/admin?error=delete_failed');
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
// --- PORT ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Sunucu ${PORT} portunda çalışıyor`);
});