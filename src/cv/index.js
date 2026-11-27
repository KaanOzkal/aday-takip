// =====================================================================
//  PROFESYONEL CV (Türkçe Özgeçmiş / Almanca Lebenslauf)
//  Veriler adayın dijital dosyasından çekilir; hiçbir bilgi uydurulmaz.
//  Serbest metinlerin Almancası elle girilir; kural tabanlı alanlar (tarih, seviye,
//  medeni durum, ehliyet, dil adları) otomatik çevrilir.
// =====================================================================
const path = require('path');
const TR_ASCII = { 'ı': 'i', 'İ': 'I', 'ş': 's', 'Ş': 'S', 'ğ': 'g', 'Ğ': 'G', 'ç': 'c', 'Ç': 'C', 'ö': 'o', 'Ö': 'O', 'ü': 'u', 'Ü': 'U' };
const fs = require('fs');
const mongoose = require('mongoose');
const PDFDocument = require('pdfkit');
const { isAllowedFile } = require('../lib/files');

const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const withParam = (url, k, v) => { const u = new URL(url, 'http://x'); u.searchParams.delete('status'); u.searchParams.delete('error'); u.searchParams.set(k, v); return u.pathname + u.search + u.hash; };
const FONT_DIR = path.join(__dirname, '..', 'assets', 'fonts');
const LOGO = path.join(__dirname, '..', '..', 'public', 'img', 'berliner-logo.png');
const pad = (n) => String(n).padStart(2, '0');

// ---- Kural tabanlı çeviriler ----
const LANG_DE = { 'türkçe': 'Türkisch', 'turkce': 'Türkisch', 'almanca': 'Deutsch', 'ingilizce': 'Englisch', 'arapça': 'Arabisch', 'arapca': 'Arabisch', 'kürtçe': 'Kurdisch', 'kurtce': 'Kurdisch', 'rusça': 'Russisch', 'rusca': 'Russisch', 'fransızca': 'Französisch', 'fransizca': 'Französisch', 'farsça': 'Persisch', 'farsca': 'Persisch', 'azerice': 'Aserbaidschanisch', 'bulgarca': 'Bulgarisch', 'boşnakça': 'Bosnisch', 'arnavutça': 'Albanisch', 'italyanca': 'Italienisch', 'ispanyolca': 'Spanisch', 'İspanyolca': 'Spanisch', 'felemenkçe': 'Niederländisch', 'hollandaca': 'Niederländisch', 'lehçe': 'Polnisch', 'romence': 'Rumänisch', 'yunanca': 'Griechisch', 'gürcüce': 'Georgisch', 'ukraynaca': 'Ukrainisch', 'özbekçe': 'Usbekisch', 'türkmence': 'Turkmenisch', 'kazakça': 'Kasachisch', 'zazaca': 'Zazaisch' };
const langDe = (l) => LANG_DE[String(l || '').trim().toLocaleLowerCase('tr-TR')] || null;
const levelTxt = (lv, lang) => !lv ? '' : lv === 'Anadil' ? (lang === 'de' ? 'Muttersprache' : 'Anadil') : `${lv} (${lang === 'de' ? 'GER' : 'AOBM'})`;
const MARITAL_DE = { 'Evli': 'verheiratet', 'Bekar': 'ledig', 'Boşanmış': 'geschieden' };
const NAT_DE = { 'türkiye cumhuriyeti': 'türkisch', 'türkiye': 'türkisch', 'tc': 'türkisch', 't.c.': 'türkisch', 'türk': 'türkisch' };
const monthYear = (d) => d ? `${pad(new Date(d).getMonth() + 1)}/${new Date(d).getFullYear()}` : '';
const dayDate = (d) => d ? `${pad(new Date(d).getDate())}.${pad(new Date(d).getMonth() + 1)}.${new Date(d).getFullYear()}` : '';
const range = (s, e, cur, lang) => { const a = monthYear(s), b = cur ? (lang === 'de' ? 'heute' : 'Halen') : monthYear(e); return a && b ? `${a} – ${b}` : (a || b || ''); };

const L = {
    tr: { doc: 'Özgeçmiş', personal: 'Kişisel Bilgiler', name: 'Ad Soyad', address: 'Adres', phone: 'Telefon', email: 'E-posta', birth: 'Doğum tarihi ve yeri', nationality: 'Uyruk', marital: 'Medeni durum', children: (n) => `${n} çocuk`, profile: 'Mesleki Profil', experience: 'İş Deneyimi', education: 'Eğitim', license: 'Sürücü Belgesi', classes: 'Ehliyet sınıfları', validUntil: 'Geçerlilik', languages: 'Dil Bilgisi', skills: 'Mesleki Yeterlilikler', certs: 'Sertifikalar ve Belgeler', issued: 'Veriliş', valid: 'geçerlilik', date: 'Tarih', page: (a, b) => `Sayfa ${a}/${b}`, birthJoin: ', ', current: 'Halen' },
    de: { doc: 'Lebenslauf', personal: 'Persönliche Daten', name: 'Name', address: 'Anschrift', phone: 'Telefon', email: 'E-Mail', birth: 'Geburtsdatum und -ort', nationality: 'Staatsangehörigkeit', marital: 'Familienstand', children: (n) => `${n} ${n === 1 ? 'Kind' : 'Kinder'}`, profile: 'Kurzprofil', experience: 'Berufserfahrung', education: 'Ausbildung', license: 'Führerschein', classes: 'Führerscheinklassen', validUntil: 'gültig bis', languages: 'Sprachkenntnisse', skills: 'Fachliche Kenntnisse', certs: 'Zertifikate und Nachweise', issued: 'ausgestellt', valid: 'gültig bis', date: 'Datum', page: (a, b) => `Seite ${a} von ${b}`, birthJoin: ' in ', current: 'heute' }
};

// Adayın dosyasından CV modeli üret (lang: 'tr' | 'de')
function buildCv(c, lang = 'tr') {
    const d = c.dossier || {}, cv = d.cv || {}, de = lang === 'de', l = L[lang];
    const warnings = [], untranslated = [];
    const pick = (tr, deVal, label) => { if (!de) return tr || ''; if (deVal) return deVal; if (tr) untranslated.push(label); return tr || ''; };
    const name = `${c.firstName || ''} ${c.lastName || ''}`.trim();
    const title = de ? (cv.titleDe || '') : (c.job || '');
    if (de && !cv.titleDe && c.job) untranslated.push('CV başlığı (meslek)');
    // Kişisel
    const personal = [];
    if (d.address) personal.push([l.address, d.address]);
    const phone = c.phone || c.phoneNumber; if (phone) personal.push([l.phone, phone]);
    if (c.email) personal.push([l.email, c.email]);
    if (d.birthDate) personal.push([l.birth, dayDate(d.birthDate) + (d.birthPlace ? l.birthJoin + d.birthPlace : '')]);
    if (d.nationality) personal.push([l.nationality, de ? (NAT_DE[d.nationality.toLocaleLowerCase('tr-TR')] || d.nationality) : d.nationality]);
    if (d.maritalStatus) personal.push([l.marital, (de ? MARITAL_DE[d.maritalStatus] : d.maritalStatus) + (d.children ? ', ' + l.children(d.children) : '')]);
    // Deneyim (kronolojik: en yeni üstte — Almanya'da yaygın "amerikanischer Lebenslauf")
    const sortKey = (x) => x.current ? Infinity : new Date(x.end || x.start || 0).getTime();
    const experience = (d.work || []).slice().sort((a, b) => sortKey(b) - sortKey(a) || new Date(b.start || 0) - new Date(a.start || 0)).map((w, i) => ({
        when: range(w.start, w.end, w.current, lang),
        title: pick(w.position || w.job, w.positionDe || w.jobDe, `İş deneyimi ${i + 1}: pozisyon`),
        org: [w.company, w.location].filter(Boolean).join(', '),
        sub: (w.position && w.job && w.position !== w.job) ? pick(w.job, w.jobDe, `İş deneyimi ${i + 1}: meslek`) : '',
        desc: de ? (w.descriptionDe || (w.description ? (untranslated.push(`İş deneyimi ${i + 1}: açıklama`), '') : '')) : (w.description || '')
    }));
    const education = (d.education || []).slice().sort((a, b) => sortKey(b) - sortKey(a)).map((e, i) => ({
        when: range(e.start, e.end, e.current, lang),
        title: [pick(e.degree, e.degreeDe, `Eğitim ${i + 1}: derece`), pick(e.field, e.fieldDe, `Eğitim ${i + 1}: bölüm`)].filter(Boolean).join(' – '),
        org: [e.school, e.location].filter(Boolean).join(', ')
    }));
    const languages = [];
    if (d.germanLevel) languages.push([de ? 'Deutsch' : 'Almanca', levelTxt(d.germanLevel, lang)]);
    if (d.englishLevel) languages.push([de ? 'Englisch' : 'İngilizce', levelTxt(d.englishLevel, lang)]);
    (d.otherLanguages || []).forEach(o => { const n = de ? langDe(o.lang) : o.lang; if (de && !n) untranslated.push(`Dil adı: ${o.lang}`); languages.push([n || o.lang, levelTxt(o.level, lang)]); });
    const license = (d.licenseClasses || []).length ? { classes: d.licenseClasses.join(', '), valid: d.licenseExpiry ? dayDate(d.licenseExpiry) : '' } : null;
    const skillsSrc = de ? cv.skillsDe : cv.skillsTr;
    if (de && !cv.skillsDe && cv.skillsTr) untranslated.push('Mesleki yeterlilikler');
    const skills = String(skillsSrc || '').split(/\r?\n/).map(x => x.replace(/^[-•*]\s*/, '').trim()).filter(Boolean);
    const certificates = (d.certificates || []).map((x, i) => ({ name: pick(x.name, x.nameDe, `Sertifika ${i + 1}: ad`), issuer: x.issuer || '', date: monthYear(x.date), valid: x.validUntil ? dayDate(x.validUntil) : '' }));
    const profile = de ? (cv.profileDe || '') : (cv.profileTr || '');
    if (de && !cv.profileDe && cv.profileTr) untranslated.push('Mesleki profil');
    // Eksik bilgi uyarıları (CV oluşturmadan önce gösterilir)
    if (!phone && !c.email) warnings.push('İletişim bilgisi (telefon veya e-posta) yok');
    if (!d.address) warnings.push('Adres girilmemiş');
    if (!d.birthDate) warnings.push('Doğum tarihi girilmemiş');
    if (!experience.length) warnings.push('İş deneyimi eklenmemiş');
    if (!education.length) warnings.push('Eğitim bilgisi eklenmemiş');
    if (!license) warnings.push('Ehliyet sınıfları girilmemiş');
    if (!languages.length) warnings.push('Dil bilgisi girilmemiş');
    if (!profile) warnings.push(de ? 'Almanca mesleki profil (Kurzprofil) yazılmamış' : 'Mesleki profil yazılmamış');
    if (!title) warnings.push(de ? 'Almanca CV başlığı (meslek) girilmemiş' : 'Meslek bilgisi girilmemiş');
    const photo = cv.includePhoto !== false && c.cvDetails && /^data:image\/(jpeg|png);base64,/.test(c.cvDetails.profilePhoto || '') ? c.cvDetails.profilePhoto : null;
    return { lang, l, name, title, photo, personal, profile, experience, education, languages, license, skills, certificates, warnings, untranslated: [...new Set(untranslated)], date: dayDate(new Date()) };
}

// ---- PDF çizimi (A4) ----
function renderPdf(m, res, filename) {
    const doc = new PDFDocument({ size: 'A4', margins: { top: 40, bottom: 56, left: 48, right: 48 }, bufferPages: true, info: { Title: `${m.l.doc} – ${m.name}`, Author: 'BERLINER', Subject: m.l.doc } });
    doc.registerFont('R', path.join(FONT_DIR, 'DejaVuSans.ttf'));
    doc.registerFont('B', path.join(FONT_DIR, 'DejaVuSans-Bold.ttf'));
    res.setHeader('Content-Type', 'application/pdf');
    const ascii = filename.replace(/[ıİşŞğĞçÇöÖüÜ]/g, ch => TR_ASCII[ch]).normalize('NFKD').replace(/[^\x20-\x7E]/g, '').replace(/["\\]/g, '');
    res.setHeader('Content-Disposition', `${res.req.query.inline === '1' ? 'inline' : 'attachment'}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`);
    doc.pipe(res);
    const RED = '#C8102E', INK = '#1A1A1A', GRAY = '#5F6368', LINE = '#D9DCE1', DARK = '#2B2B2B';
    const X = 48, W = doc.page.width - 96, LABEL = 128, VX = X + LABEL + 12, VW = W - LABEL - 12;
    // Üst şerit + logo + başlık
    doc.rect(0, 0, doc.page.width, 5).fill(RED);
    let headTop = 30;
    if (fs.existsSync(LOGO)) doc.image(LOGO, X, headTop, { width: 62, height: 62 });
    const tx = X + 78, photoW = m.photo ? 86 : 0, tw = W - 78 - (photoW ? photoW + 14 : 0);
    doc.font('B').fontSize(8.5).fill(RED).text(m.l.doc.toLocaleUpperCase(m.lang === 'de' ? 'de-DE' : 'tr-TR'), tx, headTop + 2, { width: tw, characterSpacing: 0.8 });
    doc.font('B').fontSize(22).fill(INK).text(m.name, tx, headTop + 14, { width: tw });
    if (m.title) doc.font('R').fontSize(11.5).fill(DARK).text(m.title, tx, doc.y + 1, { width: tw });
    let headBottom = Math.max(doc.y, headTop + 62);
    if (m.photo) {
        try {
            const buf = Buffer.from(m.photo.split(',')[1], 'base64');
            const px = X + W - photoW;
            doc.save().rect(px, headTop, photoW, 108).clip().image(buf, px, headTop, { cover: [photoW, 108], align: 'center', valign: 'center' }).restore();
            doc.rect(px, headTop, photoW, 108).lineWidth(0.5).strokeColor(LINE).stroke();
            headBottom = Math.max(headBottom, headTop + 108);
        } catch (e) { /* bozuk fotoğraf CV'yi engellemesin */ }
    }
    doc.y = headBottom + 16;
    doc.moveTo(X, doc.y).lineTo(X + W, doc.y).lineWidth(1.2).strokeColor(INK).stroke();
    doc.y += 14;

    const ensure = (h) => { if (doc.y + h > doc.page.height - 66) { doc.addPage(); doc.rect(0, 0, doc.page.width, 5).fill(RED); doc.y = 44; } };
    const section = (t) => {
        ensure(40);
        doc.font('B').fontSize(10.5).fill(RED).text(t.toLocaleUpperCase(m.lang === 'de' ? 'de-DE' : 'tr-TR'), X, doc.y);
        const y = doc.y + 3; doc.moveTo(X, y).lineTo(X + W, y).lineWidth(0.6).strokeColor(LINE).stroke();
        doc.y = y + 8;
    };
    const row = (label, value, opts = {}) => {
        const h = Math.max(doc.font(opts.bold ? 'B' : 'R').fontSize(9.5).heightOfString(value || '', { width: VW }), 12);
        ensure(h + 4);
        const y = doc.y;
        doc.font('R').fontSize(9).fill(GRAY).text(label || '', X, y, { width: LABEL });
        doc.font(opts.bold ? 'B' : 'R').fontSize(9.5).fill(INK).text(value || '', VX, y, { width: VW });
        doc.y = Math.max(doc.y, y + 12) + (opts.gap ?? 4);
    };
    const entry = (when, title, org, sub, desc) => {
        const hgt = doc.font('B').fontSize(10).heightOfString(title || '', { width: VW }) + (org ? 13 : 0) + (sub ? 12 : 0) + (desc ? doc.font('R').fontSize(9).heightOfString(desc, { width: VW }) + 3 : 0);
        ensure(Math.min(hgt, 200) + 8);
        const y = doc.y;
        doc.font('R').fontSize(9).fill(GRAY).text(when || '', X, y + 1, { width: LABEL });
        doc.font('B').fontSize(10).fill(INK).text(title || '', VX, y, { width: VW });
        if (org) doc.font('R').fontSize(9.2).fill(DARK).text(org, VX, doc.y + 1, { width: VW });
        if (sub) doc.font('R').fontSize(9).fill(GRAY).text(sub, VX, doc.y + 1, { width: VW });
        if (desc) doc.font('R').fontSize(9).fill(INK).text(desc, VX, doc.y + 3, { width: VW, lineGap: 1.5 });
        doc.y += 10;
    };

    section(m.l.personal);
    row(m.l.name, m.name, { bold: true });
    m.personal.forEach(([k, v]) => row(k, v));
    if (m.profile) { doc.y += 6; section(m.l.profile); doc.font('R').fontSize(9.6).fill(INK).text(m.profile, X, doc.y, { width: W, lineGap: 2 }); doc.y += 10; }
    if (m.experience.length) { doc.y += 6; section(m.l.experience); m.experience.forEach(e => entry(e.when, e.title, e.org, e.sub, e.desc)); }
    if (m.education.length) { doc.y += 2; section(m.l.education); m.education.forEach(e => entry(e.when, e.title, e.org)); }
    if (m.license) { doc.y += 2; section(m.l.license); row(m.l.classes, m.license.classes, { bold: true }); if (m.license.valid) row(m.l.validUntil, m.license.valid); doc.y += 4; }
    if (m.languages.length) { doc.y += 2; section(m.l.languages); m.languages.forEach(([n, lv]) => row(n, lv)); doc.y += 4; }
    if (m.skills.length) { doc.y += 2; section(m.l.skills); m.skills.forEach(s => { ensure(14); const y = doc.y; doc.rect(VX - 9, y + 4, 3, 3).fill(RED); doc.font('R').fontSize(9.5).fill(INK).text(s, VX, y, { width: VW }); doc.y += 3; }); doc.y += 6; }
    if (m.certificates.length) { doc.y += 2; section(m.l.certs); m.certificates.forEach(x => entry(x.date, x.name, x.issuer, x.valid ? `${m.l.valid} ${x.valid}` : '', '')); }

    const range_ = doc.bufferedPageRange();
    for (let i = 0; i < range_.count; i++) {
        doc.switchToPage(i);
        const fy = doc.page.height - 38;
        doc.moveTo(X, fy - 6).lineTo(X + W, fy - 6).lineWidth(0.5).strokeColor(LINE).stroke();
        doc.font('R').fontSize(7.5).fill(GRAY).text(`${m.name} · ${m.l.doc}`, X, fy, { width: W / 2, lineBreak: false });
        doc.text(`${m.l.date}: ${m.date} · ${m.l.page(i + 1, range_.count)}`, X + W / 2, fy, { width: W / 2, align: 'right', lineBreak: false });
    }
    doc.end();
}

module.exports = function mountCV(app, deps) {
    const { adminAuthCheck, authCheck, Candidate, upload } = deps;
    const S = () => app.locals.services;
    app.locals.buildCv = buildCv;

    async function saveCv(cand, b, file) {
        const set = {
            'dossier.cv.titleDe': str(b.titleDe, 120), 'dossier.cv.profileTr': str(b.profileTr, 1500), 'dossier.cv.profileDe': str(b.profileDe, 1500),
            'dossier.cv.skillsTr': str(b.skillsTr, 1500), 'dossier.cv.skillsDe': str(b.skillsDe, 1500), 'dossier.cv.includePhoto': b.includePhoto === 'on'
        };
        if (typeof b.job === 'string') set.job = str(b.job, 120);
        if (b.removePhoto === 'on') set['cvDetails.profilePhoto'] = '';
        if (file) {
            if (!isAllowedFile(file, ['image/jpeg', 'image/png']) || file.size > 2 * 1024 * 1024) return 'bad_photo';
            set['cvDetails.profilePhoto'] = `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
        }
        // İş / eğitim / sertifika kayıtlarının Almanca karşılıkları (aday kaydının kendisi değişmez)
        const doc = await Candidate.findById(cand._id);
        const d = doc.dossier || {};
        const map = (list, prefix, fields) => (list || []).forEach(x => { fields.forEach(f => { const k = `${prefix}_${f}_${x._id}`; if (typeof b[k] === 'string') x[f] = str(b[k], f.startsWith('description') ? 2000 : 160); }); });
        map(d.work, 'w', ['positionDe', 'jobDe', 'descriptionDe']);
        map(d.education, 'e', ['degreeDe', 'fieldDe']);
        map(d.certificates, 'c', ['nameDe']);
        Object.entries(set).forEach(([k, v]) => doc.set(k, v));
        await doc.save();
        return null;
    }
    const photoUpload = (back) => (req, res, next) => upload.single('photo')(req, res, (err) => { if (err) return res.redirect(withParam(back(req), 'error', err.code === 'LIMIT_FILE_SIZE' ? 'too_large' : 'upload_failed')); next(); });
    const fileName = (c, lang) => `${lang === 'de' ? 'Lebenslauf' : 'Ozgecmis'}_${`${c.firstName || ''}_${c.lastName || ''}`.replace(/\s+/g, '_')}.pdf`;
    const langOf = (q) => q === 'de' ? 'de' : 'tr';

    // ---- Aday ----
    app.get('/cv', authCheck, (req, res) => {
        const lang = langOf(req.query.lang);
        res.render('cv_studio', { user: req.user, c: req.user, page: 'cv', mode: 'candidate', lang, m: buildCv(req.user, lang), base: '/cv' });
    });
    app.post('/cv/save', authCheck, photoUpload(() => '/cv'), async (req, res) => {
        const err = await saveCv(req.user, req.body, req.file);
        res.redirect(withParam(`/cv?lang=${langOf(req.body.lang)}`, err ? 'error' : 'status', err || 'cv_saved'));
    });
    app.get('/cv.pdf', authCheck, async (req, res) => {
        const lang = langOf(req.query.lang);
        await Candidate.updateOne({ _id: req.user._id }, { $set: { 'dossier.cv.generatedAt': new Date() } });
        renderPdf(buildCv(req.user, lang), res, fileName(req.user, lang));
    });
    // Eski CV oluşturucu yeni sisteme yönlendirilir
    app.get(['/cv-builder', '/cv-print'], authCheck, (req, res) => res.redirect('/cv'));

    // ---- Yönetici ----
    app.get('/admin/candidate/:id/cv', adminAuthCheck, async (req, res) => {
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const c = await Candidate.findById(req.params.id);
        if (!c) return res.redirect('/admin?error=not_found');
        const lang = langOf(req.query.lang);
        res.render('cv_studio', { user: { firstName: 'Admin' }, c, mode: 'admin', lang, m: buildCv(c, lang), base: `/admin/candidate/${c._id}/cv` });
    });
    app.post('/admin/candidate/:id/cv/save', adminAuthCheck, photoUpload((req) => `/admin/candidate/${req.params.id}/cv`), async (req, res) => {
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const c = await Candidate.findById(req.params.id);
        if (!c) return res.redirect('/admin?error=not_found');
        const err = await saveCv(c, req.body, req.file);
        if (!err) await S().audit(req, 'cv.update', 'Candidate', c._id, `${c.firstName} ${c.lastName}: CV bilgileri güncellendi`);
        res.redirect(withParam(`/admin/candidate/${c._id}/cv?lang=${langOf(req.body.lang)}`, err ? 'error' : 'status', err || 'cv_saved'));
    });
    app.get('/admin/candidate/:id/cv.pdf', adminAuthCheck, async (req, res) => {
        if (!isId(req.params.id)) return res.status(404).send('Aday bulunamadı.');
        const c = await Candidate.findById(req.params.id);
        if (!c) return res.status(404).send('Aday bulunamadı.');
        const lang = langOf(req.query.lang);
        await Candidate.updateOne({ _id: c._id }, { $set: { 'dossier.cv.generatedAt': new Date() } });
        await S().audit(req, 'cv.generate', 'Candidate', c._id, `${c.firstName} ${c.lastName}: ${lang === 'de' ? 'Almanca' : 'Türkçe'} CV PDF oluşturuldu`);
        renderPdf(buildCv(c, lang), res, fileName(c, lang));
    });
};
module.exports.buildCv = buildCv;
