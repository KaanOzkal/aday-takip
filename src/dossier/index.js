// =====================================================================
//  DİJİTAL ADAY DOSYASI
//  Kişisel bilgiler · İş geçmişi / eğitim / sertifikalar · Bölüm doğrulama (kilit)
//  Sürücü Kayıt & KOD95 ödemeleri (dekont, onay/ret, geçmiş) · Kategorili belge arşivi
// =====================================================================
const mongoose = require('mongoose');
const Payment = require('../models/Payment');
const Message = require('../models/Message');
const { isAllowedFile } = require('../lib/files');

const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const withParam = (url, k, v) => { const u = new URL(url, 'http://x'); u.searchParams.delete('status'); u.searchParams.delete('error'); u.searchParams.set(k, v); return u.pathname + u.search + u.hash; };
const fullName = (c) => `${c.firstName || ''} ${c.lastName || ''}`.trim();

const LEVELS = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2', 'Anadil'];
const LICENSE_CLASSES = ['B', 'BE', 'C1', 'C1E', 'C', 'CE', 'D1', 'D1E', 'D', 'DE'];
const MARITAL = ['Evli', 'Bekar', 'Boşanmış'];
const DOC_CATEGORIES = ['Pasaport', 'Kimlik', 'Ehliyet', 'CV', 'İş Deneyimi', 'Sağlık', 'Eğitim', 'Sertifika', 'Resmi Kayıtlar', 'Diğer'];
const RECEIPT_MIMES = ['application/pdf', 'image/jpeg', 'image/png'];
const DOC_MIMES = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif',
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];

// Belge adından arşiv kategorisi (eski kayıtlar için)
function categoryOf(d) {
    if (d.category && DOC_CATEGORIES.includes(d.category)) return d.category;
    const n = String(d.name || '').toLocaleLowerCase('tr-TR');
    if (/pasaport/.test(n)) return 'Pasaport';
    if (/kimlik|nüfus cüzdan/.test(n)) return 'Kimlik';
    if (/ehliyet|sürücü/.test(n)) return 'Ehliyet';
    if (/^cv$|özgeçmiş|lebenslauf/.test(n)) return 'CV';
    if (/sağlık raporu|sağlık|saglik|medical|ärztlich/.test(n)) return 'Sağlık';
    if (/iş deneyim|is deneyim|hizmet döküm|hizmet dokum|sgk|çalışma belgesi|referans|arbeitszeugnis/.test(n)) return 'İş Deneyimi';
    if (/diploma|mezuniyet|transkript/.test(n)) return 'Eğitim';
    if (/sertifika|src|kod ?95|psikoteknik|takograf/.test(n)) return 'Sertifika';
    if (/adli sicil|nüfus kayıt|ikametgah/.test(n)) return 'Resmi Kayıtlar';
    return 'Diğer';
}

// T.C. kimlik numarası algoritma kontrolü
function tcValid(tc) {
    if (!/^[1-9]\d{10}$/.test(tc)) return false;
    const d = tc.split('').map(Number);
    const odd = d[0] + d[2] + d[4] + d[6] + d[8], even = d[1] + d[3] + d[5] + d[7];
    if (((odd * 7 - even) % 10 + 10) % 10 !== d[9]) return false;
    return d.slice(0, 10).reduce((a, b) => a + b, 0) % 10 === d[10];
}
const dateOf = (v) => { if (!v || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return null; const d = new Date(`${v}T12:00:00`); return isNaN(d) ? null : d; };
const monthOf = (v) => { if (!v || !/^\d{4}-\d{2}$/.test(v)) return null; const d = new Date(`${v}-01T12:00:00`); return isNaN(d) ? null : d; };
const phoneOk = (p) => /^[+0-9 ()\-]{7,20}$/.test(p);
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

const SECTIONS = {
    identity: { label: 'Kimlik bilgileri', fields: [['passportNo', 'Pasaport numarası'], ['tcNo', 'T.C. kimlik numarası'], ['birthDate', 'Doğum tarihi'], ['birthPlace', 'Doğum yeri'], ['maritalStatus', 'Medeni durum'], ['children', 'Çocuk sayısı']] },
    contact: { label: 'İletişim ve adres', fields: [['email', 'E-posta adresi'], ['phone', 'Telefon numarası'], ['address', 'Açık adres']] },
    license: { label: 'Ehliyet', fields: [['licenseClasses', 'Ehliyet sınıfları'], ['licenseExpiry', 'Ehliyet geçerlilik tarihi']] },
    languages: { label: 'Dil bilgisi', fields: [['germanLevel', 'Almanca seviyesi'], ['englishLevel', 'İngilizce seviyesi']] },
    emergency: { label: 'Acil durum kişisi', fields: [['emergencyName', 'Acil durumda aranacak kişi'], ['emergencyPhone', 'Acil durum telefonu']] },
    work: { label: 'İş geçmişi', fields: [['work', 'En az bir iş deneyimi']] },
    education: { label: 'Eğitim ve sertifikalar', fields: [['education', 'En az bir eğitim bilgisi']] }
};

function valueOf(c, key) {
    const d = c.dossier || {};
    if (key === 'passportNo') return c.passportNo;
    if (key === 'email') return c.email;
    if (key === 'phone') return c.phone || c.phoneNumber;
    return d[key];
}
const filled = (v) => Array.isArray(v) ? v.length > 0 : (v !== undefined && v !== null && String(v).trim() !== '');

function completeness(c) {
    const out = { sections: {}, missing: [], filled: 0, total: 0 };
    for (const [k, s] of Object.entries(SECTIONS)) {
        const f = s.fields.filter(([key]) => filled(valueOf(c, key)));
        const ver = c.dossier && c.dossier.verified && c.dossier.verified[k] && c.dossier.verified[k].at ? c.dossier.verified[k] : null;
        out.sections[k] = { label: s.label, filled: f.length, total: s.fields.length, verified: ver };
        s.fields.forEach(([key, label]) => { if (!filled(valueOf(c, key))) out.missing.push({ section: k, label }); });
        out.filled += f.length; out.total += s.fields.length;
    }
    out.pct = Math.round(out.filled / out.total * 100);
    out.verifiedCount = Object.values(out.sections).filter(s => s.verified).length;
    return out;
}

// Bölüm formunu doğrula → { set: {...}, error }
async function readSection(key, b, cand, Candidate) {
    const set = {};
    if (key === 'identity') {
        const passportNo = str(b.passportNo, 20).toUpperCase().replace(/\s+/g, '');
        if (passportNo && !/^[A-Z0-9]{6,15}$/.test(passportNo)) return { error: 'bad_passport' };
        if (passportNo && passportNo !== cand.passportNo && await Candidate.exists({ passportNo, _id: { $ne: cand._id } })) return { error: 'passport_exists' };
        if (!passportNo && cand.passportNo) return { error: 'passport_required' }; // giriş bilgisi olduğundan silinemez
        const tc = str(b.tcNo, 11).replace(/\D/g, '');
        if (tc && !tcValid(tc)) return { error: 'bad_tc' };
        const bd = b.birthDate ? dateOf(b.birthDate) : null;
        if (b.birthDate && (!bd || bd > new Date(Date.now() - 16 * 365 * 864e5) || bd < new Date('1930-01-01'))) return { error: 'bad_birthdate' };
        const ms = MARITAL.includes(b.maritalStatus) ? b.maritalStatus : '';
        const ch = b.children === '' || b.children == null ? undefined : parseInt(b.children, 10);
        if (ch !== undefined && (isNaN(ch) || ch < 0 || ch > 30)) return { error: 'bad_children' };
        if (passportNo) set.passportNo = passportNo;
        Object.assign(set, { 'dossier.tcNo': tc, 'dossier.birthDate': bd || undefined, 'dossier.birthPlace': str(b.birthPlace, 120), 'dossier.maritalStatus': ms, 'dossier.children': ch, 'dossier.nationality': str(b.nationality, 60) || 'Türkiye Cumhuriyeti' });
    } else if (key === 'contact') {
        const email = str(b.email, 160).toLowerCase(), phone = str(b.phone, 30);
        if (email && !emailOk(email)) return { error: 'bad_email' };
        if (phone && !phoneOk(phone)) return { error: 'bad_phone' };
        Object.assign(set, { email, phone, 'dossier.address': str(b.address, 400) });
    } else if (key === 'license') {
        const cls = [...new Set((Array.isArray(b.licenseClasses) ? b.licenseClasses : [b.licenseClasses]).filter(x => LICENSE_CLASSES.includes(x)))];
        const exp = b.licenseExpiry ? dateOf(b.licenseExpiry) : null;
        if (b.licenseExpiry && !exp) return { error: 'bad_date' };
        Object.assign(set, { 'dossier.licenseClasses': LICENSE_CLASSES.filter(x => cls.includes(x)), 'dossier.licenseExpiry': exp || undefined });
    } else if (key === 'languages') {
        const lv = (v) => LEVELS.includes(v) ? v : '';
        const langs = (Array.isArray(b.otherLang) ? b.otherLang : [b.otherLang]).map((l, i) => ({ lang: str(l, 40), level: lv((Array.isArray(b.otherLevel) ? b.otherLevel : [b.otherLevel])[i]) })).filter(x => x.lang).slice(0, 6);
        Object.assign(set, { 'dossier.germanLevel': lv(b.germanLevel), 'dossier.englishLevel': lv(b.englishLevel), 'dossier.otherLanguages': langs });
    } else if (key === 'emergency') {
        const phone = str(b.emergencyPhone, 30);
        if (phone && !phoneOk(phone)) return { error: 'bad_phone' };
        Object.assign(set, { 'dossier.emergencyName': str(b.emergencyName, 120), 'dossier.emergencyRelation': str(b.emergencyRelation, 60), 'dossier.emergencyPhone': phone });
    } else return { error: 'invalid_action' };
    set['dossier.updatedAt'] = new Date();
    return { set };
}

// İş / eğitim / sertifika kaydı oku
function readEntry(kind, b) {
    if (kind === 'work') {
        const start = monthOf(b.start), current = b.current === 'on', end = current ? null : monthOf(b.end);
        const e = { company: str(b.company, 160), job: str(b.job, 120), position: str(b.position, 120), location: str(b.location, 120), description: str(b.description, 2000), start, end, current, jobDe: str(b.jobDe, 120), positionDe: str(b.positionDe, 120), descriptionDe: str(b.descriptionDe, 2000) };
        if (!e.company || !(e.job || e.position) || !start) return { error: 'missing_fields' };
        if (!current && !end) return { error: 'end_required' };
        if (end && end < start) return { error: 'bad_date' };
        if (start > new Date()) return { error: 'bad_date' };
        return { e };
    }
    if (kind === 'education') {
        const start = monthOf(b.start), current = b.current === 'on', end = current ? null : monthOf(b.end);
        const e = { school: str(b.school, 160), degree: str(b.degree, 120), field: str(b.field, 120), location: str(b.location, 120), start, end, current, degreeDe: str(b.degreeDe, 120), fieldDe: str(b.fieldDe, 120) };
        if (!e.school || !e.degree) return { error: 'missing_fields' };
        if (start && end && end < start) return { error: 'bad_date' };
        return { e };
    }
    if (kind === 'certificates') {
        const e = { name: str(b.name, 160), issuer: str(b.issuer, 160), date: monthOf(b.date), validUntil: dateOf(b.validUntil), nameDe: str(b.nameDe, 160) };
        if (!e.name) return { error: 'missing_fields' };
        return { e };
    }
    return { error: 'invalid_action' };
}
const LOCK_OF = { work: 'work', education: 'education', certificates: 'education' };

module.exports = function mountDossier(app, deps) {
    const { adminAuthCheck, authCheck, Candidate, upload, storage } = deps;
    const S = () => app.locals.services;
    Object.assign(app.locals, { DOSSIER_LEVELS: LEVELS, LICENSE_CLASSES, MARITAL, DOC_CATEGORIES, docCategoryOf: categoryOf, PAYMENT_TYPES: Payment.TYPES });
    const PSTATUS = { awaiting_receipt: ['Dekont bekleniyor', 't-warn'], under_review: ['İnceleniyor', 't-info'], approved: ['Onaylandı · Tamamlandı', 't-ok'], rejected: ['Dekont reddedildi', 't-bad'] };
    app.locals.paymentStatus = (s) => PSTATUS[s] || ['—', 't-gray'];

    const uploadOne = (back) => (req, res, next) => upload.single('file')(req, res, (err) => {
        if (err) return res.redirect(withParam(back(req), 'error', err.code === 'LIMIT_FILE_SIZE' ? 'too_large' : 'upload_failed'));
        next();
    });
    const candActor = (c) => ({ type: 'anonymous', id: String(c._id), name: `${fullName(c)} (aday)` });
    const notifyAdmin = (title, message, link) => S().notify({ recipientType: 'admin', type: 'updated', title, message, link });

    // ---------------- Ortak: ödemeleri getir / tür güvenliği ----------------
    async function paymentsOf(candidateId) {
        const list = await Payment.find({ candidateId }).lean();
        return Object.keys(Payment.TYPES).map(t => ({ type: t, ...Payment.TYPES[t], record: list.find(p => p.type === t) || null }));
    }
    app.locals.dossierFor = async (cand) => ({ completeness: completeness(cand), payments: await paymentsOf(cand._id) });

    async function addReceipt(p, req, file, byType, byName) {
        const saved = await storage.save(file, `Dekontlar - ${p._candName || 'Aday'}`, { type: 'payment', id: p._id });
        p.receipts.push({ ...saved, uploadedByType: byType, uploadedByName: byName });
        p.status = 'under_review'; p.rejectReason = '';
        p.history.push({ action: 'Dekont yüklendi', byType, byName, note: saved.name });
    }

    // ==================================================================
    //  ADAY PANELİ
    // ==================================================================
    app.get('/kisisel-bilgiler', authCheck, (req, res) => {
        res.render('cand_personal', { user: req.user, page: 'personal', comp: completeness(req.user) });
    });
    app.post('/kisisel-bilgiler/:section', authCheck, async (req, res) => {
        const back = `/kisisel-bilgiler#${req.params.section}`;
        const key = req.params.section;
        if (!['identity', 'contact', 'license', 'languages', 'emergency'].includes(key)) return res.redirect(withParam(back, 'error', 'invalid_action'));
        const ver = req.user.dossier && req.user.dossier.verified && req.user.dossier.verified[key];
        if (ver && ver.at) return res.redirect(withParam(back, 'error', 'section_locked')); // doğrulanmış bölüm kilitli
        const r = await readSection(key, req.body, req.user, Candidate);
        if (r.error) return res.redirect(withParam(back, 'error', r.error));
        await Candidate.updateOne({ _id: req.user._id }, { $set: { ...r.set, lastActivityAt: new Date() } });
        res.redirect(withParam(back, 'status', 'saved'));
    });

    app.get('/is-gecmisi', authCheck, (req, res) => {
        res.render('cand_work', { user: req.user, page: 'work' });
    });
    app.post('/is-gecmisi/:kind', authCheck, async (req, res) => {
        const kind = req.params.kind, back = `/is-gecmisi#${kind}`;
        if (!LOCK_OF[kind]) return res.redirect(withParam(back, 'error', 'invalid_action'));
        const v = req.user.dossier && req.user.dossier.verified && req.user.dossier.verified[LOCK_OF[kind]];
        if (v && v.at) return res.redirect(withParam(back, 'error', 'section_locked'));
        const cand = await Candidate.findById(req.user._id);
        const list = cand.dossier[kind];
        if (req.body._action === 'delete') {
            const it = isId(req.body.id) && list.id(req.body.id);
            if (!it) return res.redirect(withParam(back, 'error', 'not_found'));
            it.deleteOne();
        } else {
            const r = readEntry(kind, req.body);
            if (r.error) return res.redirect(withParam(back, 'error', r.error));
            if (isId(req.body.id)) { const it = list.id(req.body.id); if (!it) return res.redirect(withParam(back, 'error', 'not_found')); it.set(r.e); }
            else { if (list.length >= 25) return res.redirect(withParam(back, 'error', 'too_many')); list.push(r.e); }
        }
        cand.dossier.updatedAt = new Date(); cand.lastActivityAt = new Date();
        await cand.save();
        res.redirect(withParam(back, 'status', req.body._action === 'delete' ? 'deleted' : 'saved'));
    });

    app.get('/odemelerim', authCheck, async (req, res) => {
        const pays = (await paymentsOf(req.user._id)).filter(p => p.record && p.record.active);
        res.render('cand_payments', { user: req.user, page: 'payments', pays });
    });
    app.post('/odemelerim/:type/dekont', authCheck, uploadOne(() => '/odemelerim'), async (req, res) => {
        const back = '/odemelerim';
        const p = Payment.TYPES[req.params.type] && await Payment.findOne({ candidateId: req.user._id, type: req.params.type, active: true });
        if (!p) return res.redirect(withParam(back, 'error', 'not_found'));
        if (!['awaiting_receipt', 'rejected'].includes(p.status)) return res.redirect(withParam(back, 'error', 'invalid_state'));
        if (!req.file) return res.redirect(withParam(back, 'error', 'no_file'));
        if (!isAllowedFile(req.file, RECEIPT_MIMES)) return res.redirect(withParam(back, 'error', 'bad_type'));
        try {
            p._candName = fullName(req.user);
            await addReceipt(p, req, req.file, 'candidate', fullName(req.user));
            await p.save();
            await notifyAdmin('Dekont yüklendi', `${fullName(req.user)} · ${Payment.TYPES[p.type].label} dekontu incelemenizi bekliyor`, `/admin/candidate/${req.user._id}#dossier`);
            await S().audit(req, 'payment.receipt_upload', 'Candidate', req.user._id, `${Payment.TYPES[p.type].label} dekontu yüklendi`, candActor(req.user));
            res.redirect(withParam(back, 'status', 'receipt_uploaded'));
        } catch (e) { console.error('Dekont yükleme hatası:', e.message); res.redirect(withParam(back, 'error', 'upload_failed')); }
    });

    // Dekont görüntüleme / indirme: yalnızca yönetici veya ödemenin sahibi aday
    app.get('/odeme-dekont/:pid/:rid', async (req, res) => {
        if (!isId(req.params.pid) || !isId(req.params.rid)) return res.status(404).send('Dosya bulunamadı.');
        const p = await Payment.findById(req.params.pid);
        if (!p) return res.status(404).send('Dosya bulunamadı.');
        const own = req.session.userId && String(req.session.userId) === String(p.candidateId);
        if (!req.session.isAdmin && !own) return res.status(403).send('Bu dosyaya erişim yetkiniz yok.');
        const r = p.receipts.id(req.params.rid);
        if (!r) return res.status(404).send('Dosya bulunamadı.');
        try { await storage.stream(r, res, { download: req.query.download === '1' }); } catch (e) { if (!res.headersSent) res.status(500).send('Dosya açılamadı.'); }
    });

    // ==================================================================
    //  ADMIN · DİJİTAL DOSYA
    // ==================================================================
    const adminBack = (id, anchor = 'dossier') => `/admin/candidate/${id}#${anchor}`;
    async function loadCand(req, res) {
        if (!isId(req.params.id)) { res.redirect('/admin?error=not_found'); return null; }
        const c = await Candidate.findById(req.params.id);
        if (!c) { res.redirect('/admin?error=not_found'); return null; }
        if (!c.dossier) c.dossier = {};
        return c;
    }

    app.post('/admin/candidate/:id/dossier/:section', adminAuthCheck, async (req, res) => {
        const c = await loadCand(req, res); if (!c) return;
        const key = req.params.section, back = adminBack(c._id);
        if (LOCK_OF[key]) { // iş / eğitim / sertifika
            const list = c.dossier[key];
            if (req.body._action === 'delete') { const it = isId(req.body.id) && list.id(req.body.id); if (!it) return res.redirect(withParam(back, 'error', 'not_found')); it.deleteOne(); }
            else {
                const r = readEntry(key, req.body);
                if (r.error) return res.redirect(withParam(back, 'error', r.error));
                if (isId(req.body.id)) { const it = list.id(req.body.id); if (!it) return res.redirect(withParam(back, 'error', 'not_found')); it.set(r.e); } else list.push(r.e);
            }
            c.dossier.updatedAt = new Date(); await c.save();
            await S().audit(req, 'dossier.update', 'Candidate', c._id, `${fullName(c)}: ${key} güncellendi`);
            return res.redirect(withParam(back, 'status', 'dossier_saved'));
        }
        const r = await readSection(key, req.body, c, Candidate);
        if (r.error) return res.redirect(withParam(back, 'error', r.error));
        await Candidate.updateOne({ _id: c._id }, { $set: r.set });
        await S().audit(req, 'dossier.update', 'Candidate', c._id, `${fullName(c)}: ${SECTIONS[key].label} güncellendi`);
        res.redirect(withParam(back, 'status', 'dossier_saved'));
    });

    app.post('/admin/candidate/:id/verify/:section', adminAuthCheck, async (req, res) => {
        const c = await loadCand(req, res); if (!c) return;
        const key = req.params.section, back = adminBack(c._id);
        if (!SECTIONS[key]) return res.redirect(withParam(back, 'error', 'invalid_action'));
        const cur = c.dossier.verified && c.dossier.verified[key] && c.dossier.verified[key].at;
        if (!cur) {
            const comp = completeness(c).sections[key];
            if (comp.filled < comp.total) return res.redirect(withParam(back, 'error', 'verify_incomplete'));
        }
        await Candidate.updateOne({ _id: c._id }, cur ? { $unset: { [`dossier.verified.${key}`]: 1 } } : { $set: { [`dossier.verified.${key}`]: { at: new Date(), by: 'Yönetici' } } });
        await S().audit(req, cur ? 'dossier.unverify' : 'dossier.verify', 'Candidate', c._id, `${fullName(c)}: ${SECTIONS[key].label} ${cur ? 'doğrulaması kaldırıldı' : 'doğrulandı'}`);
        res.redirect(withParam(back, 'status', cur ? 'unverified' : 'verified'));
    });

    // ---- Ödemeler ----
    async function getPayment(c, type, create) {
        let p = await Payment.findOne({ candidateId: c._id, type });
        if (!p && create) {
            try { p = await Payment.create({ candidateId: c._id, type, amount: Payment.TYPES[type].amount, history: [{ action: 'Ödeme işaretlendi', byType: 'admin', byName: 'Yönetici' }] }); }
            catch (e) { if (e.code === 11000) p = await Payment.findOne({ candidateId: c._id, type }); else throw e; } // eşzamanlı istekte mükerrer kayıt oluşmaz
            p._created = true;
        }
        return p;
    }

    app.post('/admin/candidate/:id/payment/:type/toggle', adminAuthCheck, async (req, res) => {
        const c = await loadCand(req, res); if (!c) return;
        const back = adminBack(c._id, 'payments');
        if (!Payment.TYPES[req.params.type]) return res.redirect(withParam(back, 'error', 'invalid_action'));
        const p = await getPayment(c, req.params.type, true);
        if (!p._created) {
            if (p.active && p.status === 'approved') return res.redirect(withParam(back, 'error', 'payment_approved_locked'));
            p.active = !p.active;
            p.history.push({ action: p.active ? 'Ödeme yeniden işaretlendi' : 'Ödeme işareti kaldırıldı', byType: 'admin', byName: 'Yönetici' });
            await p.save();
        }
        await S().audit(req, 'payment.toggle', 'Candidate', c._id, `${Payment.TYPES[p.type].label}: ${p.active ? 'işaretlendi' : 'işaret kaldırıldı'}`);
        if (p.active && p._created) await Message.create({ candidateId: c._id, sender: 'Admin', isRead: false, date: new Date(), content: `${Payment.TYPES[p.type].label} ödemesi (${p.amount} €) dosyanıza eklendi. Ödemeyi yaptıktan sonra dekontu "Ödemelerim" sayfasından yükleyebilirsiniz.` });
        res.redirect(withParam(back, 'status', p.active ? 'payment_marked' : 'payment_unmarked'));
    });

    app.post('/admin/candidate/:id/payment/:type/dekont', adminAuthCheck, uploadOne((req) => adminBack(req.params.id, 'payments')), async (req, res) => {
        const c = await loadCand(req, res); if (!c) return;
        const back = adminBack(c._id, 'payments');
        if (!Payment.TYPES[req.params.type]) return res.redirect(withParam(back, 'error', 'invalid_action'));
        const p = await getPayment(c, req.params.type, false);
        if (!p || !p.active) return res.redirect(withParam(back, 'error', 'payment_not_marked'));
        if (p.status === 'approved') return res.redirect(withParam(back, 'error', 'payment_approved_locked'));
        if (!req.file) return res.redirect(withParam(back, 'error', 'no_file'));
        if (!isAllowedFile(req.file, RECEIPT_MIMES)) return res.redirect(withParam(back, 'error', 'bad_type'));
        try {
            // İnceleme bekleyen eski dekont yenisiyle değiştirilirse geçmişte "yerine yenisi yüklendi" olarak kalır
            p.receipts.forEach(r => { if (r.review === 'pending') { r.review = 'rejected'; r.reviewNote = 'Yerine yeni dekont yüklendi'; r.reviewedAt = new Date(); } });
            p._candName = fullName(c);
            await addReceipt(p, req, req.file, 'admin', 'Yönetici');
            await p.save();
            await S().audit(req, 'payment.receipt_upload', 'Candidate', c._id, `${Payment.TYPES[p.type].label} dekontu yönetici tarafından yüklendi`);
            res.redirect(withParam(back, 'status', 'receipt_uploaded'));
        } catch (e) { console.error('Dekont yükleme hatası:', e.message); res.redirect(withParam(back, 'error', 'upload_failed')); }
    });

    app.post('/admin/candidate/:id/payment/:type/review', adminAuthCheck, async (req, res) => {
        const c = await loadCand(req, res); if (!c) return;
        const back = adminBack(c._id, 'payments');
        const p = Payment.TYPES[req.params.type] && await getPayment(c, req.params.type, false);
        if (!p || !p.active) return res.redirect(withParam(back, 'error', 'payment_not_marked'));
        const latest = p.receipts[p.receipts.length - 1];
        // Dekont yüklenmeden / inceleme dışı durumda onaylanamaz
        if (!latest || p.status !== 'under_review' || latest.review !== 'pending') return res.redirect(withParam(back, 'error', 'receipt_required'));
        const note = str(req.body.note, 500);
        const label = Payment.TYPES[p.type].label;
        if (req.body.decision === 'approve') {
            latest.review = 'approved'; latest.reviewedAt = new Date(); latest.reviewNote = note;
            p.status = 'approved'; p.approvedAt = new Date(); p.approvedBy = 'Yönetici';
            p.history.push({ action: 'Dekont onaylandı · ödeme tamamlandı', byType: 'admin', byName: 'Yönetici', note });
            await p.save();
            await Message.create({ candidateId: c._id, sender: 'Admin', isRead: false, date: new Date(), content: `${label} ödemeniz (${p.amount} €) onaylandı. Teşekkür ederiz.` });
        } else if (req.body.decision === 'reject') {
            if (note.length < 3) return res.redirect(withParam(back, 'error', 'reason_required_payment'));
            latest.review = 'rejected'; latest.reviewedAt = new Date(); latest.reviewNote = note;
            p.status = 'rejected'; p.rejectReason = note;
            p.history.push({ action: 'Dekont reddedildi', byType: 'admin', byName: 'Yönetici', note });
            await p.save();
            await Message.create({ candidateId: c._id, sender: 'Admin', isRead: false, date: new Date(), content: `${label} dekontunuz reddedildi: ${note}\nLütfen "Ödemelerim" sayfasından doğru dekontu yeniden yükleyin.` });
        } else return res.redirect(withParam(back, 'error', 'invalid_action'));
        await S().audit(req, `payment.${req.body.decision}`, 'Candidate', c._id, `${label} dekontu ${req.body.decision === 'approve' ? 'onaylandı' : 'reddedildi'}${note ? ': ' + note : ''}`);
        res.redirect(withParam(back, 'status', req.body.decision === 'approve' ? 'payment_approved' : 'payment_rejected'));
    });

    // ---- Belge arşivi (yönetici yüklemesi) ----
    app.post('/admin/candidate/:id/archive', adminAuthCheck, uploadOne((req) => adminBack(req.params.id, 'documents')), async (req, res) => {
        const c = await loadCand(req, res); if (!c) return;
        const back = adminBack(c._id, 'documents');
        const cat = DOC_CATEGORIES.includes(req.body.category) ? req.body.category : null;
        if (!cat) return res.redirect(withParam(back, 'error', 'missing_fields'));
        if (!req.file) return res.redirect(withParam(back, 'error', 'no_file'));
        if (!isAllowedFile(req.file, DOC_MIMES)) return res.redirect(withParam(back, 'error', 'bad_type'));
        try {
            const saved = await storage.save(req.file, fullName(c), { type: 'candidate', id: c._id });
            const name = str(req.body.name, 120) || cat;
            await Candidate.updateOne({ _id: c._id }, { $push: { documents: { name, category: cat, filename: saved.name, fileId: saved.fileId, driveLink: saved.driveLink, blobId: saved.blobId, mimeType: saved.mimeType, size: saved.size, status: 'Onaylandı', uploadedBy: 'admin', date: new Date() } } });
            await S().audit(req, 'document.admin_upload', 'Candidate', c._id, `${fullName(c)}: ${cat} · ${saved.name}`);
            res.redirect(withParam(back, 'status', 'document_uploaded'));
        } catch (e) { console.error('Arşiv yükleme hatası:', e.message); res.redirect(withParam(back, 'error', 'upload_failed')); }
    });
    app.post('/admin/candidate/:id/document/:docId/category', adminAuthCheck, async (req, res) => {
        const c = await loadCand(req, res); if (!c) return;
        const back = adminBack(c._id, 'documents');
        if (!DOC_CATEGORIES.includes(req.body.category) || !isId(req.params.docId)) return res.redirect(withParam(back, 'error', 'invalid_action'));
        const d = c.documents.id(req.params.docId);
        if (!d) return res.redirect(withParam(back, 'error', 'not_found'));
        d.category = req.body.category; await c.save();
        res.redirect(withParam(back, 'status', 'document_updated'));
    });

    mongoose.connection.once('open', () => { Payment.syncIndexes().catch(e => console.error('Ödeme indeks hatası:', e.message)); });
    app.locals.dossier = { completeness, categoryOf, tcValid, SECTIONS };
};
module.exports.tcValid = tcValid;
module.exports.categoryOf = categoryOf;
module.exports.completeness = completeness;
