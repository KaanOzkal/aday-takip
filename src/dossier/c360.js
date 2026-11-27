// Aday 360° Dijital Dosya — yönetici aday detay ekranı için veri birleştirme,
// profil fotoğrafı, personel notları ve değişiklik geçmişi.
const mongoose = require('mongoose');
const AuditLog = require('../models/AuditLog');
const Payment = require('../models/Payment');
const { categoryOf, completeness } = require('./index');
const { byName, byKey, STAGE_DEFS } = require('../process/stages');

const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const fullName = (c) => `${c.firstName || ''} ${c.lastName || ''}`.trim();
const withParam = (url, k, v) => { const u = new URL(url, 'http://x'); u.searchParams.delete('status'); u.searchParams.delete('error'); u.searchParams.set(k, v); return u.pathname + u.search + u.hash; };
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

// Dosyada bulunması beklenen temel belgeler (eşleştirme: arşiv kategorisi veya belge adı)
const REQUIRED_DOCS = [
    { key: 'passport', label: 'Pasaport', icon: 'fa-passport', test: (d, cat) => cat === 'Pasaport' },
    { key: 'id', label: 'Kimlik', icon: 'fa-id-card', test: (d, cat) => cat === 'Kimlik' },
    { key: 'license', label: 'Ehliyet', icon: 'fa-id-badge', test: (d, cat) => cat === 'Ehliyet' },
    { key: 'cv', label: 'CV', icon: 'fa-file-lines', test: (d, cat) => cat === 'CV' },
    { key: 'work', label: 'İş Deneyimi Belgesi', icon: 'fa-briefcase', test: (d, cat) => cat === 'İş Deneyimi' },
    { key: 'health', label: 'Sağlık Raporu', icon: 'fa-heart-pulse', test: (d, cat) => cat === 'Sağlık' }
];
const DOC_RANK = { 'Onaylandı': 3, 'İnceleniyor': 2, 'Reddedildi': 1 };

function requiredDocs(c) {
    const docs = c.documents || [];
    return REQUIRED_DOCS.map(r => {
        const m = docs.filter(d => r.test(d, categoryOf(d))).sort((a, b) => (DOC_RANK[b.status] || 0) - (DOC_RANK[a.status] || 0) || new Date(b.date || 0) - new Date(a.date || 0));
        const best = m[0] || null;
        const state = !best ? 'missing' : best.status === 'Onaylandı' ? 'approved' : best.status === 'Reddedildi' ? 'rejected' : 'pending';
        return { ...r, test: undefined, doc: best, count: m.length, state, done: state === 'approved' || state === 'pending' };
    });
}

const ageOf = (d) => { if (!d) return null; const b = new Date(d), n = new Date(); let a = n.getFullYear() - b.getFullYear(); if (n.getMonth() < b.getMonth() || (n.getMonth() === b.getMonth() && n.getDate() < b.getDate())) a--; return a; };

// Audit eylemlerinin okunur karşılığı (süreç geçmişi için)
const AUDIT_LABEL = {
    'candidate.edit': ['Temel bilgiler güncellendi', 'fa-user-pen'], 'candidate.company': ['Şirket değiştirildi', 'fa-building'],
    'candidate.note': ['Not eklendi', 'fa-note-sticky'], 'candidate.note_delete': ['Not silindi', 'fa-note-sticky'],
    'candidate.photo': ['Profil fotoğrafı', 'fa-camera'], 'candidate.cancel': ['Aday iptal edildi', 'fa-ban'], 'candidate.reactivate': ['Aday yeniden aktifleştirildi', 'fa-rotate-left'],
    'dossier.save': ['Dosya bilgisi güncellendi', 'fa-folder-open'], 'dossier.verify': ['Bölüm doğrulandı', 'fa-circle-check'], 'dossier.unverify': ['Doğrulama kaldırıldı', 'fa-lock-open'],
    'document.remove': ['Belge kaydı kaldırıldı', 'fa-file-circle-xmark'], 'document.archive': ['Belge arşive eklendi', 'fa-file-arrow-up'], 'document.category': ['Belge kategorisi değişti', 'fa-tags'],
    'payment.toggle': ['Ödeme takibi', 'fa-euro-sign'], 'payment.review': ['Ödeme incelendi', 'fa-euro-sign'], 'payment.receipt': ['Dekont yüklendi', 'fa-receipt'],
    'cv.update': ['CV güncellendi', 'fa-file-lines'], 'dossier.update': ['Dosya bilgisi güncellendi', 'fa-folder-open'],
    'document.admin_upload': ['Belge yüklendi (yönetici)', 'fa-file-arrow-up'], 'document.status_change': ['Belge durumu değişti', 'fa-file-circle-check'],
    'automation.run': ['Otomasyon elle çalıştırıldı', 'fa-robot'], 'automation.retry': ['Otomasyon yeniden denendi', 'fa-robot'], 'candidate.stage_update': ['Aşama kaydı güncellendi', 'fa-diagram-project']
};
const EV_ICON = { stage_change: 'fa-diagram-project', automation: 'fa-robot', status: 'fa-flag', task: 'fa-clipboard-check', migrated: 'fa-database', cancel: 'fa-ban', note: 'fa-note-sticky' };

module.exports = function mountC360(app, deps) {
    const { adminAuthCheck, Candidate, upload } = deps;
    const S = () => app.locals.services;

    // Tüm kaynaklardan kronolojik süreç geçmişi
    async function history(c, { limit = 400 } = {}) {
        const id = c._id;
        const { ProcessEvent, CandidateContact, WorkOrder } = mongoose.models;
        const [events, audits, pays, contacts, orders] = await Promise.all([
            ProcessEvent ? ProcessEvent.find({ candidateId: id }).sort({ createdAt: -1 }).limit(300).lean() : [],
            AuditLog.find({ targetType: 'Candidate', targetId: String(id) }).sort({ createdAt: -1 }).limit(300).lean(),
            Payment.find({ candidateId: id }).lean(),
            CandidateContact ? CandidateContact.find({ candidateId: id }).sort({ contactAt: -1 }).limit(200).lean() : [],
            WorkOrder ? WorkOrder.find({ candidateId: id }).select('code title history assignedTo').populate('assignedTo', 'fullName').lean() : []
        ]);
        const items = [];
        const push = (at, kind, icon, title, text, by) => { if (at) items.push({ at: new Date(at), kind, icon, title, text: text || '', by: by || '' }); };
        push(c.applicationDate || c.createdAt, 'system', 'fa-user-plus', 'Başvuru alındı', c.applicationNo ? 'Başvuru no: ' + c.applicationNo : '', 'Sistem');
        events.forEach(e => push(e.createdAt, 'process', EV_ICON[e.type] || 'fa-diagram-project', e.type === 'stage_change' ? 'Aşama değişikliği' : e.type === 'automation' ? 'Otomasyon' : 'Süreç', e.text, e.actorName));
        // Aşama değişikliklerinin denetim kopyaları süreç olaylarıyla aynıdır; tekrar gösterme
        audits.filter(a => !/^candidate\.stage_(change|resolve)/.test(a.action) && !/^payment\./.test(a.action) && !['candidate.contact', 'candidate.note', 'candidate.document_view', 'candidate.login_denied', 'cv.generate', 'document.admin_upload'].includes(a.action)).forEach(a => {
            const [t, ic] = AUDIT_LABEL[a.action] || ['İşlem', 'fa-pen'];
            push(a.createdAt, 'audit', ic, t, (a.summary || '').replace(/^[^:]{0,60}:\s*/, ''), a.actorName);
        });
        pays.forEach(p => (p.history || []).forEach(h => push(h.at, 'payment', 'fa-euro-sign', `${(Payment.TYPES[p.type] || {}).label || 'Ödeme'} · ${h.action}`, h.note, h.byName)));
        (c.documents || []).forEach(d => push(d.date, 'document', 'fa-file-arrow-up', 'Belge yüklendi', `${d.name || 'Belge'} · ${categoryOf(d)}`, d.uploadedBy === 'admin' ? 'Yönetici' : d.uploadedBy === 'staff' ? 'Personel' : 'Aday'));
        contacts.forEach(k => push(k.contactAt, 'contact', 'fa-phone', 'İletişim kaydı', [k.subject, k.summary].filter(Boolean).join(' — ').slice(0, 240), k.authorName));
        orders.forEach(o => (o.history || []).filter(h => ['Oluşturuldu', 'Tamamlandı', 'Onaylandı', 'İptal'].some(x => (h.action || '').startsWith(x)))
            .forEach(h => push(h.at, 'task', 'fa-clipboard-check', `İş emri · ${h.action}`, `${o.code} ${o.title}${o.assignedTo ? ' → ' + o.assignedTo.fullName : ''}`, h.byName)));
        (c.notes || []).forEach(n => push(n.date, 'note', 'fa-note-sticky', n.authorType === 'staff' ? 'Personel notu' : 'Yönetici notu', String(n.content || '').slice(0, 200), n.authorName || n.author));
        items.sort((a, b) => b.at - a.at);
        return items.slice(0, limit);
    }

    // Ekran için tüm özet hesaplar
    app.locals.c360For = async (c, dossier, pipeline) => {
        const comp = (dossier && dossier.completeness) || completeness(c);
        const req = requiredDocs(c);
        const docsDone = req.filter(r => r.done).length;
        const total = comp.total + req.length;
        const pct = Math.round((comp.filled + docsDone) / total * 100);
        const payments = (dossier ? dossier.payments : []).filter(p => p.record && p.record.active);
        const payDone = payments.filter(p => p.record.status === 'approved').length;
        const hist = await history(c);
        // Sonraki adım: mevcut aşamadan bir sonraki aşama ve tahmini süresi (aşama tanımından)
        const cur = byName[c.currentStage];
        const next = cur && cur.index < STAGE_DEFS.length - 1 ? byKey[STAGE_DEFS[cur.index + 1].key] : null;
        // Aşamaların tamamlanma tarihleri
        const stageDates = {};
        if (pipeline && pipeline.stages) pipeline.stages.forEach(s => { stageDates[s.key] = s.state && (s.state.completedAt || s.state.startedAt); });
        const pending = [];
        req.filter(r => r.state === 'missing' || r.state === 'rejected').forEach(r => pending.push({ kind: 'doc', label: r.label + (r.state === 'rejected' ? ' (reddedildi)' : '') }));
        payments.filter(p => p.record.status !== 'approved').forEach(p => pending.push({ kind: 'payment', label: p.label + ' ödemesi' }));
        comp.missing.forEach(m => pending.push({ kind: 'info', label: m.label }));
        const docsReview = (c.documents || []).filter(d => d.status === 'İnceleniyor').length;
        return {
            pct, comp, req, docsDone, payments, payDone, history: hist, next, cur, stageDates, pending, docsReview,
            missingInfo: comp.missing.length, missingDocs: req.length - docsDone,
            age: ageOf(c.dossier && c.dossier.birthDate),
            photo: c.cvDetails && /^data:image\/(jpeg|png|webp);base64,/.test(c.cvDetails.profilePhoto || '') ? c.cvDetails.profilePhoto : null,
            staffNotes: (c.notes || []).filter(n => n.authorType === 'staff').length
        };
    };

    // ---------------- Profil fotoğrafı (yönetici) ----------------
    app.post('/admin/candidate/:id/photo', adminAuthCheck, (req, res, next) => upload.single('photo')(req, res, (err) => {
        if (err) return res.redirect(withParam(`/admin/candidate/${req.params.id}#overview`, 'error', err.code === 'LIMIT_FILE_SIZE' ? 'too_large' : 'upload_failed'));
        next();
    }), async (req, res) => {
        const back = `/admin/candidate/${req.params.id}#overview`;
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const c = await Candidate.findById(req.params.id).select('firstName lastName cvDetails');
        if (!c) return res.redirect('/admin?error=not_found');
        if (req.body.remove === '1') {
            await Candidate.updateOne({ _id: c._id }, { $set: { 'cvDetails.profilePhoto': '' } });
            await S().audit(req, 'candidate.photo', 'Candidate', c._id, `${fullName(c)}: profil fotoğrafı kaldırıldı`);
            return res.redirect(withParam(back, 'status', 'photo_removed'));
        }
        const f = req.file;
        if (!f) return res.redirect(withParam(back, 'error', 'no_file'));
        if (!['image/jpeg', 'image/png'].includes(f.mimetype)) return res.redirect(withParam(back, 'error', 'photo_type'));
        if (f.size > 2 * 1024 * 1024) return res.redirect(withParam(back, 'error', 'photo_large'));
        // İçerik imzası kontrolü (uzantı/mime taklidine karşı)
        const b = f.buffer; const okSig = (b[0] === 0xFF && b[1] === 0xD8) || (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47);
        if (!okSig) return res.redirect(withParam(back, 'error', 'photo_type'));
        await Candidate.updateOne({ _id: c._id }, { $set: { 'cvDetails.profilePhoto': `data:${f.mimetype};base64,${b.toString('base64')}` } });
        await S().audit(req, 'candidate.photo', 'Candidate', c._id, `${fullName(c)}: profil fotoğrafı güncellendi`);
        res.redirect(withParam(back, 'status', 'photo_saved'));
    });

    // ---------------- Personel notu ----------------
    // Personel yalnızca kendisine atanmış, iptal edilmemiş görevin adayına not ekleyebilir.
    app.post('/personel/gorev/:id/note', (req, res, next) => app.locals.staffAuth(req, res, next), async (req, res) => {
        const wo = await app.locals.ownTask(req, res); if (!wo) return;
        const back = `/personel/gorev/${wo._id}#cnotes`;
        if (wo.status === 'İptal' || !wo.candidateId) return res.redirect(withParam(back, 'error', 'invalid_state'));
        const content = str(req.body.content, 4000);
        if (content.length < 2) return res.redirect(withParam(back, 'error', 'missing_fields'));
        const c = await Candidate.findById(wo.candidateId).select('firstName lastName');
        if (!c) return res.redirect(withParam(back, 'error', 'not_found'));
        await Candidate.updateOne({ _id: c._id }, { $push: { notes: { content, date: new Date(), author: req.staff.fullName, authorType: 'staff', authorName: req.staff.fullName, workOrderId: wo._id } }, $set: { lastActivityAt: new Date() } });
        await S().audit(req, 'candidate.note', 'Candidate', c._id, `${fullName(c)}: personel notu eklendi (${wo.code})`);
        await S().notify({ recipientType: 'admin', type: 'updated', title: 'Personel notu', message: `${req.staff.fullName} · ${fullName(c)}: ${content.slice(0, 120)}`, link: `/admin/candidate/${c._id}#notes` }).catch(() => {});
        res.redirect(withParam(back, 'status', 'note_added'));
    });
    // Görev ekranında: bu adaya ait personel notları (yönetici notları personele gösterilmez)
    app.locals.staffCandidateNotes = async (candidateId) => {
        const c = await Candidate.findById(candidateId).select('notes').lean();
        return ((c && c.notes) || []).filter(n => n.authorType === 'staff').sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 50);
    };

    app.locals.REQUIRED_DOCS = REQUIRED_DOCS.map(r => ({ key: r.key, label: r.label, icon: r.icon }));
};
module.exports.requiredDocs = requiredDocs;
module.exports.ageOf = ageOf;
