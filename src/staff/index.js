// =====================================================================
//  PERSONEL YÖNETİMİ · İŞ EMİRLERİ · BİLDİRİMLER · İŞLEM GEÇMİŞİ
//  app.js içinden mountStaffSystem(app, deps) ile bağlanır.
// =====================================================================
const mongoose = require('mongoose');
const Staff = require('../models/Staff');
const WorkOrder = require('../models/WorkOrder');
const Notification = require('../models/Notification');
const AuditLog = require('../models/AuditLog');
const { hashPassword, verifyPassword, passwordProblem, randomToken, sha256, loginLimiter } = require('../lib/security');
const rt = require('../lib/realtime');

const { STATUSES, PRIORITIES, CATEGORIES } = WorkOrder;
const OPEN = ['Yeni', 'Devam Ediyor', 'Revizyon'];
const PRIORITY_RANK = { 'Acil': 0, 'Yüksek': 1, 'Normal': 2, 'Düşük': 3 };
const SENSITIVE_CATEGORIES = ['Vize İşlemleri', 'Tercüme', 'Evrak Takibi', 'Seyahat & Konaklama'];
const INVITE_HOURS = 72;

const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const esc = (s = '') => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const parseDate = (v) => { if (!v) return null; const d = new Date(v); return isNaN(d) ? null : d; };
// "YYYY-MM-DD" gelirse Türkiye saatiyle gün sonu (23:59) kabul edilir
const endOfDay = (v) => { if (!v) return null; if (/^\d{4}-\d{2}-\d{2}$/.test(String(v))) { const d = new Date(`${v}T23:59:00+03:00`); return isNaN(d) ? null : d; } return parseDate(v); };
const isOverdue = (w) => !!(w.dueDate && OPEN.includes(w.status) && new Date(w.dueDate) < new Date());
const baseUrl = (req) => (process.env.APP_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
const safeBack = (req, fallback) => { const r = req.body && req.body.returnTo; return (typeof r === 'string' && r.startsWith('/admin') && !r.startsWith('//')) ? r : fallback; };
const withParam = (url, k, v) => { const u = new URL(url, 'http://x'); u.searchParams.delete('status'); u.searchParams.delete('error'); u.searchParams.set(k, v); return u.pathname + u.search + u.hash; };

module.exports = function mountStaffSystem(app, deps) {
    const { adminAuthCheck, Candidate, uploadToGoogleDrive, transporter, upload, google, getMailFrom } = deps;

    // ------------------------------------------------------------------
    //  Ortak yardımcılar
    // ------------------------------------------------------------------
    const actorOf = (req) => {
        if (req.staff) return { type: 'staff', id: String(req.staff._id), name: req.staff.fullName };
        if (req.session && req.session.isAdmin) return { type: 'admin', id: 'admin', name: 'Yönetici' };
        return { type: 'anonymous', id: '', name: 'Ziyaretçi' };
    };

    async function audit(req, action, targetType, targetId, summary, actor) {
        try {
            const a = actor || actorOf(req);
            await AuditLog.create({
                actorType: a.type, actorId: a.id, actorName: a.name, action, targetType,
                targetId: targetId ? String(targetId) : '', summary: String(summary || '').slice(0, 500),
                ip: req ? (req.ip || '') : '', userAgent: req ? String(req.get('user-agent') || '').slice(0, 200) : ''
            });
        } catch (e) { console.error('Audit log hatası:', e.message); }
    }

    async function unreadFor(recipientType, recipientId) {
        const q = { recipientType, isRead: false };
        if (recipientType === 'staff') q.recipientId = recipientId;
        return Notification.countDocuments(q);
    }

    async function notify({ recipientType, recipientId, type, title, message, workOrder }) {
        try {
            const link = workOrder ? (recipientType === 'staff' ? `/personel/gorev/${workOrder._id}` : `/admin/is-emirleri/${workOrder._id}`) : (recipientType === 'staff' ? '/personel/bildirimler' : '/admin/bildirimler');
            const n = await Notification.create({ recipientType, recipientId: recipientType === 'staff' ? recipientId : undefined, type, title, message, link, workOrderId: workOrder ? workOrder._id : undefined });
            const key = recipientType === 'staff' ? `staff:${recipientId}` : 'admin';
            const unread = await unreadFor(recipientType, recipientId);
            rt.publish(key, 'notification', { id: String(n._id), type, title, message, link: `/n/${n._id}`, unread, createdAt: n.createdAt });
            return n;
        } catch (e) { console.error('Bildirim hatası:', e.message); }
    }

    const pushHistory = (wo, req, action, note) => {
        const a = actorOf(req);
        wo.history.push({ action, byType: a.type, byName: a.name, note: note ? String(note).slice(0, 600) : '' });
    };

    // Ortak iş emri oluşturma servisi (admin formu, süreç otomasyonu ve AI asistanı kullanır)
    async function createWorkOrder(o) {
        const { candidate, staff, actor } = o;
        const wo = new WorkOrder({
            code: await nextCode(), candidateId: candidate._id, candidateName: `${candidate.firstName || ''} ${candidate.lastName || ''}`.trim(),
            category: CATEGORIES.includes(o.category) ? o.category : 'Diğer', title: String(o.title).slice(0, 160), description: String(o.description || '').slice(0, 6000),
            assignedTo: staff._id, priority: PRIORITIES.includes(o.priority) ? o.priority : 'Normal', startDate: o.startDate || new Date(), dueDate: o.dueDate || null,
            adminNote: String(o.adminNote || '').slice(0, 4000), status: 'Yeni',
            stageKey: o.stageKey || undefined, templateId: o.templateId || undefined, automationKey: o.automationKey || undefined, source: o.source || 'manual'
        });
        wo.history.push({ action: 'Oluşturuldu', byType: actor.type, byName: actor.name, note: o.historyNote || `${staff.fullName} kişisine atandı` });
        await wo.save();
        await notify({ recipientType: 'staff', recipientId: staff._id, type: 'assigned', title: 'Yeni iş emri atandı', message: `${wo.code} · ${wo.title} (${wo.candidateName})`, workOrder: wo });
        fireHook(wo, 'created', actor);
        return wo;
    }

    // Süreç modülüne iş emri olaylarını bildir (aday süreç geçmişi için)
    const fireHook = (wo, action, actor) => { try { if (app.locals.processHooks) app.locals.processHooks.workOrder(wo, action, actor); } catch (e) { console.error('Süreç kancası hatası:', e.message); } };

    async function nextCode() {
        const last = await WorkOrder.findOne({ code: /^IE-\d+$/ }).sort({ createdAt: -1 }).select('code').lean();
        const n = last ? parseInt(last.code.slice(3), 10) + 1 : 1;
        return 'IE-' + String(n).padStart(5, '0');
    }

    function driveClient() {
        const auth = new google.auth.OAuth2(process.env.CLIENT_ID, process.env.CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
        auth.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
        return google.drive({ version: 'v3', auth });
    }

    async function streamDriveFile(fileId, res) {
        const drive = driveClient();
        const meta = await drive.files.get({ fileId, fields: 'mimeType, name' });
        res.setHeader('Content-Type', meta.data.mimeType);
        res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(meta.data.name)}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        const r = await drive.files.get({ fileId, alt: 'media' }, { responseType: 'stream' });
        r.data.on('error', () => { if (!res.headersSent) res.status(500).end(); }).pipe(res);
    }

    // multer hatalarını kullanıcı dostu yönlendirmeye çevir
    const uploadSingle = (field, back) => (req, res, next) => upload.single(field)(req, res, (err) => {
        if (err) return res.redirect(withParam(back(req), 'error', err.code === 'LIMIT_FILE_SIZE' ? 'too_large' : 'upload_failed'));
        next();
    });
    const ALLOWED = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'image/heic', 'image/heif',
        'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];

    async function attachFile(req, wo, type) {
        if (!req.file) return null;
        if (!ALLOWED.includes(req.file.mimetype)) throw Object.assign(new Error('bad_type'), { code: 'bad_type' });
        const folder = `İş Emirleri - ${wo.candidateName || 'Aday'}`;
        const f = await uploadToGoogleDrive(req.file, folder);
        const a = actorOf(req);
        wo.attachments.push({ name: req.file.originalname, fileId: f.id, driveLink: f.webViewLink, mimeType: req.file.mimetype, size: req.file.size, uploadedByType: type, uploadedByName: a.name });
        return f;
    }

    async function sendMail(to, subject, html) {
        if (!to) return false;
        try { await transporter.sendMail({ from: getMailFrom(), to, subject, html }); return true; }
        catch (e) { console.error('Mail gönderilemedi:', e.message); return false; }
    }

    function computeStats(list) {
        const done = list.filter(w => w.status === 'Tamamlandı');
        const durations = done.filter(w => w.completedAt).map(w => (new Date(w.completedAt) - new Date(w.startedAt || w.createdAt)) / 36e5);
        return {
            total: list.filter(w => w.status !== 'İptal').length,
            newCount: list.filter(w => w.status === 'Yeni').length,
            inProgress: list.filter(w => w.status === 'Devam Ediyor' || w.status === 'Revizyon').length,
            completed: done.length,
            overdue: list.filter(isOverdue).length,
            cancelled: list.filter(w => w.status === 'İptal').length,
            avgHours: durations.length ? durations.reduce((a, b) => a + b, 0) / durations.length : null,
            onTime: done.filter(w => !w.dueDate || new Date(w.completedAt) <= new Date(w.dueDate)).length
        };
    }

    const fmtDuration = (h) => h == null ? '—' : h < 1 ? `${Math.max(1, Math.round(h * 60))} dk` : h < 48 ? `${h.toFixed(1)} sa` : `${(h / 24).toFixed(1)} gün`;
    app.locals.fmtDuration = fmtDuration;
    app.locals.woIsOverdue = isOverdue;
    // Görünüm yardımcıları (admin ve personel şablonları ortak kullanır)
    app.locals.woStatusTone = (s) => ({ 'Yeni': 't-brand', 'Devam Ediyor': 't-info', 'Revizyon': 't-warn', 'Tamamlandı': 't-ok', 'İptal': 't-gray' })[s] || 't-gray';
    app.locals.woPriorityTone = (p) => ({ 'Acil': 't-bad', 'Yüksek': 't-warn', 'Normal': 't-brand', 'Düşük': 't-gray' })[p] || 't-gray';
    app.locals.woPriorityIcon = (p) => ({ 'Acil': 'fa-angles-up', 'Yüksek': 'fa-angle-up', 'Normal': 'fa-minus', 'Düşük': 'fa-angle-down' })[p] || 'fa-minus';
    app.locals.notifIcon = (t) => ({ assigned: ['fa-clipboard-list', 't-brand'], updated: ['fa-pen', 't-info'], cancelled: ['fa-ban', 't-gray'], due_soon: ['fa-hourglass-half', 't-warn'], overdue: ['fa-triangle-exclamation', 't-bad'], comment: ['fa-comment-dots', 't-info'], completed: ['fa-circle-check', 't-ok'], revision: ['fa-rotate-left', 't-warn'], started: ['fa-play', 't-brand'] })[t] || ['fa-bell', 't-gray'];
    app.locals.fmtDT = (d, withTime = true) => { if (!d) return '—'; const x = new Date(d); if (isNaN(x)) return '—'; return x.toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', day: '2-digit', month: 'short', year: 'numeric', ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {}) }); };
    app.locals.fmtAgo = (d) => { const s = (Date.now() - new Date(d)) / 1000; if (s < 60) return 'az önce'; if (s < 3600) return Math.floor(s / 60) + ' dk önce'; if (s < 86400) return Math.floor(s / 3600) + ' sa önce'; if (s < 7 * 86400) return Math.floor(s / 86400) + ' gün önce'; return new Date(d).toLocaleDateString('tr-TR', { timeZone: 'Europe/Istanbul', day: 'numeric', month: 'short' }); };
    app.locals.dueLabel = (w) => { if (!w.dueDate) return null; const ms = new Date(w.dueDate) - Date.now(); const open = OPEN.includes(w.status); if (!open) return null; if (ms < 0) { const d = Math.ceil(-ms / 864e5); return { text: d <= 1 ? 'Gecikti' : `${d} gün gecikti`, tone: 't-bad' }; } const h = ms / 36e5; if (h < 24) return { text: 'Bugün / 24 sa içinde', tone: 't-warn' }; const d = Math.ceil(h / 24); return { text: `${d} gün kaldı`, tone: d <= 3 ? 't-warn' : 't-gray' }; };

    // ------------------------------------------------------------------
    //  Admin: menü rozetleri için sayaç (tüm /admin GET sayfaları)
    // ------------------------------------------------------------------
    app.use('/admin', async (req, res, next) => {
        if (req.session && req.session.isAdmin && req.method === 'GET') {
            try {
                const [n, review] = await Promise.all([
                    Notification.countDocuments({ recipientType: 'admin', isRead: false }),
                    WorkOrder.countDocuments({ status: 'Tamamlandı', 'history.action': { $ne: 'Onaylandı' } })
                ]);
                res.locals.adminUnread = n;
                res.locals.woToReview = review;
            } catch (e) { /* sayaç hatası paneli bozmasın */ }
        }
        next();
    });

    // Bildirim tıklama yönlendirmesi (sahiplik kontrolüyle)
    app.get('/n/:id', async (req, res) => {
        if (!isId(req.params.id)) return res.redirect('/');
        const n = await Notification.findById(req.params.id);
        if (!n) return res.redirect(req.session.isAdmin ? '/admin/bildirimler' : '/personel/bildirimler');
        const okAdmin = n.recipientType === 'admin' && req.session.isAdmin;
        const okStaff = n.recipientType === 'staff' && req.session.staffId && String(n.recipientId) === String(req.session.staffId);
        if (!okAdmin && !okStaff) return res.redirect(n.recipientType === 'admin' ? '/admin/login' : '/personel');
        if (!n.isRead) { n.isRead = true; n.readAt = new Date(); await n.save(); }
        res.redirect(n.link || '/');
    });

    // ==================================================================
    //  ADMIN · PERSONEL YÖNETİMİ
    // ==================================================================
    app.get('/admin/personel', adminAuthCheck, async (req, res) => {
        const q = str(req.query.q, 80).toLocaleLowerCase('tr-TR');
        const show = ['active', 'passive', 'deleted', 'all'].includes(req.query.show) ? req.query.show : 'current';
        const filter = show === 'deleted' ? { deletedAt: { $ne: null } } : show === 'all' ? {} : { deletedAt: null };
        if (show === 'active') filter.status = 'active';
        if (show === 'passive') filter.status = 'passive';
        let staff = await Staff.find(filter).sort({ fullName: 1 }).lean();
        if (q) staff = staff.filter(s => [s.fullName, s.username, s.email, s.title, s.phone].join(' ').toLocaleLowerCase('tr-TR').includes(q));
        const orders = await WorkOrder.find({ assignedTo: { $in: staff.map(s => s._id) } }).select('assignedTo status dueDate createdAt startedAt completedAt').lean();
        const rows = staff.map(s => ({ ...s, stats: computeStats(orders.filter(o => String(o.assignedTo) === String(s._id))) }));
        const allCounts = {
            active: await Staff.countDocuments({ deletedAt: null, status: 'active' }),
            passive: await Staff.countDocuments({ deletedAt: null, status: 'passive' }),
            deleted: await Staff.countDocuments({ deletedAt: { $ne: null } })
        };
        res.render('admin_staff', { rows, q: req.query.q || '', show, allCounts, totals: computeStats(orders), user: { firstName: 'Admin' } });
    });

    function issueInvite(staff, req) {
        const token = randomToken(32);
        staff.inviteTokenHash = sha256(token);
        staff.inviteExpires = new Date(Date.now() + INVITE_HOURS * 36e5);
        return `${baseUrl(req)}/personel/davet/${token}`;
    }

    function inviteMailHtml(staff, link, reset) {
        return `<div style="font-family:Arial,sans-serif;background:#f4f6fb;padding:24px"><div style="max-width:560px;margin:auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden">
        <div style="background:#0b1220;color:#fff;padding:16px 22px;font-weight:bold;letter-spacing:1px">BERLINER · Personel Paneli</div>
        <div style="padding:22px;color:#1f2937;font-size:15px;line-height:1.6"><p>Merhaba ${esc(staff.fullName)},</p>
        <p>${reset ? 'Şifre sıfırlama talebiniz oluşturuldu.' : 'BERLINER personel paneline davet edildiniz.'} Aşağıdaki bağlantıdan şifrenizi belirleyebilirsiniz. Bağlantı ${INVITE_HOURS} saat geçerlidir.</p>
        <p><a href="${esc(link)}" style="display:inline-block;background:#2F54EB;color:#fff;text-decoration:none;padding:12px 20px;border-radius:10px;font-weight:bold">Şifremi Belirle</a></p>
        <p style="color:#6b7280;font-size:13px">Kullanıcı adınız: <b>${esc(staff.username)}</b></p></div></div></div>`;
    }

    app.post('/admin/personel', adminAuthCheck, async (req, res) => {
        const back = '/admin/personel';
        try {
            const fullName = str(req.body.fullName, 120);
            const username = str(req.body.username, 60).toLowerCase();
            const email = str(req.body.email, 160).toLowerCase();
            const mode = req.body.mode === 'invite' ? 'invite' : 'password';
            if (!fullName || !username) return res.redirect(withParam(back, 'error', 'missing_fields'));
            if (!/^[a-z0-9._-]{3,40}$/.test(username)) return res.redirect(withParam(back, 'error', 'bad_username'));
            if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.redirect(withParam(back, 'error', 'bad_email'));
            if (await Staff.exists({ username })) return res.redirect(withParam(back, 'error', 'username_taken'));
            const staff = new Staff({ fullName, username, email, phone: str(req.body.phone, 40), title: str(req.body.title, 80), status: req.body.status === 'passive' ? 'passive' : 'active' });
            let link = null;
            if (mode === 'password') {
                if (passwordProblem(req.body.password)) return res.redirect(withParam(back, 'error', 'weak_password'));
                staff.passwordHash = await hashPassword(req.body.password);
            } else {
                link = issueInvite(staff, req);
            }
            await staff.save();
            let mailed = false;
            if (link) mailed = await sendMail(email, 'BERLINER Personel Paneli Daveti', inviteMailHtml(staff, link));
            await audit(req, 'staff.create', 'Staff', staff._id, `${fullName} (${username}) oluşturuldu · ${mode === 'invite' ? 'davet bağlantısı' : 'şifre ile'}`);
            req.session.staffFlash = { kind: link ? 'invite' : 'created', name: fullName, username, link, mailed };
            res.redirect(`/admin/personel/${staff._id}?status=staff_created`);
        } catch (e) {
            console.error('Personel oluşturma hatası:', e);
            res.redirect(withParam(back, 'error', e.code === 11000 ? 'username_taken' : 'create_failed'));
        }
    });

    app.get('/admin/personel/:id', adminAuthCheck, async (req, res) => {
        if (!isId(req.params.id)) return res.redirect('/admin/personel?error=not_found');
        const staff = await Staff.findById(req.params.id).lean();
        if (!staff) return res.redirect('/admin/personel?error=not_found');
        const orders = await WorkOrder.find({ assignedTo: staff._id }).sort({ createdAt: -1 }).select('-history -comments -attachments').lean();
        const logs = await AuditLog.find({ $or: [{ targetType: 'Staff', targetId: String(staff._id) }, { actorType: 'staff', actorId: String(staff._id) }] }).sort({ createdAt: -1 }).limit(40).lean();
        const flash = req.session.staffFlash || null; delete req.session.staffFlash;
        res.render('admin_staff_detail', { staff, orders, stats: computeStats(orders), logs, flash, user: { firstName: 'Admin' } });
    });

    app.post('/admin/personel/:id/edit', adminAuthCheck, async (req, res) => {
        const back = `/admin/personel/${req.params.id}`;
        try {
            const s = isId(req.params.id) && await Staff.findById(req.params.id);
            if (!s) return res.redirect('/admin/personel?error=not_found');
            const fullName = str(req.body.fullName, 120), username = str(req.body.username, 60).toLowerCase(), email = str(req.body.email, 160).toLowerCase();
            if (!fullName || !/^[a-z0-9._-]{3,40}$/.test(username)) return res.redirect(withParam(back, 'error', 'bad_username'));
            if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.redirect(withParam(back, 'error', 'bad_email'));
            if (username !== s.username && await Staff.exists({ username, _id: { $ne: s._id } })) return res.redirect(withParam(back, 'error', 'username_taken'));
            const changes = [];
            for (const [k, v] of Object.entries({ fullName, username, email, phone: str(req.body.phone, 40), title: str(req.body.title, 80) })) {
                if ((s[k] || '') !== v) { changes.push(k); s[k] = v; }
            }
            await s.save();
            await audit(req, 'staff.update', 'Staff', s._id, `${s.fullName} güncellendi${changes.length ? ': ' + changes.join(', ') : ''}`);
            res.redirect(withParam(back, 'status', 'staff_updated'));
        } catch (e) { res.redirect(withParam(back, 'error', 'update_failed')); }
    });

    app.post('/admin/personel/:id/status', adminAuthCheck, async (req, res) => {
        const back = safeBack(req, `/admin/personel/${req.params.id}`);
        const s = isId(req.params.id) && await Staff.findById(req.params.id);
        if (!s || s.deletedAt) return res.redirect(withParam(back, 'error', 'not_found'));
        const to = req.body.to === 'passive' ? 'passive' : 'active';
        if (s.status !== to) {
            s.status = to;
            if (to === 'passive') { s.sessionVersion += 1; rt.closeChannel(`staff:${s._id}`); }
            await s.save();
            await audit(req, to === 'passive' ? 'staff.deactivate' : 'staff.activate', 'Staff', s._id, `${s.fullName} ${to === 'passive' ? 'pasife alındı (oturumları sonlandırıldı)' : 'aktifleştirildi'}`);
        }
        res.redirect(withParam(back, 'status', to === 'passive' ? 'staff_passive' : 'staff_active'));
    });

    app.post('/admin/personel/:id/reset-password', adminAuthCheck, async (req, res) => {
        const back = `/admin/personel/${req.params.id}`;
        const s = isId(req.params.id) && await Staff.findById(req.params.id);
        if (!s || s.deletedAt) return res.redirect(withParam(back, 'error', 'not_found'));
        let link = null;
        if (req.body.mode === 'invite') {
            link = issueInvite(s, req);
        } else {
            if (passwordProblem(req.body.password)) return res.redirect(withParam(back, 'error', 'weak_password'));
            s.passwordHash = await hashPassword(req.body.password);
            s.inviteTokenHash = ''; s.inviteExpires = undefined;
        }
        s.sessionVersion += 1; s.failedLogins = 0; s.lockedUntil = undefined;
        rt.closeChannel(`staff:${s._id}`);
        await s.save();
        let mailed = false;
        if (link) mailed = await sendMail(s.email, 'BERLINER Personel Paneli · Şifre Sıfırlama', inviteMailHtml(s, link, true));
        await audit(req, 'staff.password_reset', 'Staff', s._id, `${s.fullName} için şifre sıfırlandı (${link ? 'bağlantı' : 'yeni şifre'})`);
        req.session.staffFlash = { kind: link ? 'invite' : 'reset', name: s.fullName, username: s.username, link, mailed };
        res.redirect(withParam(back, 'status', 'password_reset'));
    });

    app.post('/admin/personel/:id/delete', adminAuthCheck, async (req, res) => {
        const s = isId(req.params.id) && await Staff.findById(req.params.id);
        if (!s) return res.redirect('/admin/personel?error=not_found');
        s.deletedAt = new Date(); s.status = 'passive'; s.sessionVersion += 1;
        rt.closeChannel(`staff:${s._id}`);
        await s.save();
        const open = await WorkOrder.countDocuments({ assignedTo: s._id, status: { $in: OPEN } });
        await audit(req, 'staff.delete', 'Staff', s._id, `${s.fullName} devre dışı bırakıldı (silindi). Açık iş emri: ${open}`);
        res.redirect(`/admin/personel?status=staff_deleted${open ? '&open=' + open : ''}`);
    });

    app.post('/admin/personel/:id/restore', adminAuthCheck, async (req, res) => {
        const s = isId(req.params.id) && await Staff.findById(req.params.id);
        if (!s) return res.redirect('/admin/personel?error=not_found');
        s.deletedAt = null; s.status = 'passive';
        await s.save();
        await audit(req, 'staff.restore', 'Staff', s._id, `${s.fullName} geri yüklendi (pasif)`);
        res.redirect(`/admin/personel/${s._id}?status=staff_restored`);
    });

    // ==================================================================
    //  ADMIN · İŞ EMİRLERİ
    // ==================================================================
    app.get('/admin/is-emirleri', adminAuthCheck, async (req, res) => {
        const f = {
            q: str(req.query.q, 80),
            status: STATUSES.includes(req.query.status) ? req.query.status : (req.query.status === 'open' ? 'open' : ''),
            staff: isId(req.query.staff) ? req.query.staff : '',
            priority: PRIORITIES.includes(req.query.priority) ? req.query.priority : '',
            category: CATEGORIES.includes(req.query.category) ? req.query.category : '',
            overdue: req.query.overdue === '1', review: req.query.review === '1',
            sort: ['due', 'priority', 'created', 'updated'].includes(req.query.sort) ? req.query.sort : 'created'
        };
        const query = {};
        if (f.status === 'open') query.status = { $in: OPEN }; else if (f.status) query.status = f.status;
        if (f.staff) query.assignedTo = f.staff;
        if (f.priority) query.priority = f.priority;
        if (f.category) query.category = f.category;
        if (f.overdue) { query.status = { $in: OPEN }; query.dueDate = { $lt: new Date() }; }
        if (f.review) { query.status = 'Tamamlandı'; query['history.action'] = { $ne: 'Onaylandı' }; }
        let list = await WorkOrder.find(query).select('-history -comments').populate('assignedTo', 'fullName title deletedAt').sort({ createdAt: -1 }).limit(1000).lean();
        if (f.q) { const q = f.q.toLocaleLowerCase('tr-TR'); list = list.filter(w => [w.code, w.title, w.candidateName, w.category, w.assignedTo && w.assignedTo.fullName].join(' ').toLocaleLowerCase('tr-TR').includes(q)); }
        const far = new Date(8640000000000000);
        if (f.sort === 'due') list.sort((a, b) => new Date(a.dueDate || far) - new Date(b.dueDate || far));
        if (f.sort === 'priority') list.sort((a, b) => (PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority]) || (new Date(a.dueDate || far) - new Date(b.dueDate || far)));
        if (f.sort === 'updated') list.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        const [staffList, candidates, all] = await Promise.all([
            Staff.find({ deletedAt: null }).sort({ fullName: 1 }).select('fullName title status').lean(),
            Candidate.find().select('firstName lastName passportNo').sort({ firstName: 1 }).lean(),
            WorkOrder.find().select('status dueDate history.action').lean()
        ]);
        const counts = {
            open: all.filter(w => OPEN.includes(w.status)).length, overdue: all.filter(isOverdue).length,
            review: all.filter(w => w.status === 'Tamamlandı' && !(w.history || []).some(h => h.action === 'Onaylandı')).length, total: all.length
        };
        res.render('admin_workorders', { list, f, staffList, candidates, counts, STATUSES, PRIORITIES, CATEGORIES, user: { firstName: 'Admin' } });
    });

    app.post('/admin/is-emirleri', adminAuthCheck, async (req, res) => {
        const back = safeBack(req, '/admin/is-emirleri');
        try {
            const b = req.body;
            if (!isId(b.candidateId) || !isId(b.assignedTo)) return res.redirect(withParam(back, 'error', 'missing_fields'));
            const title = str(b.title, 160);
            if (!title) return res.redirect(withParam(back, 'error', 'missing_fields'));
            const [cand, staff] = await Promise.all([Candidate.findById(b.candidateId).select('firstName lastName'), Staff.findById(b.assignedTo)]);
            if (!cand) return res.redirect(withParam(back, 'error', 'not_found'));
            if (!staff || staff.deletedAt || staff.status !== 'active') return res.redirect(withParam(back, 'error', 'staff_inactive'));
            const startDate = parseDate(b.startDate) || new Date();
            const dueDate = endOfDay(b.dueDate || null);
            if (b.dueDate && !dueDate) return res.redirect(withParam(back, 'error', 'bad_date'));
            if (dueDate && dueDate < new Date(new Date(startDate).setHours(0, 0, 0, 0))) return res.redirect(withParam(back, 'error', 'bad_date'));
            const stageKey = app.locals.stageKeys && app.locals.stageKeys.includes(b.stageKey) ? b.stageKey : undefined;
            const wo = await createWorkOrder({
                candidate: cand, staff, actor: actorOf(req), category: b.category, title, description: str(b.description, 6000),
                priority: b.priority, startDate, dueDate, adminNote: str(b.adminNote, 4000), stageKey, source: 'manual'
            });
            await audit(req, 'workorder.create', 'WorkOrder', wo._id, `${wo.code} "${wo.title}" → ${staff.fullName}`);
            if (back.startsWith('/admin/candidate/')) return res.redirect(withParam(back, 'status', 'wo_created'));
            res.redirect(`/admin/is-emirleri/${wo._id}?status=wo_created`);
        } catch (e) {
            console.error('İş emri oluşturma hatası:', e);
            res.redirect(withParam(back, 'error', 'create_failed'));
        }
    });

    async function loadWO(req, res) {
        if (!isId(req.params.id)) { res.redirect('/admin/is-emirleri?error=not_found'); return null; }
        const wo = await WorkOrder.findById(req.params.id);
        if (!wo) { res.redirect('/admin/is-emirleri?error=not_found'); return null; }
        return wo;
    }

    app.get('/admin/is-emirleri/:id', adminAuthCheck, async (req, res) => {
        if (!isId(req.params.id)) return res.redirect('/admin/is-emirleri?error=not_found');
        const wo = await WorkOrder.findById(req.params.id).populate('assignedTo', 'fullName title email phone status deletedAt').lean();
        if (!wo) return res.redirect('/admin/is-emirleri?error=not_found');
        const [candidate, staffList] = await Promise.all([
            Candidate.findById(wo.candidateId).select('firstName lastName passportNo email phone phoneNumber job location currentStage company').lean(),
            Staff.find({ deletedAt: null, status: 'active' }).sort({ fullName: 1 }).select('fullName title').lean()
        ]);
        res.render('admin_workorder_detail', { wo, candidate, staffList, STATUSES, PRIORITIES, CATEGORIES, overdue: isOverdue(wo), user: { firstName: 'Admin' } });
    });

    app.post('/admin/is-emirleri/:id/edit', adminAuthCheck, async (req, res) => {
        const wo = await loadWO(req, res); if (!wo) return;
        const back = `/admin/is-emirleri/${wo._id}`;
        try {
            const b = req.body;
            const title = str(b.title, 160);
            if (!title) return res.redirect(withParam(back, 'error', 'missing_fields'));
            const changes = [];
            const set = (k, v, label) => {
                const a = wo[k] instanceof Date ? wo[k].getTime() : String(wo[k] ?? '');
                const n = v instanceof Date ? v.getTime() : String(v ?? '');
                if (a !== n) { wo[k] = v; changes.push(label); }
            };
            set('title', title, 'başlık');
            set('description', str(b.description, 6000), 'açıklama');
            if (CATEGORIES.includes(b.category)) set('category', b.category, 'kategori');
            if (PRIORITIES.includes(b.priority)) set('priority', b.priority, 'öncelik');
            set('adminNote', str(b.adminNote, 4000), 'admin notu');
            const sd = parseDate(b.startDate); if (sd) set('startDate', sd, 'başlangıç tarihi');
            const dd = b.dueDate ? endOfDay(b.dueDate) : null;
            if (b.dueDate && !dd) return res.redirect(withParam(back, 'error', 'bad_date'));
            const prevDue = wo.dueDate ? wo.dueDate.getTime() : null;
            set('dueDate', dd, 'son teslim tarihi');
            if ((dd ? dd.getTime() : null) !== prevDue) { wo.dueSoonNotifiedAt = undefined; wo.overdueNotifiedAt = undefined; }
            let prevStaff = null, newStaff = null;
            if (isId(b.assignedTo) && String(b.assignedTo) !== String(wo.assignedTo)) {
                newStaff = await Staff.findById(b.assignedTo);
                if (!newStaff || newStaff.deletedAt || newStaff.status !== 'active') return res.redirect(withParam(back, 'error', 'staff_inactive'));
                prevStaff = wo.assignedTo; wo.assignedTo = newStaff._id; changes.push('atanan personel');
            }
            if (!changes.length) return res.redirect(withParam(back, 'status', 'no_change'));
            pushHistory(wo, req, 'Güncellendi', changes.join(', '));
            await wo.save();
            if (newStaff) {
                await notify({ recipientType: 'staff', recipientId: newStaff._id, type: 'assigned', title: 'Yeni iş emri atandı', message: `${wo.code} · ${wo.title} (${wo.candidateName})`, workOrder: wo });
                await notify({ recipientType: 'staff', recipientId: prevStaff, type: 'cancelled', title: 'İş emri başka personele aktarıldı', message: `${wo.code} · ${wo.title} artık size atanmış değil.`, workOrder: null });
            }
            const other = changes.filter(c => c !== 'atanan personel');
            if (other.length) await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'updated', title: 'Görev güncellendi', message: `${wo.code} · ${other.join(', ')} değişti.`, workOrder: wo });
            await audit(req, 'workorder.update', 'WorkOrder', wo._id, `${wo.code}: ${changes.join(', ')}`);
            res.redirect(withParam(back, 'status', 'wo_updated'));
        } catch (e) { console.error(e); res.redirect(withParam(back, 'error', 'update_failed')); }
    });

    app.post('/admin/is-emirleri/:id/action', adminAuthCheck, async (req, res) => {
        const wo = await loadWO(req, res); if (!wo) return;
        const back = safeBack(req, `/admin/is-emirleri/${wo._id}`);
        const note = str(req.body.note, 1000);
        const act = req.body.action;
        if (act === 'cancel' && wo.status !== 'İptal') {
            wo.status = 'İptal'; wo.cancelledAt = new Date();
            pushHistory(wo, req, 'İptal edildi', note);
            await wo.save();
            await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'cancelled', title: 'Görev iptal edildi', message: `${wo.code} · ${wo.title}${note ? ' — ' + note : ''}`, workOrder: wo });
            fireHook(wo, 'cancelled', actorOf(req));
        } else if (act === 'revision' && wo.status === 'Tamamlandı') {
            if (!note) return res.redirect(withParam(back, 'error', 'note_required'));
            wo.status = 'Revizyon'; wo.completedAt = undefined;
            pushHistory(wo, req, 'Revizyona gönderildi', note);
            wo.comments.push({ authorType: 'admin', authorName: 'Yönetici', text: `Revizyon talebi: ${note}` });
            await wo.save();
            await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'revision', title: 'Görev revizyona gönderildi', message: `${wo.code} · ${note}`, workOrder: wo });
        } else if (act === 'approve' && wo.status === 'Tamamlandı') {
            pushHistory(wo, req, 'Onaylandı', note);
            await wo.save();
            fireHook(wo, 'approved', actorOf(req));
            await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'completed', title: 'Görev onaylandı', message: `${wo.code} · ${wo.title} yönetici tarafından onaylandı.`, workOrder: wo });
        } else if (act === 'reopen' && wo.status === 'İptal') {
            const s = await Staff.findById(wo.assignedTo);
            if (!s || s.deletedAt || s.status !== 'active') return res.redirect(withParam(back, 'error', 'staff_inactive'));
            wo.status = 'Yeni'; wo.cancelledAt = undefined;
            pushHistory(wo, req, 'Yeniden açıldı', note);
            await wo.save();
            await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'assigned', title: 'İş emri yeniden açıldı', message: `${wo.code} · ${wo.title}`, workOrder: wo });
        } else {
            return res.redirect(withParam(back, 'error', 'invalid_action'));
        }
        await audit(req, `workorder.${act}`, 'WorkOrder', wo._id, `${wo.code}${note ? ': ' + note : ''}`);
        res.redirect(withParam(back, 'status', `wo_${act}`));
    });

    app.post('/admin/is-emirleri/:id/comment', adminAuthCheck, async (req, res) => {
        const wo = await loadWO(req, res); if (!wo) return;
        const back = `/admin/is-emirleri/${wo._id}#comments`;
        const text = str(req.body.text, 4000);
        if (!text) return res.redirect(withParam(back, 'error', 'missing_fields'));
        wo.comments.push({ authorType: 'admin', authorName: 'Yönetici', text });
        pushHistory(wo, req, 'Açıklama eklendi');
        await wo.save();
        await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'comment', title: 'Yönetici açıklama ekledi', message: `${wo.code} · ${text.slice(0, 140)}`, workOrder: wo });
        await audit(req, 'workorder.comment', 'WorkOrder', wo._id, `${wo.code}: açıklama eklendi`);
        res.redirect(withParam(back, 'status', 'comment_added'));
    });

    app.post('/admin/is-emirleri/:id/attach', adminAuthCheck, uploadSingle('file', (req) => `/admin/is-emirleri/${req.params.id}`), async (req, res) => {
        const wo = await loadWO(req, res); if (!wo) return;
        const back = `/admin/is-emirleri/${wo._id}`;
        if (!req.file) return res.redirect(withParam(back, 'error', 'no_file'));
        try {
            await attachFile(req, wo, 'admin');
            pushHistory(wo, req, 'Dosya eklendi', req.file.originalname);
            await wo.save();
            await audit(req, 'workorder.attach', 'WorkOrder', wo._id, `${wo.code}: ${req.file.originalname}`);
            res.redirect(withParam(back, 'status', 'file_added'));
        } catch (e) { res.redirect(withParam(back, 'error', e.code === 'bad_type' ? 'bad_type' : 'upload_failed')); }
    });

    // İş emri eki görüntüleme (admin veya görevin sahibi personel)
    app.get('/is-emri-dosya/:woId/:attId', async (req, res) => {
        try {
            if (!isId(req.params.woId) || !isId(req.params.attId)) return res.status(404).send('Dosya bulunamadı.');
            const wo = await WorkOrder.findById(req.params.woId).select('assignedTo attachments status');
            if (!wo) return res.status(404).send('Dosya bulunamadı.');
            const isAdmin = !!req.session.isAdmin;
            let isOwner = false;
            if (req.session.staffId && String(wo.assignedTo) === String(req.session.staffId)) {
                const s = await Staff.findById(req.session.staffId);
                isOwner = !!(s && s.isUsable() && s.sessionVersion === req.session.staffVer);
            }
            if (!isAdmin && !isOwner) { await audit(req, 'security.denied', 'WorkOrder', wo._id, 'Yetkisiz ek görüntüleme denemesi'); return res.status(403).send('Bu dosyaya erişim yetkiniz yok.'); }
            const att = wo.attachments.id(req.params.attId);
            if (!att || !att.fileId) return res.status(404).send('Dosya bulunamadı.');
            await streamDriveFile(att.fileId, res);
        } catch (e) { if (!res.headersSent) res.status(500).send('Dosya açılamadı.'); }
    });

    // ==================================================================
    //  ADMIN · BİLDİRİMLER VE İŞLEM GEÇMİŞİ
    // ==================================================================
    app.get('/admin/bildirimler', adminAuthCheck, async (req, res) => {
        const only = req.query.only === 'unread';
        const q = { recipientType: 'admin' }; if (only) q.isRead = false;
        const list = await Notification.find(q).sort({ createdAt: -1 }).limit(200).lean();
        res.render('admin_notifications', { list, only, user: { firstName: 'Admin' } });
    });
    app.post('/admin/bildirimler/read-all', adminAuthCheck, async (req, res) => {
        await Notification.updateMany({ recipientType: 'admin', isRead: false }, { $set: { isRead: true, readAt: new Date() } });
        rt.publish('admin', 'unread', { unread: 0 });
        res.redirect('/admin/bildirimler?status=all_read');
    });
    app.post('/admin/bildirimler/:id/read', adminAuthCheck, async (req, res) => {
        if (isId(req.params.id)) await Notification.updateOne({ _id: req.params.id, recipientType: 'admin' }, { $set: { isRead: true, readAt: new Date() } });
        if ((req.get('accept') || '').includes('application/json')) return res.json({ ok: true, unread: await unreadFor('admin') });
        res.redirect('/admin/bildirimler');
    });
    app.get('/admin/bildirimler/stream', adminAuthCheck, (req, res) => rt.subscribe('admin', req, res));
    app.get('/admin/api/unread', adminAuthCheck, async (req, res) => res.json({ unread: await unreadFor('admin') }));

    app.get('/admin/islem-gecmisi', adminAuthCheck, async (req, res) => {
        const q = {};
        const actor = ['admin', 'staff', 'system', 'anonymous'].includes(req.query.actor) ? req.query.actor : '';
        if (actor) q.actorType = actor;
        const action = str(req.query.action, 40).replace(/[^a-z._]/gi, '');
        if (action) q.action = new RegExp('^' + action.replace(/\./g, '\\.'));
        let list = await AuditLog.find(q).sort({ createdAt: -1 }).limit(500).lean();
        const s = str(req.query.q, 80).toLocaleLowerCase('tr-TR');
        if (s) list = list.filter(l => [l.actorName, l.action, l.summary, l.ip].join(' ').toLocaleLowerCase('tr-TR').includes(s));
        res.render('admin_audit', { list, f: { actor, action, q: req.query.q || '' }, user: { firstName: 'Admin' } });
    });

    // Diğer modüllerin kullandığı servisler
    app.locals.services = { createWorkOrder, notify, audit, actorOf, unreadFor, computeStats, isOverdue, OPEN };

    // Aday detay sayfası için iş emri verisi (app.js'teki rota kullanır)
    app.locals.loadCandidateWorkOrders = async (candidateId) => {
        const [orders, staff] = await Promise.all([
            WorkOrder.find({ candidateId }).select('-history -comments -attachments').populate('assignedTo', 'fullName').sort({ createdAt: -1 }).lean(),
            Staff.find({ deletedAt: null, status: 'active' }).sort({ fullName: 1 }).select('fullName title').lean()
        ]);
        return { orders, staff, CATEGORIES, PRIORITIES };
    };

    // ==================================================================
    //  PERSONEL PANELİ  (/personel)
    // ==================================================================
    async function staffAuth(req, res, next) {
        const wantsJson = req.xhr || (req.get('accept') || '').includes('application/json') || req.path.endsWith('/stream');
        const deny = (reason) => {
            const done = () => wantsJson ? res.status(401).json({ error: 'unauthorized' }) : res.redirect('/personel?error=' + reason);
            if (req.session.staffId) { delete req.session.staffId; delete req.session.staffVer; return req.session.save(done); }
            done();
        };
        if (!req.session.staffId) return deny('login_required');
        try {
            const s = await Staff.findById(req.session.staffId);
            if (!s || s.deletedAt) return deny('account_disabled');
            if (s.status !== 'active') return deny('account_passive');
            if (s.sessionVersion !== req.session.staffVer) return deny('session_expired');
            req.staff = s;
            res.locals.staff = s;
            res.locals.staffUnread = await unreadFor('staff', s._id);
            next();
        } catch (e) { deny('login_required'); }
    }

    app.get('/personel', (req, res) => {
        if (req.session.staffId) return res.redirect('/personel/panel');
        res.render('staff_login', { error: null, username: '', reason: req.query.error || '', status: req.query.status || '' });
    });

    app.post('/personel/giris', async (req, res) => {
        const username = str(req.body.username, 60).toLowerCase();
        const password = typeof req.body.password === 'string' ? req.body.password.slice(0, 200) : '';
        const render = (code, msg) => res.status(code).render('staff_login', { error: msg, username, reason: '', status: '' });
        if (!username || !password) return render(400, 'Kullanıcı adı ve şifre gerekli.');
        const lim = loginLimiter(`${req.ip}|${username}`);
        if (lim.blocked()) {
            await audit(req, 'security.rate_limited', 'Staff', '', `Çok fazla deneme: ${username}`, { type: 'anonymous', id: '', name: username });
            return render(429, 'Çok fazla hatalı deneme yapıldı. Lütfen 15 dakika sonra tekrar deneyin.');
        }
        const s = await Staff.findOne({ username });
        const generic = 'Kullanıcı adı veya şifre hatalı.';
        if (!s) {
            lim.fail();
            await audit(req, 'staff.login_failed', 'Staff', '', `Bilinmeyen kullanıcı: ${username}`, { type: 'anonymous', id: '', name: username });
            return render(401, generic);
        }
        if (s.lockedUntil && s.lockedUntil > new Date()) return render(429, 'Hesap geçici olarak kilitlendi. Lütfen 15 dakika sonra tekrar deneyin.');
        const ok = !!s.passwordHash && await verifyPassword(password, s.passwordHash);
        if (!ok) {
            lim.fail(); s.failedLogins = (s.failedLogins || 0) + 1;
            if (s.failedLogins >= 8) { s.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); s.failedLogins = 0; }
            await s.save();
            await audit(req, 'staff.login_failed', 'Staff', s._id, `Hatalı şifre: ${s.username}`, { type: 'anonymous', id: '', name: s.username });
            return render(401, generic);
        }
        if (s.deletedAt) return render(403, 'Bu hesap devre dışı bırakılmış. Yöneticinizle iletişime geçin.');
        if (s.status !== 'active') return render(403, 'Hesabınız pasif durumda. Yöneticinizle iletişime geçin.');
        lim.reset();
        // Oturum sabitleme saldırısına karşı yeni oturum; admin/aday yetkileri taşınmaz
        req.session.regenerate(async (err) => {
            if (err) return render(500, 'Oturum başlatılamadı, tekrar deneyin.');
            req.session.staffId = String(s._id);
            req.session.staffVer = s.sessionVersion;
            s.lastLoginAt = new Date(); s.failedLogins = 0; s.lockedUntil = undefined;
            await s.save();
            await audit(req, 'staff.login', 'Staff', s._id, `${s.fullName} giriş yaptı`, { type: 'staff', id: String(s._id), name: s.fullName });
            req.session.save(() => res.redirect('/personel/panel'));
        });
    });

    app.get('/personel/cikis', (req, res) => {
        const id = req.session.staffId;
        if (id) AuditLog.create({ actorType: 'staff', actorId: id, action: 'staff.logout', targetType: 'Staff', targetId: id, summary: 'Çıkış yaptı', ip: req.ip }).catch(() => {});
        req.session.destroy(() => { res.clearCookie('connect.sid'); res.redirect('/personel?status=logged_out'); });
    });

    // Davet / şifre belirleme
    async function staffByInvite(token) {
        if (!token || token.length < 20) return null;
        const s = await Staff.findOne({ inviteTokenHash: sha256(token) });
        if (!s || !s.inviteExpires || s.inviteExpires < new Date() || s.deletedAt) return null;
        return s;
    }
    app.get('/personel/davet/:token', async (req, res) => {
        const s = await staffByInvite(req.params.token);
        res.render('staff_invite', { s, token: req.params.token, error: null });
    });
    app.post('/personel/davet/:token', async (req, res) => {
        const s = await staffByInvite(req.params.token);
        if (!s) return res.render('staff_invite', { s: null, token: '', error: null });
        const p = passwordProblem(req.body.password);
        if (p) return res.render('staff_invite', { s, token: req.params.token, error: p });
        if (req.body.password !== req.body.password2) return res.render('staff_invite', { s, token: req.params.token, error: 'Şifreler eşleşmiyor.' });
        s.passwordHash = await hashPassword(req.body.password);
        s.inviteTokenHash = ''; s.inviteExpires = undefined; s.sessionVersion += 1;
        await s.save();
        await audit(req, 'staff.password_set', 'Staff', s._id, `${s.fullName} şifresini belirledi`, { type: 'staff', id: String(s._id), name: s.fullName });
        res.redirect('/personel?status=password_set');
    });

    // Dashboard
    app.get('/personel/panel', staffAuth, async (req, res) => {
        const all = await WorkOrder.find({ assignedTo: req.staff._id }).select('-history -comments -attachments -adminNote').lean();
        const stats = computeStats(all);
        const now = Date.now();
        const upcoming = all.filter(w => OPEN.includes(w.status) && w.dueDate && new Date(w.dueDate) >= now && new Date(w.dueDate) - now < 7 * 864e5)
            .sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate)).slice(0, 6);
        const filter = ['new', 'progress', 'done', 'overdue', 'cancelled', 'open', 'all'].includes(req.query.f) ? req.query.f : 'open';
        const sort = ['priority', 'due', 'created'].includes(req.query.sort) ? req.query.sort : 'priority';
        const list = all.filter(w => ({
            new: w.status === 'Yeni', progress: w.status === 'Devam Ediyor' || w.status === 'Revizyon', done: w.status === 'Tamamlandı',
            overdue: isOverdue(w), cancelled: w.status === 'İptal', open: OPEN.includes(w.status), all: true
        })[filter]);
        const far = new Date(8640000000000000);
        if (sort === 'priority') list.sort((a, b) => (PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority]) || (new Date(a.dueDate || far) - new Date(b.dueDate || far)));
        if (sort === 'due') list.sort((a, b) => new Date(a.dueDate || far) - new Date(b.dueDate || far));
        if (sort === 'created') list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        const recent = await Notification.find({ recipientType: 'staff', recipientId: req.staff._id }).sort({ createdAt: -1 }).limit(5).lean();
        res.render('staff_dashboard', { stats, upcoming, list, filter, sort, recent, page: 'panel' });
    });

    async function ownTask(req, res) {
        const notFound = () => res.status(404).render('staff_error', { page: '', title: 'Görev bulunamadı', message: 'Bu görev size atanmamış veya mevcut değil.' });
        if (!isId(req.params.id)) { notFound(); return null; }
        const wo = await WorkOrder.findById(req.params.id);
        if (!wo || String(wo.assignedTo) !== String(req.staff._id)) {
            if (wo) await audit(req, 'security.denied', 'WorkOrder', wo._id, `${req.staff.username} başkasına ait görevi açmaya çalıştı`);
            notFound();
            return null;
        }
        return wo;
    }

    app.get('/personel/gorev/:id', staffAuth, async (req, res) => {
        const wo = await ownTask(req, res); if (!wo) return;
        const sensitive = SENSITIVE_CATEGORIES.includes(wo.category);
        let candidate = null;
        if (wo.status !== 'İptal') {
            const fields = 'firstName lastName email phone phoneNumber job location currentStage targetState documents._id documents.name documents.status documents.date documents.fileId' + (sensitive ? ' passportNo' : '');
            candidate = await Candidate.findById(wo.candidateId).select(fields).lean();
        }
        await Notification.updateMany({ recipientType: 'staff', recipientId: req.staff._id, workOrderId: wo._id, isRead: false }, { $set: { isRead: true, readAt: new Date() } });
        res.locals.staffUnread = await unreadFor('staff', req.staff._id);
        res.render('staff_task', { wo: wo.toObject(), candidate, overdue: isOverdue(wo), page: 'panel', sensitive });
    });

    const staffBack = (req) => `/personel/gorev/${req.params.id}`;

    app.post('/personel/gorev/:id/start', staffAuth, async (req, res) => {
        const wo = await ownTask(req, res); if (!wo) return;
        if (!['Yeni', 'Revizyon'].includes(wo.status)) return res.redirect(withParam(staffBack(req), 'error', 'invalid_state'));
        const wasRevision = wo.status === 'Revizyon';
        wo.status = 'Devam Ediyor'; if (!wo.startedAt) wo.startedAt = new Date();
        pushHistory(wo, req, wasRevision ? 'Revizyon üzerinde çalışmaya başladı' : 'Göreve başladı');
        await wo.save();
        await notify({ recipientType: 'admin', type: 'started', title: 'Göreve başlandı', message: `${req.staff.fullName} · ${wo.code} ${wo.title}`, workOrder: wo });
        fireHook(wo, 'started', actorOf(req));
        await audit(req, 'workorder.start', 'WorkOrder', wo._id, `${wo.code} başlatıldı`);
        res.redirect(withParam(staffBack(req), 'status', 'started'));
    });

    app.post('/personel/gorev/:id/complete', staffAuth, uploadSingle('file', staffBack), async (req, res) => {
        const wo = await ownTask(req, res); if (!wo) return;
        if (!OPEN.includes(wo.status)) return res.redirect(withParam(staffBack(req), 'error', 'invalid_state'));
        const note = str(req.body.resultNote, 6000);
        if (note.length < 5) return res.redirect(withParam(staffBack(req), 'error', 'result_required'));
        try { if (req.file) await attachFile(req, wo, 'staff'); }
        catch (e) { return res.redirect(withParam(staffBack(req), 'error', e.code === 'bad_type' ? 'bad_type' : 'upload_failed')); }
        wo.status = 'Tamamlandı'; wo.resultNote = note; wo.completedAt = new Date(); if (!wo.startedAt) wo.startedAt = wo.createdAt;
        pushHistory(wo, req, 'Tamamlandı', note.slice(0, 300));
        await wo.save();
        await notify({ recipientType: 'admin', type: 'completed', title: 'Görev tamamlandı', message: `${req.staff.fullName} · ${wo.code} ${wo.title}`, workOrder: wo });
        fireHook(wo, 'completed', actorOf(req));
        await audit(req, 'workorder.complete', 'WorkOrder', wo._id, `${wo.code} tamamlandı`);
        res.redirect(withParam(staffBack(req), 'status', 'completed'));
    });

    app.post('/personel/gorev/:id/comment', staffAuth, async (req, res) => {
        const wo = await ownTask(req, res); if (!wo) return;
        const text = str(req.body.text, 4000);
        if (!text) return res.redirect(withParam(staffBack(req) + '#comments', 'error', 'missing_fields'));
        wo.comments.push({ authorType: 'staff', authorName: req.staff.fullName, text });
        await wo.save();
        await notify({ recipientType: 'admin', type: 'comment', title: 'Personel not ekledi', message: `${req.staff.fullName} · ${wo.code}: ${text.slice(0, 140)}`, workOrder: wo });
        await audit(req, 'workorder.comment', 'WorkOrder', wo._id, `${wo.code}: personel notu`);
        res.redirect(withParam(staffBack(req) + '#comments', 'status', 'comment_added'));
    });

    app.post('/personel/gorev/:id/attach', staffAuth, uploadSingle('file', staffBack), async (req, res) => {
        const wo = await ownTask(req, res); if (!wo) return;
        if (wo.status === 'İptal') return res.redirect(withParam(staffBack(req), 'error', 'invalid_state'));
        if (!req.file) return res.redirect(withParam(staffBack(req), 'error', 'no_file'));
        try {
            await attachFile(req, wo, 'staff');
            pushHistory(wo, req, 'Dosya eklendi', req.file.originalname);
            await wo.save();
            await audit(req, 'workorder.attach', 'WorkOrder', wo._id, `${wo.code}: ${req.file.originalname}`);
            res.redirect(withParam(staffBack(req), 'status', 'file_added'));
        } catch (e) { res.redirect(withParam(staffBack(req), 'error', e.code === 'bad_type' ? 'bad_type' : 'upload_failed')); }
    });

    // Görevle ilişkili adayın belgesini görüntüleme (yalnızca iptal edilmemiş, kendisine atanmış görev üzerinden)
    app.get('/personel/gorev/:id/belge/:docId', staffAuth, async (req, res) => {
        const wo = await ownTask(req, res); if (!wo) return;
        if (wo.status === 'İptal' || !isId(req.params.docId)) return res.status(403).send('Erişim yok.');
        const cand = await Candidate.findOne({ _id: wo.candidateId, 'documents._id': req.params.docId }, { 'documents.$': 1 });
        const doc = cand && cand.documents && cand.documents[0];
        if (!doc || !doc.fileId) return res.status(404).send('Belge bulunamadı.');
        await audit(req, 'candidate.document_view', 'Candidate', wo.candidateId, `${wo.code}: ${doc.name} görüntülendi`);
        try { await streamDriveFile(doc.fileId, res); } catch (e) { if (!res.headersSent) res.status(500).send('Belge açılamadı.'); }
    });

    // Bildirimler
    app.get('/personel/bildirimler', staffAuth, async (req, res) => {
        const only = req.query.only === 'unread';
        const q = { recipientType: 'staff', recipientId: req.staff._id }; if (only) q.isRead = false;
        const list = await Notification.find(q).sort({ createdAt: -1 }).limit(200).lean();
        res.render('staff_notifications', { list, only, page: 'notifications' });
    });
    app.post('/personel/bildirimler/read-all', staffAuth, async (req, res) => {
        await Notification.updateMany({ recipientType: 'staff', recipientId: req.staff._id, isRead: false }, { $set: { isRead: true, readAt: new Date() } });
        rt.publish(`staff:${req.staff._id}`, 'unread', { unread: 0 });
        res.redirect('/personel/bildirimler?status=all_read');
    });
    app.post('/personel/bildirimler/:id/read', staffAuth, async (req, res) => {
        if (isId(req.params.id)) await Notification.updateOne({ _id: req.params.id, recipientType: 'staff', recipientId: req.staff._id }, { $set: { isRead: true, readAt: new Date() } });
        const unread = await unreadFor('staff', req.staff._id);
        if ((req.get('accept') || '').includes('application/json')) return res.json({ ok: true, unread });
        res.redirect('/personel/bildirimler');
    });
    app.get('/personel/stream', staffAuth, (req, res) => rt.subscribe(`staff:${req.staff._id}`, req, res));
    app.get('/personel/api/unread', staffAuth, async (req, res) => {
        const latest = await Notification.findOne({ recipientType: 'staff', recipientId: req.staff._id }).sort({ createdAt: -1 }).lean();
        res.json({ unread: res.locals.staffUnread, latest: latest ? { id: String(latest._id), title: latest.title, message: latest.message, createdAt: latest.createdAt, link: `/n/${latest._id}` } : null });
    });

    // Hesap / şifre değiştirme
    app.get('/personel/hesap', staffAuth, (req, res) => res.render('staff_account', { page: 'account', error: null }));
    app.post('/personel/hesap/sifre', staffAuth, async (req, res) => {
        const s = req.staff;
        if (!(await verifyPassword(String(req.body.current || ''), s.passwordHash))) return res.render('staff_account', { page: 'account', error: 'Mevcut şifre hatalı.' });
        const p = passwordProblem(req.body.password); if (p) return res.render('staff_account', { page: 'account', error: p });
        if (req.body.password !== req.body.password2) return res.render('staff_account', { page: 'account', error: 'Yeni şifreler eşleşmiyor.' });
        s.passwordHash = await hashPassword(req.body.password); s.sessionVersion += 1;
        await s.save();
        req.session.staffVer = s.sessionVersion; // bu oturum devam etsin, diğer cihazlardaki oturumlar düşsün
        await audit(req, 'staff.password_change', 'Staff', s._id, 'Personel şifresini değiştirdi');
        req.session.save(() => res.redirect('/personel/hesap?status=password_changed'));
    });

    // ==================================================================
    //  ZAMANLAYICI · teslim tarihi yaklaşan / geciken görevler
    // ==================================================================
    async function dueScan() {
        try {
            const now = new Date(), soon = new Date(Date.now() + 24 * 36e5);
            const dueSoon = await WorkOrder.find({ status: { $in: OPEN }, dueDate: { $gte: now, $lte: soon }, dueSoonNotifiedAt: null });
            for (const wo of dueSoon) {
                wo.dueSoonNotifiedAt = now; await wo.save();
                const when = wo.dueDate.toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul', day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' });
                await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'due_soon', title: 'Son teslim tarihi yaklaşıyor', message: `${wo.code} · ${wo.title} — ${when}`, workOrder: wo });
            }
            const overdue = await WorkOrder.find({ status: { $in: OPEN }, dueDate: { $lt: now }, overdueNotifiedAt: null });
            for (const wo of overdue) {
                wo.overdueNotifiedAt = now; await wo.save();
                await notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'overdue', title: 'Görev gecikti', message: `${wo.code} · ${wo.title} teslim tarihini geçti.`, workOrder: wo });
                await notify({ recipientType: 'admin', type: 'overdue', title: 'Geciken görev', message: `${wo.code} · ${wo.title} (${wo.candidateName})`, workOrder: wo });
            }
        } catch (e) { console.error('Teslim tarihi taraması hatası:', e.message); }
    }
    setTimeout(dueScan, 15 * 1000).unref();
    setInterval(dueScan, 5 * 60 * 1000).unref();
    app.locals.runDueScan = dueScan;

    // Migration: yeni koleksiyonların indekslerini oluştur (mevcut veriye dokunmaz)
    mongoose.connection.once('open', () => {
        Promise.all([Staff.syncIndexes(), WorkOrder.syncIndexes(), Notification.syncIndexes(), AuditLog.syncIndexes()])
            .then(() => console.log('✅ Personel / iş emri koleksiyonları hazır'))
            .catch(e => console.error('İndeks oluşturma hatası:', e.message));
    });
};
