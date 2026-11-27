// =====================================================================
//  OPERASYON: İş emri kategorileri · Tekrarlayan görevler · Duyurular
//             Personel ekip dağılımı · Tahmini iş emri zamanı · Bildirim ön izleme
//  app.js içinden staff modülünden ÖNCE bağlanır (rota sırası için);
//  staff servislerine istek anında app.locals üzerinden erişir.
// =====================================================================
const mongoose = require('mongoose');
const Staff = require('../models/Staff');
const WorkOrder = require('../models/WorkOrder');
const Notification = require('../models/Notification');
const TaskCategory = require('../models/TaskCategory');
const RecurringTask = require('../models/RecurringTask');
const Announcement = require('../models/Announcement');
const cats = require('../lib/categories');

const OPEN = ['Yeni', 'Devam Ediyor', 'Revizyon'];
const PRIORITIES = ['Düşük', 'Normal', 'Yüksek', 'Acil'];
const PRIORITY_RANK = { 'Acil': 0, 'Yüksek': 1, 'Normal': 2, 'Düşük': 3 };
const FREQ = { daily: 'Her gün', weekdays: 'Hafta içi her gün', weekly: 'Her hafta', monthly: 'Her ay' };
const WEEKDAYS = ['Pazar', 'Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi'];
const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const withParam = (url, k, v) => { const u = new URL(url, 'http://x'); u.searchParams.delete('status'); u.searchParams.delete('error'); u.searchParams.set(k, v); return u.pathname + u.search + u.hash; };
const ids = (v) => [...new Set((Array.isArray(v) ? v : [v]).filter(isId))];

// Bir sonraki çalışma zamanı (sunucu saat dilimi Europe/Istanbul olarak ayarlı)
function computeNext(rule, from = new Date()) {
    const [hh, mm] = String(rule.time || '09:00').split(':').map(Number);
    const d = new Date(from); d.setSeconds(0, 0);
    for (let i = 0; i < 400; i++) {
        const c = new Date(d.getFullYear(), d.getMonth(), d.getDate() + i, hh, mm, 0, 0);
        if (c <= from) continue;
        const wd = c.getDay();
        if (rule.frequency === 'daily') return c;
        if (rule.frequency === 'weekdays' && wd >= 1 && wd <= 5) return c;
        if (rule.frequency === 'weekly' && wd === Number(rule.weekday)) return c;
        if (rule.frequency === 'monthly' && c.getDate() === Number(rule.monthDay)) return c;
    }
    return null;
}
const describeRule = (r) => `${FREQ[r.frequency]}${r.frequency === 'weekly' ? ' · ' + WEEKDAYS[r.weekday] : ''}${r.frequency === 'monthly' ? ' · ayın ' + r.monthDay + '. günü' : ''} · ${r.time}`;

module.exports = function mountOps(app, deps) {
    const { adminAuthCheck, Candidate } = deps;
    const S = () => app.locals.services;
    const staffAuth = (req, res, next) => app.locals.staffAuth(req, res, next);
    const actor = (req) => S().actorOf(req);
    app.locals.describeRule = describeRule;
    app.locals.categoryColor = cats.colorOf;

    // ==================================================================
    //  KATEGORİLER
    // ==================================================================
    app.get('/admin/is-emirleri/kategoriler', adminAuthCheck, async (req, res) => {
        await cats.refresh();
        const u = {};
        (await WorkOrder.find().select('category status').lean()).forEach(w => { const x = u[w.category] || (u[w.category] = { n: 0, open: 0 }); x.n++; if (OPEN.includes(w.status)) x.open++; });
        res.render('admin_categories', { list: cats.all().map(c => ({ ...c, used: (u[c.name] || {}).n || 0, open: (u[c.name] || {}).open || 0 })), user: { firstName: 'Admin' } });
    });

    app.post('/admin/is-emirleri/kategoriler', adminAuthCheck, async (req, res) => {
        const back = '/admin/is-emirleri/kategoriler';
        const name = str(req.body.name, 60), color = /^#[0-9a-fA-F]{6}$/.test(req.body.color) ? req.body.color : '#D4111B';
        if (!name) return res.redirect(withParam(back, 'error', 'missing_fields'));
        if (await TaskCategory.exists({ name })) return res.redirect(withParam(back, 'error', 'category_exists'));
        const max = await TaskCategory.findOne().sort({ order: -1 }).select('order').lean();
        await TaskCategory.create({ name, color, order: (max ? max.order : 0) + 1 });
        await cats.refresh();
        await S().audit(req, 'category.create', 'TaskCategory', '', `Kategori eklendi: ${name}`);
        res.redirect(withParam(back, 'status', 'category_created'));
    });

    app.post('/admin/is-emirleri/kategoriler/:id', adminAuthCheck, async (req, res) => {
        const back = '/admin/is-emirleri/kategoriler';
        const c = isId(req.params.id) && await TaskCategory.findById(req.params.id);
        if (!c) return res.redirect(withParam(back, 'error', 'not_found'));
        const act = req.body._action;
        if (act === 'toggle') {
            if (c.active && (await TaskCategory.countDocuments({ active: true })) <= 1) return res.redirect(withParam(back, 'error', 'last_category'));
            c.active = !c.active; await c.save();
            await S().audit(req, 'category.toggle', 'TaskCategory', c._id, `${c.name} ${c.active ? 'aktifleştirildi' : 'pasife alındı'}`);
        } else if (act === 'delete') {
            const used = await WorkOrder.countDocuments({ category: c.name }) + await RecurringTask.countDocuments({ category: c.name });
            if (used) { // kullanılan kategori silinmez, geçmiş kayıtlar bozulmasın diye pasife alınır
                if (c.active && (await TaskCategory.countDocuments({ active: true })) <= 1) return res.redirect(withParam(back, 'error', 'last_category'));
                c.active = false; await c.save(); await cats.refresh();
                await S().audit(req, 'category.deactivate', 'TaskCategory', c._id, `${c.name} kullanımda olduğu için pasife alındı`);
                return res.redirect(withParam(back, 'status', 'category_deactivated'));
            }
            if ((await TaskCategory.countDocuments({ active: true })) <= 1 && c.active) return res.redirect(withParam(back, 'error', 'last_category'));
            await TaskCategory.deleteOne({ _id: c._id });
            await S().audit(req, 'category.delete', 'TaskCategory', c._id, `Kategori silindi: ${c.name}`);
            await cats.refresh();
            return res.redirect(withParam(back, 'status', 'category_deleted'));
        } else {
            const name = str(req.body.name, 60);
            if (!name) return res.redirect(withParam(back, 'error', 'missing_fields'));
            if (name !== c.name) {
                if (await TaskCategory.exists({ name, _id: { $ne: c._id } })) return res.redirect(withParam(back, 'error', 'category_exists'));
                const old = c.name;
                await WorkOrder.updateMany({ category: old }, { $set: { category: name } });
                await RecurringTask.updateMany({ category: old }, { $set: { category: name } });
                // Otomasyon şablonlarındaki kategori adları
                const StageConfig = mongoose.model('StageConfig');
                for (const cfg of await StageConfig.find({ 'templates.category': old })) { cfg.templates.forEach(t => { if (t.category === old) t.category = name; }); await cfg.save(); }
                c.name = name;
                await S().audit(req, 'category.rename', 'TaskCategory', c._id, `${old} → ${name} (iş emirleri güncellendi)`);
            }
            if (/^#[0-9a-fA-F]{6}$/.test(req.body.color)) c.color = req.body.color;
            const ord = parseInt(req.body.order, 10); if (ord >= 0 && ord < 10000) c.order = ord;
            await c.save();
        }
        await cats.refresh();
        res.redirect(withParam(back, 'status', 'category_updated'));
    });

    // ==================================================================
    //  TEKRARLAYAN GÖREVLER
    // ==================================================================
    function readRule(b) {
        const r = {
            title: str(b.title, 160), description: str(b.description, 6000), category: b.category, priority: PRIORITIES.includes(b.priority) ? b.priority : 'Normal',
            assignees: ids(b.assignees), frequency: Object.keys(FREQ).includes(b.frequency) ? b.frequency : null,
            weekday: Math.max(0, Math.min(6, parseInt(b.weekday, 10) || 0)), monthDay: Math.max(1, Math.min(28, parseInt(b.monthDay, 10) || 1)),
            time: /^([01]\d|2[0-3]):[0-5]\d$/.test(b.time) ? b.time : null, dueHours: Math.max(1, Math.min(720, parseInt(b.dueHours, 10) || 8)),
            checklist: str(b.checklist, 6000).split(/\r?\n/).map(x => x.trim().slice(0, 200)).filter(Boolean).slice(0, 30),
            candidateId: isId(b.candidateId) ? b.candidateId : undefined
        };
        if (!r.title || !r.frequency || !r.time || !r.assignees.length || !cats.isValid(r.category)) return null;
        return r;
    }

    app.get('/admin/is-emirleri/tekrarlayan', adminAuthCheck, async (req, res) => {
        const [rules, staffList, candidates] = await Promise.all([
            RecurringTask.find().populate('assignees', 'fullName status deletedAt').populate('candidateId', 'firstName lastName').sort({ active: -1, nextRunAt: 1 }).lean(),
            Staff.find({ deletedAt: null, status: 'active' }).sort({ fullName: 1 }).select('fullName title').lean(),
            Candidate.find({ status: { $ne: 'cancelled' } }).select('firstName lastName passportNo').sort({ firstName: 1 }).lean()
        ]);
        res.render('admin_recurring', { rules, staffList, candidates, CATEGORIES: cats.names(), PRIORITIES, FREQ, WEEKDAYS, user: { firstName: 'Admin' } });
    });

    app.post('/admin/is-emirleri/tekrarlayan', adminAuthCheck, async (req, res) => {
        const back = '/admin/is-emirleri/tekrarlayan';
        const r = readRule(req.body);
        if (!r) return res.redirect(withParam(back, 'error', 'missing_fields'));
        if ((await Staff.countDocuments({ _id: { $in: r.assignees }, deletedAt: null, status: 'active' })) !== r.assignees.length) return res.redirect(withParam(back, 'error', 'staff_inactive'));
        let rule;
        if (isId(req.body.id)) {
            rule = await RecurringTask.findById(req.body.id);
            if (!rule) return res.redirect(withParam(back, 'error', 'not_found'));
            Object.assign(rule, r);
            if (!r.candidateId) rule.candidateId = undefined;
        } else rule = new RecurringTask({ ...r, createdByName: actor(req).name });
        rule.nextRunAt = rule.active ? computeNext(rule) : null;
        await rule.save();
        await S().audit(req, isId(req.body.id) ? 'recurring.update' : 'recurring.create', 'RecurringTask', rule._id, `${rule.title} · ${describeRule(rule)}`);
        res.redirect(withParam(back, 'status', isId(req.body.id) ? 'recurring_updated' : 'recurring_created'));
    });

    app.post('/admin/is-emirleri/tekrarlayan/:id/:act', adminAuthCheck, async (req, res) => {
        const back = '/admin/is-emirleri/tekrarlayan';
        const rule = isId(req.params.id) && await RecurringTask.findById(req.params.id);
        if (!rule) return res.redirect(withParam(back, 'error', 'not_found'));
        if (req.params.act === 'toggle') {
            rule.active = !rule.active; rule.nextRunAt = rule.active ? computeNext(rule) : null; await rule.save();
            await S().audit(req, 'recurring.toggle', 'RecurringTask', rule._id, `${rule.title} ${rule.active ? 'aktif' : 'durduruldu'}`);
            return res.redirect(withParam(back, 'status', rule.active ? 'recurring_resumed' : 'recurring_paused'));
        }
        if (req.params.act === 'delete') {
            await RecurringTask.deleteOne({ _id: rule._id }); // oluşturulmuş iş emirleri silinmez
            await S().audit(req, 'recurring.delete', 'RecurringTask', rule._id, `${rule.title} silindi`);
            return res.redirect(withParam(back, 'status', 'recurring_deleted'));
        }
        if (req.params.act === 'run') {
            const n = await runRule(rule, actor(req));
            return res.redirect(withParam(back, n ? 'status' : 'error', n ? 'recurring_ran' : 'staff_inactive'));
        }
        res.redirect(withParam(back, 'error', 'invalid_action'));
    });

    // Kuralı çalıştır: aktif personellere ortak iş emri oluştur
    async function runRule(rule, by) {
        const staffList = await Staff.find({ _id: { $in: rule.assignees }, deletedAt: null, status: 'active' });
        if (!staffList.length) { console.error(`Tekrarlayan görev "${rule.title}": aktif personel yok`); return 0; }
        let candidate = null;
        if (rule.candidateId) { candidate = await Candidate.findById(rule.candidateId).select('firstName lastName status'); if (candidate && candidate.status === 'cancelled') candidate = null; }
        const now = new Date();
        const created = await S().createWorkOrderGroup({
            candidate, staffList, actor: by || { type: 'system', id: 'system', name: 'Tekrarlayan görev' }, category: rule.category, title: rule.title,
            description: rule.description, priority: rule.priority, startDate: now, dueDate: new Date(now.getTime() + rule.dueHours * 36e5),
            checklist: rule.checklist, recurringId: rule._id, source: 'automation', historyNote: `Tekrarlayan görevden oluşturuldu (${describeRule(rule)})`
        });
        await RecurringTask.updateOne({ _id: rule._id }, { $set: { lastRunAt: now }, $inc: { runCount: 1 } });
        return created.length;
    }

    // Zamanlayıcı: dakikada bir vadesi gelen kuralları çalıştırır (atomik "talep" ile mükerrer çalışma önlenir)
    async function scheduler() {
        try {
            const due = await RecurringTask.find({ active: true, nextRunAt: { $lte: new Date() } }).limit(50);
            for (const r of due) {
                const next = computeNext(r, new Date());
                const claimed = await RecurringTask.findOneAndUpdate({ _id: r._id, nextRunAt: r.nextRunAt }, { $set: { nextRunAt: next } }, { new: true });
                if (claimed) await runRule(claimed);
            }
        } catch (e) { console.error('Tekrarlayan görev zamanlayıcı hatası:', e.message); }
    }
    setTimeout(scheduler, 20 * 1000).unref();
    setInterval(scheduler, 60 * 1000).unref();
    app.locals.runRecurringScheduler = scheduler;

    // ==================================================================
    //  DUYURULAR
    // ==================================================================
    app.get('/admin/duyurular', adminAuthCheck, async (req, res) => {
        const [list, staffList] = await Promise.all([
            Announcement.find().sort({ pinned: -1, createdAt: -1 }).limit(100).lean(),
            Staff.find({ deletedAt: null, status: 'active' }).sort({ fullName: 1 }).select('fullName title').lean()
        ]);
        res.render('admin_announcements', { list, staffList, user: { firstName: 'Admin' } });
    });
    app.post('/admin/duyurular', adminAuthCheck, async (req, res) => {
        const back = '/admin/duyurular';
        const title = str(req.body.title, 160);
        if (!title) return res.redirect(withParam(back, 'error', 'missing_fields'));
        const exp = req.body.expiresAt && /^\d{4}-\d{2}-\d{2}$/.test(req.body.expiresAt) ? new Date(`${req.body.expiresAt}T23:59:00+03:00`) : undefined;
        const a = await Announcement.create({ title, body: str(req.body.body, 4000), level: ['info', 'important', 'urgent'].includes(req.body.level) ? req.body.level : 'info', pinned: req.body.pinned === 'on', expiresAt: exp, createdByName: actor(req).name });
        const staff = await Staff.find({ deletedAt: null, status: 'active' }).select('_id').lean();
        for (const s of staff) await S().notify({ recipientType: 'staff', recipientId: s._id, type: 'announcement', title: 'Yeni duyuru', message: title, link: '/personel/panel#announcements' });
        await S().audit(req, 'announcement.create', 'Announcement', a._id, title);
        res.redirect(withParam(back, 'status', 'announcement_created'));
    });
    app.post('/admin/duyurular/:id/:act', adminAuthCheck, async (req, res) => {
        const back = '/admin/duyurular';
        const a = isId(req.params.id) && await Announcement.findById(req.params.id);
        if (!a) return res.redirect(withParam(back, 'error', 'not_found'));
        if (req.params.act === 'pin') a.pinned = !a.pinned;
        else if (req.params.act === 'toggle') a.active = !a.active;
        else if (req.params.act === 'delete') { await Announcement.deleteOne({ _id: a._id }); await S().audit(req, 'announcement.delete', 'Announcement', a._id, a.title); return res.redirect(withParam(back, 'status', 'announcement_deleted')); }
        else return res.redirect(withParam(back, 'error', 'invalid_action'));
        await a.save();
        res.redirect(withParam(back, 'status', 'announcement_updated'));
    });

    const visibleAnnouncements = () => Announcement.find({ active: true, $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] }).sort({ pinned: -1, createdAt: -1 }).limit(10).lean();
    app.post('/personel/duyuru/:id/okundu', staffAuth, async (req, res) => {
        if (isId(req.params.id)) await Announcement.updateOne({ _id: req.params.id, 'reads.staffId': { $ne: req.staff._id } }, { $push: { reads: { staffId: req.staff._id, at: new Date() } } });
        if ((req.get('accept') || '').includes('application/json')) return res.json({ ok: true });
        res.redirect('/personel/panel#announcements');
    });

    // ==================================================================
    //  PERSONEL: bildirim ön izleme, ekip dağılımı, tahmini iş zamanı
    // ==================================================================
    app.get('/personel/api/bildirimler', staffAuth, async (req, res) => {
        const list = await Notification.find({ recipientType: 'staff', recipientId: req.staff._id }).sort({ createdAt: -1 }).limit(8).lean();
        res.json({
            unread: res.locals.staffUnread,
            items: list.map(n => ({ id: String(n._id), type: n.type, title: n.title, message: n.message, isRead: n.isRead, createdAt: n.createdAt, link: `/n/${n._id}`, icon: app.locals.notifIcon(n.type) }))
        });
    });

    // Tahmini yeni iş emri zamanı: yalnızca gerçek planlı veriler (tekrarlayan kurallar, ileri tarihli görevler) kullanılır
    async function etaFor(staffIds) {
        const now = new Date();
        const [rules, future] = await Promise.all([
            RecurringTask.find({ active: true, nextRunAt: { $gt: now }, assignees: { $in: staffIds } }).select('title category nextRunAt assignees').lean(),
            WorkOrder.find({ assignedTo: { $in: staffIds }, status: 'Yeni', startDate: { $gt: now } }).select('title category startDate assignedTo').lean()
        ]);
        const out = {};
        for (const id of staffIds.map(String)) {
            const opts = rules.filter(r => r.assignees.map(String).includes(id)).map(r => ({ at: r.nextRunAt, title: r.title, category: r.category, kind: 'recurring' }))
                .concat(future.filter(w => String(w.assignedTo) === id).map(w => ({ at: w.startDate, title: w.title, category: w.category, kind: 'scheduled' })));
            opts.sort((a, b) => new Date(a.at) - new Date(b.at));
            out[id] = opts[0] || null;
        }
        return out;
    }

    // Personel paneli için ek veriler (staff/index.js içindeki /personel/panel rotası kullanır)
    app.locals.opsStaffDashboard = async (staff) => {
        const team = await Staff.find({ deletedAt: null, status: 'active' }).sort({ fullName: 1 }).select('fullName title').lean();
        const teamIds = team.map(t => t._id);
        const [orders, eta, announcements] = await Promise.all([
            WorkOrder.find({ assignedTo: { $in: teamIds }, status: { $ne: 'İptal' } }).select('assignedTo status category startedAt completedAt dueDate').lean(),
            etaFor(teamIds),
            visibleAnnouncements()
        ]);
        const weekAgo = Date.now() - 30 * 864e5;
        // Gizlilik: diğer personellerin görev başlığı/açıklaması gönderilmez; yalnızca sayılar ve kategori
        const rows = team.map(t => {
            const m = orders.filter(o => String(o.assignedTo) === String(t._id));
            const active = m.filter(o => o.status === 'Devam Ediyor').sort((a, b) => new Date(b.startedAt || 0) - new Date(a.startedAt || 0))[0];
            const e = eta[String(t._id)];
            return {
                _id: t._id, name: t.fullName, title: t.title, me: String(t._id) === String(staff._id),
                active: m.filter(o => OPEN.includes(o.status)).length,
                pending: m.filter(o => o.status === 'Yeni' || o.status === 'Revizyon').length,
                completed: m.filter(o => o.status === 'Tamamlandı' && o.completedAt && new Date(o.completedAt) > weekAgo).length,
                current: active ? active.category : null,
                overdue: m.filter(o => OPEN.includes(o.status) && o.dueDate && new Date(o.dueDate) < new Date()).length,
                eta: e ? e.at : null
            };
        });
        const maxActive = Math.max(1, ...rows.map(r => r.active));
        const myEta = eta[String(staff._id)];
        return {
            team: rows, maxActive, announcements: announcements.map(a => ({ ...a, read: (a.reads || []).some(r => String(r.staffId) === String(staff._id)), reads: undefined })),
            eta: myEta ? { at: myEta.at, title: myEta.title, category: myEta.category, kind: myEta.kind } : null
        };
    };

    mongoose.connection.once('open', () => {
        Promise.all([RecurringTask.syncIndexes(), Announcement.syncIndexes()]).catch(e => console.error('Operasyon indeks hatası:', e.message));
    });

    app.locals.ops = { computeNext, runRule, etaFor, describeRule };
};
module.exports.computeNext = computeNext;
