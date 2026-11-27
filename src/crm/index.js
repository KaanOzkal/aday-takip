// =====================================================================
//  CRM: Yönetim paneli verileri · İletişim merkezi · Şirket/işveren · Raporlama (CSV/PDF)
//  app.js içinden staff ve process modüllerinden SONRA bağlanır.
// =====================================================================
const path = require('path');
const mongoose = require('mongoose');
const PDFDocument = require('pdfkit');
const Company = require('../models/Company');
const CandidateContact = require('../models/CandidateContact');
const CandidateStage = require('../models/CandidateStage');
const ProcessEvent = require('../models/ProcessEvent');
const WorkOrder = require('../models/WorkOrder');
const Staff = require('../models/Staff');
const Message = require('../models/Message');
const { STAGE_DEFS, STAGE_NAMES, byKey, byName } = require('../process/stages');

const DAY = 864e5;
const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const fullName = (c) => `${c.firstName || ''} ${c.lastName || ''}`.trim();
const OPEN = ['Yeni', 'Devam Ediyor', 'Revizyon'];
const FINAL = STAGE_NAMES[STAGE_NAMES.length - 1];
const startOfDay = (d = new Date()) => { const x = new Date(d); x.setHours(0, 0, 0, 0); return x; };
const startOfMonth = (d = new Date()) => new Date(d.getFullYear(), d.getMonth(), 1);
const monthKey = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
const MONTHS_TR = ['Oca', 'Şub', 'Mar', 'Nis', 'May', 'Haz', 'Tem', 'Ağu', 'Eyl', 'Eki', 'Kas', 'Ara'];
const monthLabel = (k) => { const [y, m] = k.split('-'); return `${MONTHS_TR[+m - 1]} ${y.slice(2)}`; };
const withParam = (url, k, v) => { const u = new URL(url, 'http://x'); u.searchParams.delete('status'); u.searchParams.delete('error'); u.searchParams.set(k, v); return u.pathname + u.search + u.hash; };
const CONTACT_TYPES = CandidateContact.TYPES;

module.exports = function mountCRM(app, deps) {
    const { adminAuthCheck, Candidate, Appointment } = deps;
    const svc = () => app.locals.services;
    const P = () => app.locals.processService;
    app.locals.contactTypes = CONTACT_TYPES;
    app.locals.woStatusLabel = (s) => ({ 'Yeni': 'Atandı', 'İptal': 'İptal Edildi' })[s] || s;

    // Almanya'ya varış tarihi: süreç geçmişindeki son "Almanya aşamasına geçiş" kaydı.
    // Sisteme geçişten önce Almanya'ya ulaşmış adayların gerçek varış tarihi bilinmediği için tarih atanmaz
    // (bu adaylar "Almanya'ya ulaşan" toplamında sayılır, ancak aylık grafiklere ve "bu ay" sayısına girmez).
    async function arrivalMap(candIds) {
        const q = { type: 'stage_change', stageKey: 'almanya', 'meta.legacy': { $exists: false } };
        if (candIds) q.candidateId = { $in: candIds };
        const ev = await ProcessEvent.find(q).select('candidateId createdAt').sort({ createdAt: 1 }).lean();
        const out = {};
        ev.forEach(e => { out[String(e.candidateId)] = new Date(e.createdAt); });
        return out;
    }

    // ==================================================================
    //  YÖNETİM PANELİ VERİLERİ (gerçek veritabanı)
    // ==================================================================
    async function dashboardData() {
        const now = new Date(), today = startOfDay(), tomorrow = new Date(today.getTime() + DAY), som = startOfMonth();
        const [cands, orders, staff, appts, companies] = await Promise.all([
            Candidate.find().select('firstName lastName currentStage company status applicationDate stageEnteredAt lastActivityAt documents.status documents.name documents.date documents._id cancelledAt stageReviewNeeded').lean(),
            WorkOrder.find({ status: { $in: OPEN } }).select('code title candidateName candidateId assignedTo dueDate priority status').populate('assignedTo', 'fullName').lean(),
            Staff.find({ deletedAt: null, status: 'active' }).select('fullName title').lean(),
            Appointment.find({ status: { $ne: 'Reddedildi' } }).populate('candidateId', 'firstName lastName').lean(),
            Company.find().select('name').lean()
        ]);
        const active = cands.filter(c => c.status !== 'cancelled');
        const cancelled = cands.filter(c => c.status === 'cancelled');
        const arrivals = await arrivalMap();
        const arrivedAll = active.filter(c => c.currentStage === FINAL);
        const arrivedThisMonth = arrivedAll.filter(c => arrivals[String(c._id)] && arrivals[String(c._id)] >= som);
        const inProcess = active.filter(c => c.currentStage !== FINAL);
        const overdue = orders.filter(o => o.dueDate && new Date(o.dueDate) < now);
        const dueToday = orders.filter(o => o.dueDate && new Date(o.dueDate) >= now && new Date(o.dueDate) < tomorrow);
        const issueStates = await CandidateStage.find({ status: 'Sorun Var' }).select('candidateId').lean();
        const issueSet = new Set(issueStates.map(s => String(s.candidateId)));
        const openByCand = new Set(orders.filter(o => o.candidateId).map(o => String(o.candidateId)));
        const pendingDocCands = inProcess.filter(c => (c.documents || []).some(d => d.status === 'İnceleniyor'));
        // İşlem bekleyen: süreçte olup bekleyen belgesi, açık görevi veya sorunu olan aday
        const needsAction = inProcess.filter(c => (c.documents || []).some(d => d.status === 'İnceleniyor') || openByCand.has(String(c._id)) || issueSet.has(String(c._id)));
        const unassigned = active.filter(c => !c.company || c.company === 'Atanmadı');
        const stale = await P().staleCandidates();
        const inactive = inProcess.filter(c => c.lastActivityAt && now - new Date(c.lastActivityAt) > 15 * DAY).sort((a, b) => new Date(a.lastActivityAt) - new Date(b.lastActivityAt));
        const todayStr = today.toISOString().slice(0, 10);
        const localToday = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
        const todayAppts = appts.filter(a => a.date === localToday || a.date === todayStr).sort((a, b) => String(a.time).localeCompare(String(b.time)));
        // Aylık başvuru ve varış grafikleri (son 12 ay)
        const months = []; for (let i = 11; i >= 0; i--) months.push(monthKey(new Date(now.getFullYear(), now.getMonth() - i, 1)));
        const monthly = months.map(k => ({
            key: k, label: monthLabel(k),
            applications: cands.filter(c => c.applicationDate && monthKey(new Date(c.applicationDate)) === k).length,
            arrivals: Object.entries(arrivals).filter(([id, d]) => monthKey(d) === k && active.some(c => String(c._id) === id)).length,
            cancellations: cancelled.filter(c => c.cancelledAt && monthKey(new Date(c.cancelledAt)) === k).length
        }));
        // Şirket dağılımı — iptal edilen adaylar şirket sayımına dahil edilmez
        const companyDist = companies.map(co => ({ name: co.name, _id: co._id, active: active.filter(c => c.company === co.name).length, cancelled: cancelled.filter(c => c.company === co.name).length }))
            .concat([{ name: 'Atanmadı', active: unassigned.length, cancelled: cancelled.filter(c => !c.company || c.company === 'Atanmadı').length }])
            .sort((a, b) => b.active - a.active);
        // Aşama bekleme süreleri
        const sts = await CandidateStage.find({ startedAt: { $ne: null } }).select('candidateId stageKey status startedAt completedAt skipped').lean();
        const activeIds = new Set(active.map(c => String(c._id)));
        const stageWait = STAGE_DEFS.slice(0, -1).map(d => {
            const done = sts.filter(s => s.stageKey === d.key && s.status === 'Tamamlandı' && !s.skipped && s.completedAt && activeIds.has(String(s.candidateId))).map(s => (new Date(s.completedAt) - new Date(s.startedAt)) / DAY).filter(x => x >= 0);
            const waiting = active.filter(c => c.currentStage === d.name && c.stageEnteredAt).map(c => (now - new Date(c.stageEnteredAt)) / DAY);
            return { key: d.key, name: d.name, avgDone: done.length ? done.reduce((a, b) => a + b, 0) / done.length : null, avgWaiting: waiting.length ? waiting.reduce((a, b) => a + b, 0) / waiting.length : null, waitingCount: waiting.length };
        });
        const worstStages = stageWait.filter(s => s.avgWaiting !== null).sort((a, b) => b.avgWaiting - a.avgWaiting).slice(0, 3);
        // Personel yapılacakları
        const staffTodo = staff.map(s => {
            const mine = orders.filter(o => o.assignedTo && String(o.assignedTo._id) === String(s._id));
            return { _id: s._id, name: s.fullName, title: s.title, open: mine.length, overdue: mine.filter(o => o.dueDate && new Date(o.dueDate) < now).length, today: mine.filter(o => o.dueDate && new Date(o.dueDate) >= now && new Date(o.dueDate) < tomorrow).length };
        }).filter(s => s.open).sort((a, b) => (b.overdue - a.overdue) || (b.open - a.open));
        const decided = arrivedAll.length + cancelled.length;
        return {
            kpi: {
                total: cands.length, active: active.length, arrived: arrivedAll.length, needsAction: needsAction.length, overdueTasks: overdue.length,
                arrivedThisMonth: arrivedThisMonth.length, cancelled: cancelled.length, unassigned: unassigned.length, review: cands.filter(c => c.stageReviewNeeded).length
            },
            stageDist: STAGE_DEFS.map(d => ({ name: d.name, key: d.key, count: active.filter(c => c.currentStage === d.name).length })),
            companyDist, monthly, stageWait, worstStages,
            rates: { success: decided ? Math.round(arrivedAll.length / decided * 100) : null, cancel: cands.length ? Math.round(cancelled.length / cands.length * 100) : 0, successOfAll: cands.length ? Math.round(arrivedAll.length / cands.length * 100) : 0 },
            today: {
                dueToday, overdue: overdue.sort((a, b) => new Date(a.dueDate) - new Date(b.dueDate)), appointments: todayAppts,
                pendingDocCands: pendingDocCands.map(c => ({ _id: c._id, name: fullName(c), count: (c.documents || []).filter(d => d.status === 'İnceleniyor').length })),
                stale, inactive: inactive.map(c => ({ _id: c._id, name: fullName(c), stage: c.currentStage, days: Math.floor((now - new Date(c.lastActivityAt)) / DAY) })),
                staffTodo
            },
            ids: { needsAction: needsAction.map(c => String(c._id)), arrivedThisMonth: arrivedThisMonth.map(c => String(c._id)) }
        };
    }
    app.locals.crmDashboard = dashboardData;

    // ==================================================================
    //  İLETİŞİM MERKEZİ
    // ==================================================================
    function readContact(b) {
        const type = Object.keys(CONTACT_TYPES).includes(b.type) ? b.type : null;
        if (!type) return null;
        const summary = str(b.summary, 4000);
        if (!summary && !str(b.subject, 200)) return null;
        let at = b.contactAt ? new Date(b.contactAt) : new Date();
        if (isNaN(at) || at > new Date(Date.now() + 5 * 60000)) at = new Date(); // gelecek tarihli kayıt kabul edilmez
        const dur = parseInt(b.durationMin, 10);
        return { type, direction: ['outgoing', 'incoming'].includes(b.direction) ? b.direction : '', subject: str(b.subject, 200), summary, outcome: str(b.outcome, 300), contactAt: at, durationMin: dur >= 0 && dur <= 600 ? dur : undefined };
    }

    async function candidateTimeline(candidateId) {
        const [contacts, messages] = await Promise.all([
            CandidateContact.find({ candidateId }).sort({ contactAt: -1 }).limit(300).lean(),
            Message.find({ candidateId }).sort({ date: -1 }).limit(200).lean()
        ]);
        const items = contacts.map(c => ({ kind: 'contact', at: c.contactAt, ...c }))
            .concat(messages.map(m => ({ kind: 'panel', at: m.date, type: 'panel', summary: m.content, authorName: m.sender === 'Admin' ? 'Yönetici' : 'Aday', direction: m.sender === 'Admin' ? 'outgoing' : 'incoming', isRead: m.isRead, _id: m._id })));
        items.sort((a, b) => new Date(b.at) - new Date(a.at));
        return { items, counts: Object.fromEntries(Object.keys(CONTACT_TYPES).map(k => [k, contacts.filter(c => c.type === k).length])) };
    }
    app.locals.candidateTimeline = candidateTimeline;

    app.post('/admin/candidate/:id/contact', adminAuthCheck, async (req, res) => {
        const back = `/admin/candidate/${req.params.id}#contacts`;
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const c = await Candidate.findById(req.params.id).select('_id firstName lastName');
        if (!c) return res.redirect('/admin?error=not_found');
        const data = readContact(req.body);
        if (!data) return res.redirect(withParam(back, 'error', 'missing_fields'));
        await CandidateContact.create({ ...data, candidateId: c._id, source: 'manual', authorType: 'admin', authorId: 'admin', authorName: 'Yönetici' });
        await Candidate.updateOne({ _id: c._id }, { $set: { lastActivityAt: new Date() } });
        await svc().audit(req, 'candidate.contact', 'Candidate', c._id, `${fullName(c)}: ${CONTACT_TYPES[data.type]} kaydı eklendi`);
        res.redirect(withParam(back, 'status', 'contact_added'));
    });

    // Personel: yalnızca kendisine atanmış (iptal edilmemiş) görevin adayı için iletişim kaydı ekleyebilir
    app.post('/personel/gorev/:id/contact', (req, res, next) => app.locals.staffAuth(req, res, next), async (req, res) => {
        const wo = await app.locals.ownTask(req, res); if (!wo) return;
        const back = `/personel/gorev/${wo._id}#contacts`;
        if (wo.status === 'İptal' || !wo.candidateId) return res.redirect(withParam(back, 'error', 'invalid_state'));
        const data = readContact(req.body);
        if (!data) return res.redirect(withParam(back, 'error', 'missing_fields'));
        await CandidateContact.create({ ...data, candidateId: wo.candidateId, source: 'manual', authorType: 'staff', authorId: String(req.staff._id), authorName: req.staff.fullName });
        await Candidate.updateOne({ _id: wo.candidateId }, { $set: { lastActivityAt: new Date() } });
        await svc().audit(req, 'candidate.contact', 'Candidate', wo.candidateId, `${wo.code}: ${CONTACT_TYPES[data.type]} kaydı eklendi`);
        res.redirect(withParam(back, 'status', 'contact_added'));
    });
    app.locals.staffCandidateContacts = (candidateId) => CandidateContact.find({ candidateId }).sort({ contactAt: -1 }).limit(30).lean();

    // ==================================================================
    //  ŞİRKET / İŞVEREN
    // ==================================================================
    async function companyStats() {
        const [companies, cands] = await Promise.all([Company.find().sort({ name: 1 }).lean(), Candidate.find().select('company status currentStage applicationDate').lean()]);
        const arrivals = await arrivalMap();
        const approvalStages = ['Ön Onay Sözleşmesi', 'Ön Onay'];
        return companies.map(co => {
            const mine = cands.filter(c => c.company === co.name);
            const act = mine.filter(c => c.status !== 'cancelled');
            const arrived = act.filter(c => c.currentStage === FINAL);
            const durs = arrived.map(c => arrivals[String(c._id)] && c.applicationDate ? (arrivals[String(c._id)] - new Date(c.applicationDate)) / DAY : null).filter(x => x !== null && x >= 0);
            return {
                ...co, active: act.length, cancelled: mine.length - act.length, arrived: arrived.length,
                waitingApproval: act.filter(c => approvalStages.includes(c.currentStage)).length, inProcess: act.filter(c => c.currentStage !== FINAL).length,
                openPositions: (co.positions || []).filter(p => p.active).reduce((a, p) => a + (p.openings || 0), 0),
                successRate: mine.length ? Math.round(arrived.length / mine.length * 100) : null,
                avgDays: durs.length ? durs.reduce((a, b) => a + b, 0) / durs.length : null
            };
        });
    }

    app.get('/admin/sirketler', adminAuthCheck, async (req, res) => {
        res.render('admin_companies', { rows: await companyStats(), CONTRACT: Company.CONTRACT_STATUSES, user: { firstName: 'Admin' } });
    });

    app.get('/admin/sirketler/:id', adminAuthCheck, async (req, res) => {
        if (!isId(req.params.id)) return res.redirect('/admin/sirketler?error=not_found');
        const co = await Company.findById(req.params.id).lean();
        if (!co) return res.redirect('/admin/sirketler?error=not_found');
        const stats = (await companyStats()).find(r => String(r._id) === String(co._id));
        const cands = await Candidate.find({ company: co.name }).select('firstName lastName currentStage status stageEnteredAt cancelReason cancelledAt job').sort({ firstName: 1 }).lean();
        res.render('admin_company_detail', { co, stats, cands, CONTRACT: Company.CONTRACT_STATUSES, stages: STAGE_NAMES, user: { firstName: 'Admin' } });
    });

    app.post('/admin/sirketler/:id', adminAuthCheck, async (req, res) => {
        const back = `/admin/sirketler/${req.params.id}`;
        if (!isId(req.params.id)) return res.redirect('/admin/sirketler?error=not_found');
        const co = await Company.findById(req.params.id);
        if (!co) return res.redirect('/admin/sirketler?error=not_found');
        const b = req.body;
        const name = str(b.name, 80);
        if (!name || name === 'Atanmadı') return res.redirect(withParam(back, 'error', 'missing_fields'));
        if (name !== co.name) {
            if (await Company.exists({ name, _id: { $ne: co._id } })) return res.redirect(withParam(back, 'error', 'company_exists'));
            await Candidate.updateMany({ company: co.name }, { $set: { company: name } });
            co.name = name;
        }
        const email = str(b.email, 160);
        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.redirect(withParam(back, 'error', 'bad_email'));
        Object.assign(co, { contactPerson: str(b.contactPerson, 120), phone: str(b.phone, 40), email, address: str(b.address, 300), city: str(b.city, 80), website: str(b.website, 200), notes: str(b.notes, 4000) });
        if (Company.CONTRACT_STATUSES.includes(b.contractStatus)) co.contractStatus = b.contractStatus;
        const cs = b.contractStart ? new Date(b.contractStart) : null, ce = b.contractEnd ? new Date(b.contractEnd) : null;
        co.contractStart = cs && !isNaN(cs) ? cs : undefined; co.contractEnd = ce && !isNaN(ce) ? ce : undefined;
        if (co.contractStart && co.contractEnd && co.contractEnd < co.contractStart) return res.redirect(withParam(back, 'error', 'bad_date'));
        await co.save();
        await svc().audit(req, 'company.update', 'Company', co._id, `${co.name} bilgileri güncellendi`);
        res.redirect(withParam(back, 'status', 'company_updated'));
    });

    app.post('/admin/sirketler/:id/position', adminAuthCheck, async (req, res) => {
        const back = `/admin/sirketler/${req.params.id}#positions`;
        if (!isId(req.params.id)) return res.redirect('/admin/sirketler?error=not_found');
        const co = await Company.findById(req.params.id);
        if (!co) return res.redirect('/admin/sirketler?error=not_found');
        if (isId(req.body.positionId)) {
            const p = co.positions.id(req.body.positionId);
            if (!p) return res.redirect(withParam(back, 'error', 'not_found'));
            if (req.body._action === 'delete') p.deleteOne(); else p.active = !p.active;
        } else {
            const title = str(req.body.title, 120);
            if (!title) return res.redirect(withParam(back, 'error', 'missing_fields'));
            co.positions.push({ title, city: str(req.body.city, 80), openings: Math.max(0, Math.min(9999, parseInt(req.body.openings, 10) || 1)), active: true });
        }
        await co.save();
        await svc().audit(req, 'company.positions', 'Company', co._id, `${co.name}: pozisyonlar güncellendi`);
        res.redirect(withParam(back, 'status', 'company_updated'));
    });

    // ==================================================================
    //  RAPORLAMA
    // ==================================================================
    function parseFilters(q) {
        const today = startOfDay();
        let from = q.from ? new Date(q.from + 'T00:00:00') : new Date(today.getFullYear(), today.getMonth() - 5, 1);
        let to = q.to ? new Date(q.to + 'T23:59:59') : new Date(today.getTime() + DAY - 1);
        if (isNaN(from)) from = new Date(today.getFullYear(), today.getMonth() - 5, 1);
        if (isNaN(to)) to = new Date(today.getTime() + DAY - 1);
        if (from > to) [from, to] = [to, from];
        return {
            from, to, staff: isId(q.staff) ? q.staff : '', company: str(q.company, 80), stage: STAGE_NAMES.includes(q.stage) ? q.stage : '',
            status: ['active', 'cancelled', 'arrived'].includes(q.status) ? q.status : '', period: ['day', 'week', 'month'].includes(q.period) ? q.period : 'month',
            fromStr: q.from || '', toStr: q.to || ''
        };
    }
    const bucketKey = (d, period) => {
        const x = new Date(d);
        if (period === 'day') return x.toISOString().slice(0, 10);
        if (period === 'week') { const m = new Date(x); const day = (m.getDay() + 6) % 7; m.setDate(m.getDate() - day); m.setHours(0, 0, 0, 0); return 'H ' + `${m.getDate()}.${m.getMonth() + 1}.${String(m.getFullYear()).slice(2)}`; }
        return monthLabel(monthKey(x));
    };
    function buckets(from, to, period) {
        const out = []; const d = new Date(from);
        if (period === 'month') { d.setDate(1); while (d <= to) { out.push(bucketKey(d, 'month')); d.setMonth(d.getMonth() + 1); } }
        else if (period === 'week') { const day = (d.getDay() + 6) % 7; d.setDate(d.getDate() - day); while (d <= to) { out.push(bucketKey(d, 'week')); d.setDate(d.getDate() + 7); } }
        else { while (d <= to && out.length < 400) { out.push(bucketKey(d, 'day')); d.setDate(d.getDate() + 1); } }
        return out;
    }

    async function computeReport(f) {
        const cq = {};
        if (f.company) cq.company = f.company;
        if (f.stage) cq.currentStage = f.stage;
        if (f.status === 'active') cq.status = { $ne: 'cancelled' };
        if (f.status === 'cancelled') cq.status = 'cancelled';
        if (f.status === 'arrived') { cq.status = { $ne: 'cancelled' }; cq.currentStage = FINAL; }
        let cands = await Candidate.find(cq).select('firstName lastName company status currentStage applicationDate cancelledAt stageEnteredAt').lean();
        let staffCandIds = null;
        if (f.staff) { // personel filtresi: personelin görev aldığı adaylar
            staffCandIds = new Set((await WorkOrder.find({ assignedTo: f.staff }).distinct('candidateId')).map(String));
            cands = cands.filter(c => staffCandIds.has(String(c._id)));
        }
        const ids = cands.map(c => c._id);
        const arrivals = await arrivalMap(ids);
        const inRange = (d) => d && new Date(d) >= f.from && new Date(d) <= f.to;
        const newCands = cands.filter(c => inRange(c.applicationDate));
        const arrivedInRange = cands.filter(c => c.status !== 'cancelled' && c.currentStage === FINAL && inRange(arrivals[String(c._id)]));
        const cancelledInRange = cands.filter(c => c.status === 'cancelled' && inRange(c.cancelledAt));
        const bk = buckets(f.from, f.to, f.period);
        const series = bk.map(k => ({ label: k, applications: newCands.filter(c => bucketKey(c.applicationDate, f.period) === k).length, arrivals: arrivedInRange.filter(c => bucketKey(arrivals[String(c._id)], f.period) === k).length, cancellations: cancelledInRange.filter(c => bucketKey(c.cancelledAt, f.period) === k).length }));
        const companyNames = [...new Set(cands.map(c => c.company || 'Atanmadı'))].sort((a, b) => a.localeCompare(b, 'tr'));
        const byCompany = companyNames.map(n => {
            const l = cands.filter(c => (c.company || 'Atanmadı') === n);
            return { name: n, active: l.filter(c => c.status !== 'cancelled').length, cancelled: l.filter(c => c.status === 'cancelled').length, arrived: l.filter(c => c.status !== 'cancelled' && c.currentStage === FINAL).length, newInRange: l.filter(c => inRange(c.applicationDate)).length };
        }).sort((a, b) => b.active - a.active);
        // Personel performansı (tarih aralığında oluşturulan görevler)
        const woQ = { createdAt: { $gte: f.from, $lte: f.to } }; if (f.staff) woQ.assignedTo = f.staff;
        const [wos, staffList] = await Promise.all([WorkOrder.find(woQ).select('assignedTo status dueDate createdAt startedAt completedAt candidateId').lean(), Staff.find(f.staff ? { _id: f.staff } : {}).select('fullName title status deletedAt').lean()]);
        const staffPerf = staffList.map(s => {
            const m = wos.filter(w => String(w.assignedTo) === String(s._id));
            const st = svc().computeStats(m);
            return { name: s.fullName + (s.deletedAt ? ' (devre dışı)' : s.status !== 'active' ? ' (pasif)' : ''), ...st, candidates: new Set(m.filter(w => w.candidateId).map(w => String(w.candidateId))).size, rate: st.total ? Math.round(st.completed / st.total * 100) : null };
        }).filter(r => r.total || r.cancelled || f.staff).sort((a, b) => b.total - a.total);
        // Aşama bekleme süreleri
        const sts = await CandidateStage.find({ candidateId: { $in: ids }, startedAt: { $ne: null } }).select('stageKey status startedAt completedAt skipped').lean();
        const stageWait = STAGE_DEFS.slice(0, -1).map(d => {
            const done = sts.filter(s => s.stageKey === d.key && s.status === 'Tamamlandı' && !s.skipped && s.completedAt && inRange(s.completedAt)).map(s => (new Date(s.completedAt) - new Date(s.startedAt)) / DAY).filter(x => x >= 0);
            return { name: d.name, count: done.length, avg: done.length ? done.reduce((a, b) => a + b, 0) / done.length : null, max: done.length ? Math.max(...done) : null, current: cands.filter(c => c.status !== 'cancelled' && c.currentStage === d.name).length };
        });
        const compl = arrivedInRange.map(c => c.applicationDate && arrivals[String(c._id)] ? (arrivals[String(c._id)] - new Date(c.applicationDate)) / DAY : null).filter(x => x !== null && x >= 0);
        const cohortArrived = newCands.filter(c => c.status !== 'cancelled' && c.currentStage === FINAL).length;
        const cohortCancelled = newCands.filter(c => c.status === 'cancelled').length;
        return {
            f, series, byCompany, staffPerf, stageWait,
            summary: {
                candidates: cands.length, newInRange: newCands.length, arrivedInRange: arrivedInRange.length, cancelledInRange: cancelledInRange.length,
                avgCompletionDays: compl.length ? compl.reduce((a, b) => a + b, 0) / compl.length : null,
                cohortSuccessRate: newCands.length ? Math.round(cohortArrived / newCands.length * 100) : null,
                cohortCancelRate: newCands.length ? Math.round(cohortCancelled / newCands.length * 100) : null,
                active: cands.filter(c => c.status !== 'cancelled').length, cancelledTotal: cands.filter(c => c.status === 'cancelled').length
            }
        };
    }

    app.get('/admin/raporlar', adminAuthCheck, async (req, res) => {
        const f = parseFilters(req.query);
        const [r, staffList, companies] = await Promise.all([computeReport(f), Staff.find().sort({ fullName: 1 }).select('fullName deletedAt').lean(), Company.find().sort({ name: 1 }).select('name').lean()]);
        res.render('admin_reports', { r, staffList, companies, stages: STAGE_NAMES, qs: new URLSearchParams(Object.entries({ from: f.fromStr, to: f.toStr, staff: f.staff, company: f.company, stage: f.stage, status: f.status, period: f.period }).filter(([, v]) => v)).toString(), user: { firstName: 'Admin' } });
    });

    const fmtD = (v) => v == null ? '—' : v.toFixed(1);
    const filterText = (f, staffName) => [`Tarih: ${f.from.toLocaleDateString('tr-TR')} – ${f.to.toLocaleDateString('tr-TR')}`, f.company && `Şirket: ${f.company}`, f.stage && `Aşama: ${f.stage}`, f.status && `Durum: ${({ active: 'Aktif', cancelled: 'İptal', arrived: 'Almanya\'ya ulaşan' })[f.status]}`, staffName && `Personel: ${staffName}`].filter(Boolean).join(' · ');

    app.get('/admin/raporlar.csv', adminAuthCheck, async (req, res) => {
        const f = parseFilters(req.query);
        const r = await computeReport(f);
        const staffName = f.staff ? ((await Staff.findById(f.staff).select('fullName').lean()) || {}).fullName : '';
        const cell = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const lines = [];
        const row = (...a) => lines.push(a.map(cell).join(';'));
        row('BERLINER Yönetim Raporu'); row(filterText(f, staffName)); row('');
        row('ÖZET'); row('Toplam aday (filtre)', r.summary.candidates); row('Aktif', r.summary.active); row('İptal', r.summary.cancelledTotal);
        row('Dönemde yeni aday', r.summary.newInRange); row('Dönemde Almanya\'ya ulaşan', r.summary.arrivedInRange); row('Dönemde iptal edilen', r.summary.cancelledInRange);
        row('Ortalama tamamlanma süresi (gün)', fmtD(r.summary.avgCompletionDays)); row('Dönem başvurularında başarı oranı (%)', r.summary.cohortSuccessRate ?? '—'); row('Dönem başvurularında iptal oranı (%)', r.summary.cohortCancelRate ?? '—'); row('');
        row('DÖNEMSEL'); row('Dönem', 'Yeni aday', 'Almanya\'ya ulaşan', 'İptal'); r.series.forEach(s => row(s.label, s.applications, s.arrivals, s.cancellations)); row('');
        row('ŞİRKET BAZLI'); row('Şirket', 'Aktif', 'Almanya\'ya ulaşan', 'İptal', 'Dönemde yeni'); r.byCompany.forEach(c => row(c.name, c.active, c.arrived, c.cancelled, c.newInRange)); row('');
        row('PERSONEL PERFORMANSI'); row('Personel', 'Görev', 'Tamamlanan', 'Devam eden', 'Geciken', 'Tamamlama oranı (%)', 'Ort. süre (saat)', 'Aday sayısı'); r.staffPerf.forEach(s => row(s.name, s.total, s.completed, s.inProgress + s.newCount, s.overdue, s.rate ?? '—', s.avgHours == null ? '—' : s.avgHours.toFixed(1), s.candidates)); row('');
        row('AŞAMA BEKLEME SÜRELERİ'); row('Aşama', 'Tamamlanan kayıt', 'Ort. gün', 'En uzun gün', 'Şu an bekleyen'); r.stageWait.forEach(s => row(s.name, s.count, fmtD(s.avg), fmtD(s.max), s.current));
        await svc().audit(req, 'report.export_csv', 'Report', '', filterText(f, staffName));
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="berliner_rapor_${new Date().toISOString().slice(0, 10)}.csv"`);
        res.send('﻿' + lines.join('\r\n'));
    });

    app.get('/admin/raporlar.pdf', adminAuthCheck, async (req, res) => {
        const f = parseFilters(req.query);
        const r = await computeReport(f);
        const staffName = f.staff ? ((await Staff.findById(f.staff).select('fullName').lean()) || {}).fullName : '';
        const doc = new PDFDocument({ size: 'A4', margin: 40, bufferPages: true, info: { Title: 'BERLINER Yönetim Raporu' } });
        const fontDir = path.join(__dirname, '..', 'assets', 'fonts');
        doc.registerFont('R', path.join(fontDir, 'DejaVuSans.ttf')); doc.registerFont('B', path.join(fontDir, 'DejaVuSans-Bold.ttf'));
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="berliner_rapor_${new Date().toISOString().slice(0, 10)}.pdf"`);
        doc.pipe(res);
        const RED = '#D4111B', INK = '#0F172A', MUTED = '#64748B', LINE = '#E6E9F0';
        const W = doc.page.width - 80;
        doc.rect(0, 0, doc.page.width, 70).fill('#0B1220');
        doc.rect(0, 70, doc.page.width, 4).fill(RED);
        const logo = path.join(__dirname, '..', '..', 'public', 'img', 'berliner-logo.png');
        let tx = 40;
        try { if (require('fs').existsSync(logo)) { doc.image(logo, 40, 12, { width: 46, height: 46 }); tx = 96; } } catch (e) { /* logo yoksa metinle devam */ }
        doc.font('B').fontSize(18).fill('#fff').text('BERLINER · Yönetim Raporu', tx, 22);
        doc.font('R').fontSize(9).fill('#CBD5E1').text(`Oluşturulma: ${new Date().toLocaleString('tr-TR')}`, tx, 46);
        doc.y = 90; doc.font('R').fontSize(9).fill(MUTED).text(filterText(f, staffName), 40, doc.y, { width: W });
        const section = (t) => { if (doc.y > 720) doc.addPage(); doc.moveDown(1); doc.font('B').fontSize(12).fill(RED).text(t, 40); doc.moveDown(0.3); };
        const table = (cols, rows, widths) => {
            const x0 = 40; let y = doc.y;
            const drawRow = (vals, bold, bg) => {
                if (y > 770) { doc.addPage(); y = 40; }
                if (bg) doc.rect(x0, y - 3, W, 17).fill(bg);
                let x = x0;
                vals.forEach((v, i) => { doc.font(bold ? 'B' : 'R').fontSize(8.5).fill(INK).text(String(v ?? '—'), x + 3, y, { width: widths[i] - 6, ellipsis: true, lineBreak: false, align: i ? 'right' : 'left' }); x += widths[i]; });
                y += 17; doc.moveTo(x0, y - 3).lineTo(x0 + W, y - 3).strokeColor(LINE).lineWidth(0.5).stroke();
            };
            drawRow(cols, true, '#F3F4F6'); rows.forEach(rw => drawRow(rw, false)); doc.y = y + 4;
        };
        section('Özet');
        const s = r.summary;
        table(['Gösterge', 'Değer'], [['Toplam aday (filtre)', s.candidates], ['Aktif aday', s.active], ['İptal edilen (toplam)', s.cancelledTotal], ['Dönemde yeni aday', s.newInRange], ["Dönemde Almanya'ya ulaşan", s.arrivedInRange], ['Dönemde iptal edilen', s.cancelledInRange], ['Ort. tamamlanma süresi (gün)', fmtD(s.avgCompletionDays)], ['Dönem başvurularında başarı oranı', s.cohortSuccessRate == null ? '—' : s.cohortSuccessRate + '%'], ['Dönem başvurularında iptal oranı', s.cohortCancelRate == null ? '—' : s.cohortCancelRate + '%']], [W * 0.7, W * 0.3]);
        section(`Dönemsel (${({ day: 'günlük', week: 'haftalık', month: 'aylık' })[f.period]})`);
        table(['Dönem', 'Yeni aday', "Almanya'ya ulaşan", 'İptal'], r.series.slice(-40).map(x => [x.label, x.applications, x.arrivals, x.cancellations]), [W * 0.4, W * 0.2, W * 0.2, W * 0.2]);
        section('Şirket bazlı');
        table(['Şirket', 'Aktif', 'Ulaşan', 'İptal', 'Dönemde yeni'], r.byCompany.map(c => [c.name, c.active, c.arrived, c.cancelled, c.newInRange]), [W * 0.4, W * 0.15, W * 0.15, W * 0.15, W * 0.15]);
        section('Personel performansı (dönemde atanan görevler)');
        table(['Personel', 'Görev', 'Tamam', 'Devam', 'Geciken', 'Oran', 'Ort. süre'], r.staffPerf.map(x => [x.name, x.total, x.completed, x.inProgress + x.newCount, x.overdue, x.rate == null ? '—' : x.rate + '%', svc() && x.avgHours != null ? x.avgHours.toFixed(1) + ' sa' : '—']), [W * 0.34, W * 0.1, W * 0.1, W * 0.1, W * 0.11, W * 0.11, W * 0.14]);
        section('Aşama bekleme süreleri');
        table(['Aşama', 'Kayıt', 'Ort. gün', 'En uzun', 'Bekleyen'], r.stageWait.map(x => [x.name, x.count, fmtD(x.avg), fmtD(x.max), x.current]), [W * 0.4, W * 0.15, W * 0.15, W * 0.15, W * 0.15]);
        const range = doc.bufferedPageRange();
        for (let i = 0; i < range.count; i++) { doc.switchToPage(i); doc.font('R').fontSize(8).fill(MUTED).text(`BERLINER · Sayfa ${i + 1}/${range.count}`, 40, doc.page.height - 30, { width: W, align: 'right', lineBreak: false }); }
        doc.end();
        svc().audit(req, 'report.export_pdf', 'Report', '', filterText(f, staffName));
    });

    app.locals.crm = { dashboardData, computeReport, companyStats, candidateTimeline, parseFilters };
};
