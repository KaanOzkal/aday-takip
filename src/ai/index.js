// =====================================================================
//  AI YÖNETİCİ ASİSTANI
//  - ANTHROPIC_API_KEY tanımlıysa: Claude, gerçek verileri araçlarla (tool use) okuyarak yanıtlar.
//  - Tanımlı değilse: yerel analiz motoru aynı sorulara gerçek verilerle yanıt verir.
//  - Veri değiştiren her işlem "öneri" olarak döner; yalnızca admin onaylayınca uygulanır.
// =====================================================================
const crypto = require('crypto');
const mongoose = require('mongoose');
const Staff = require('../models/Staff');
const AutomationLog = require('../models/AutomationLog');
const StageConfig = require('../models/StageConfig');
const CandidateStage = require('../models/CandidateStage');
const { STAGE_DEFS, byKey } = require('../process/stages');

const norm = (s) => String(s || '').toLocaleLowerCase('tr-TR').replace(/ç/g, 'c').replace(/ğ/g, 'g').replace(/ı/g, 'i').replace(/i̇/g, 'i').replace(/ö/g, 'o').replace(/ş/g, 's').replace(/ü/g, 'u').replace(/['’`]/g, '').replace(/\s+/g, ' ').trim();
const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const API_URL = () => (process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com').replace(/\/$/, '') + '/v1/messages';
const MODEL = () => process.env.AI_MODEL || 'claude-sonnet-4-5';

// Mesajdaki aşamayı bul (sıra önemli: "ön onay sözleşmesi" → "ön onay"dan önce)
const STAGE_PATTERNS = [
    ['on_onay_sozlesmesi', /on ?onay sozlesme/],
    ['hizmet_sozlesmesi', /hizmet sozlesme|hizmet asama|\bsozlesme asama/],
    ['evrak_teslimi', /evrak/],
    ['tercume_islemleri', /tercume/],
    ['giris_islemleri', /giris islem|giris asama/],
    ['on_onay', /on ?onay|vorab/],
    ['vize_randevusu', /vize|randevu/],
    ['seyahat_plani', /seyahat|ucus|bilet/],
    ['almanya', /almanya/]
];
const detectStage = (n) => { for (const [k, rx] of STAGE_PATTERNS) if (rx.test(n)) return k; return null; };

module.exports = function mountAI(app, deps) {
    const { adminAuthCheck, Candidate } = deps;
    const P = () => app.locals.processService;
    const S = () => app.locals.services;

    // ------------------------------------------------------------------
    //  Ortak veri araçları (hem Claude hem yerel motor kullanır)
    // ------------------------------------------------------------------
    async function insights() {
        const [summary, stale, workload, overdue, failed, cfgs, issues] = await Promise.all([
            P().stageSummary(), P().staleCandidates(), P().staffWorkload(), P().overdueTasks(100),
            AutomationLog.countDocuments({ status: { $in: ['failed', 'partial'] }, resolvedAt: null }),
            StageConfig.find().select('stageKey automationEnabled defaultStaffId').lean(),
            CandidateStage.find({ status: 'Sorun Var' }).select('candidateId stageKey issueNote').lean()
        ]);
        const total = summary.reduce((a, b) => a + b.count, 0);
        const notes = [];
        const active = summary.slice(0, -1).filter(s => s.count);
        if (active.length) {
            const top = active.reduce((a, b) => (b.count > a.count ? b : a));
            if (total && top.count / total >= 0.3) notes.push(`Adayların %${Math.round(top.count / total * 100)}'i **${top.name}** aşamasında yığılmış (${top.count} aday). Bu aşamaya ek personel ataması veya süreç hızlandırma değerlendirilebilir.`);
        }
        if (stale.length) notes.push(`**${stale.length} aday** bekleme sınırını aşmış. En uzun: ${stale.slice(0, 3).map(s => `${s.name} (${s.stage}, ${s.days} gün)`).join(', ')}.`);
        if (issues.length) notes.push(`**${issues.length} aşamada "Sorun Var"** işaretli. Bu adaylar öncelikli ele alınmalı.`);
        if (overdue.length) notes.push(`**${overdue.length} geciken görev** var. En eskisi: ${overdue[0].title} (${overdue[0].candidate}, ${overdue[0].days} gün gecikmiş).`);
        const activeStaff = workload.filter(w => w.status === 'active');
        if (activeStaff.length > 1) {
            const avg = activeStaff.reduce((a, b) => a + b.open, 0) / activeStaff.length;
            const heavy = activeStaff.filter(w => w.open >= Math.max(3, avg * 1.5));
            const idle = activeStaff.filter(w => w.open === 0);
            if (heavy.length) notes.push(`İş yükü dengesiz: ${heavy.map(h => `${h.name} (${h.open} açık görev)`).join(', ')}${idle.length ? `; ${idle.map(i => i.name).join(', ')} üzerinde görev yok` : ''}. Görev dağılımı yeniden yapılabilir.`);
        }
        const noStaff = cfgs.filter(c => c.automationEnabled && !c.defaultStaffId).map(c => byKey[c.stageKey] && byKey[c.stageKey].name).filter(Boolean);
        if (noStaff.length) notes.push(`${noStaff.length} aşamada varsayılan sorumlu personel tanımlı değil (${noStaff.slice(0, 4).join(', ')}${noStaff.length > 4 ? '…' : ''}); bu aşamalarda otomatik görev atanamaz.`);
        if (failed) notes.push(`${failed} otomasyon çalışması başarısız; Otomasyon > Geçmiş sayfasından yeniden denenebilir.`);
        if (!notes.length) notes.push('Süreçte dikkat gerektiren bir durum görünmüyor.');
        return { total, summary, notes };
    }

    async function findCandidatesInText(text) {
        const n = norm(text);
        const cands = await Candidate.find().select('firstName lastName currentStage').lean();
        const hits = cands.filter(c => { const full = norm(`${c.firstName} ${c.lastName}`); return full.length > 3 && n.includes(full); });
        if (hits.length) return hits;
        // soyad + ad parçası eşleşmesi
        return cands.filter(c => norm(c.lastName).length > 2 && n.includes(norm(c.lastName)) && norm(c.firstName).split(' ').some(p => p.length > 2 && n.includes(p)));
    }

    // Yönetim paneli ile aynı kaynaktan genel sayılar (iptaller aktif sayılmaz)
    async function overview() {
        const d = await app.locals.crmDashboard();
        return { ...d.kpi, successRate: d.rates.success, cancelRate: d.rates.cancel, companyRanking: d.companyDist.filter(c => c.name !== 'Atanmadı').slice(0, 10) };
    }
    async function inactiveCandidates(days = 15) {
        days = Math.max(1, Math.min(365, parseInt(days, 10) || 15));
        const since = new Date(Date.now() - days * 864e5);
        const list = await Candidate.find({ status: { $ne: 'cancelled' }, currentStage: { $ne: STAGE_DEFS[STAGE_DEFS.length - 1].name } }).select('firstName lastName currentStage company lastActivityAt stageEnteredAt applicationDate').lean();
        const rows = list.map(c => ({ _id: c._id, name: `${c.firstName} ${c.lastName}`.trim(), stage: c.currentStage, company: c.company || 'Atanmadı', last: c.lastActivityAt || c.stageEnteredAt || c.applicationDate }))
            .filter(r => !r.last || new Date(r.last) < since)
            .map(r => ({ ...r, days: r.last ? Math.floor((Date.now() - new Date(r.last)) / 864e5) : null }))
            .sort((a, b) => (b.days ?? 1e9) - (a.days ?? 1e9));
        return { days, total: rows.length, rows };
    }
    async function arrivalsThisMonth() {
        const som = new Date(); som.setDate(1); som.setHours(0, 0, 0, 0);
        const d = await app.locals.crmDashboard(); // yönetim paneliyle aynı kaynak
        const ids = d.ids.arrivedThisMonth;
        const ProcessEvent = mongoose.model('ProcessEvent');
        const [cands, ev] = await Promise.all([
            Candidate.find({ _id: { $in: ids } }).select('firstName lastName company').lean(),
            ProcessEvent.find({ candidateId: { $in: ids }, type: 'stage_change', stageKey: 'almanya' }).select('candidateId createdAt').sort({ createdAt: 1 }).lean()
        ]);
        const at = {}; ev.forEach(e => { at[String(e.candidateId)] = e.createdAt; });
        return { month: som.toLocaleDateString('tr-TR', { month: 'long', year: 'numeric' }), total: cands.length, rows: cands.map(c => ({ _id: c._id, name: `${c.firstName} ${c.lastName}`.trim(), company: c.company || 'Atanmadı', date: at[String(c._id)] })) };
    }
    async function todayTasks() {
        const d = await app.locals.crmDashboard();
        const m = (o) => ({ _id: o._id, code: o.code, title: o.title, candidate: o.candidateName, staff: o.assignedTo ? o.assignedTo.fullName : 'Atanmamış', due: o.dueDate });
        return { dueToday: d.today.dueToday.map(m), overdue: d.today.overdue.map(m), appointments: d.today.appointments.map(a => ({ time: a.time, type: a.type, status: a.status, candidate: a.candidateId ? `${a.candidateId.firstName} ${a.candidateId.lastName}` : 'Silinmiş aday' })), pendingDocuments: d.today.pendingDocCands };
    }

    // ------------------------------------------------------------------
    //  Onay bekleyen işlemler (session'da tutulur, istemciden gelen veriye güvenilmez)
    // ------------------------------------------------------------------
    function addPending(req, action) {
        const id = crypto.randomBytes(8).toString('hex');
        req.session.aiPending = req.session.aiPending || {};
        const keys = Object.keys(req.session.aiPending);
        if (keys.length >= 20) delete req.session.aiPending[keys[0]];
        req.session.aiPending[id] = { ...action, createdAt: Date.now() };
        return { id, type: action.type, summary: action.summary, details: action.details || [] };
    }

    async function proposeStageChange(req, candidateId, toKey, reason) {
        if (!isId(String(candidateId)) || !byKey[toKey]) return { error: 'Geçersiz aday veya aşama.' };
        const c = await Candidate.findById(candidateId).select('firstName lastName currentStage').lean();
        if (!c) return { error: 'Aday bulunamadı.' };
        const check = await P().move(String(c._id), toKey, { dryRun: true });
        if (!check.ok) return { error: check.message || 'Bu geçiş yapılamaz.' };
        return addPending(req, {
            type: 'stage_change', candidateId: String(c._id), toKey, reason: String(reason || 'AI asistanı önerisi, yönetici onayladı').slice(0, 300),
            summary: `${c.firstName} ${c.lastName}: ${c.currentStage} → ${byKey[toKey].name}`, details: check.warnings || []
        });
    }

    async function proposeWorkOrder(req, a) {
        if (!isId(String(a.candidate_id)) || !isId(String(a.staff_id)) || !a.title) return { error: 'Aday, personel ve başlık gerekli.' };
        const [c, s] = await Promise.all([Candidate.findById(a.candidate_id).select('firstName lastName currentStage').lean(), Staff.findById(a.staff_id).lean()]);
        if (!c) return { error: 'Aday bulunamadı.' };
        if (!s || s.deletedAt || s.status !== 'active') return { error: 'Personel aktif değil.' };
        const dueDays = Math.max(0, Math.min(90, parseInt(a.due_days, 10) || 3));
        return addPending(req, {
            type: 'work_order', candidateId: String(c._id), staffId: String(s._id), title: String(a.title).slice(0, 160), description: String(a.description || '').slice(0, 2000),
            priority: ['Düşük', 'Normal', 'Yüksek', 'Acil'].includes(a.priority) ? a.priority : 'Normal', dueDays,
            summary: `İş emri: "${String(a.title).slice(0, 80)}" → ${s.fullName} (${c.firstName} ${c.lastName}, ${dueDays} gün)`
        });
    }

    // ------------------------------------------------------------------
    //  Claude araç tanımları
    // ------------------------------------------------------------------
    const stageEnum = STAGE_DEFS.map(d => d.key);
    const TOOLS = [
        { name: 'get_overview', description: 'Genel sayılar: toplam, aktif (iptal hariç), Almanya\'ya ulaşan, bu ay Almanya\'ya giden, iptal, şirket atanmamış, işlem bekleyen, geciken görev sayıları; başarı ve iptal oranı; en çok aktif adayı olan şirketler (companyRanking).', input_schema: { type: 'object', properties: {} } },
        { name: 'get_inactive_candidates', description: 'Son N gün içinde hiçbir işlem (aşama değişikliği, belge, mesaj, iletişim kaydı, randevu) yapılmayan aktif adayları döndürür.', input_schema: { type: 'object', properties: { days: { type: 'integer', minimum: 1, maximum: 365 } } } },
        { name: 'get_arrivals_this_month', description: 'Bu ay Almanya aşamasına geçen (Almanya\'ya giden) adayları döndürür.', input_schema: { type: 'object', properties: {} } },
        { name: 'get_today_tasks', description: 'Bugün teslim tarihi olan görevler, geciken görevler, bugünkü randevular ve onay bekleyen belgeler.', input_schema: { type: 'object', properties: {} } },
        { name: 'get_stage_summary', description: 'Her aşamadaki aktif (iptal edilmemiş) aday sayısını döndürür.', input_schema: { type: 'object', properties: {} } },
        { name: 'list_candidates', description: 'Adayları listeler. stage_key ile aşamaya, stage_status ile o aşamadaki duruma (Bekliyor, Devam Ediyor, Tamamlandı, Sorun Var), name_query ile isme göre filtreler. Her satırda aday id, ad, aşama, aşama durumu ve aşamada geçen gün vardır.', input_schema: { type: 'object', properties: { stage_key: { type: 'string', enum: stageEnum }, stage_status: { type: 'string', enum: ['Bekliyor', 'Devam Ediyor', 'Tamamlandı', 'Sorun Var'] }, name_query: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 200 } } } },
        { name: 'get_stale_candidates', description: 'Aşama bekleme sınırını aşmış (uzun süredir aynı aşamada bekleyen) adayları döndürür.', input_schema: { type: 'object', properties: {} } },
        { name: 'get_staff_workload', description: 'Personel başına açık, yeni ve geciken görev sayılarını döndürür (personel id dahil).', input_schema: { type: 'object', properties: {} } },
        { name: 'get_overdue_tasks', description: 'Teslim tarihi geçmiş açık görevleri döndürür.', input_schema: { type: 'object', properties: {} } },
        { name: 'get_insights', description: 'Süreçteki darboğaz, bekleyen adaylar, iş yükü dengesizliği ve otomasyon sorunları hakkında hazır analiz notları döndürür.', input_schema: { type: 'object', properties: {} } },
        { name: 'propose_stage_change', description: 'Bir adayın aşamasını değiştirmeyi ÖNERİR. Değişiklik hemen yapılmaz; yöneticinin ekranda onaylaması gerekir.', input_schema: { type: 'object', properties: { candidate_id: { type: 'string' }, to_stage_key: { type: 'string', enum: stageEnum }, reason: { type: 'string' } }, required: ['candidate_id', 'to_stage_key', 'reason'] } },
        { name: 'propose_work_order', description: 'Bir aday için personele iş emri oluşturmayı ÖNERİR. Yönetici onaylamadan oluşturulmaz.', input_schema: { type: 'object', properties: { candidate_id: { type: 'string' }, staff_id: { type: 'string' }, title: { type: 'string' }, description: { type: 'string' }, priority: { type: 'string', enum: ['Düşük', 'Normal', 'Yüksek', 'Acil'] }, due_days: { type: 'integer', minimum: 0, maximum: 90 } }, required: ['candidate_id', 'staff_id', 'title'] } }
    ];

    async function runTool(req, name, input, actions) {
        input = input || {};
        switch (name) {
            case 'get_overview': return overview();
            case 'get_inactive_candidates': return inactiveCandidates(input.days);
            case 'get_arrivals_this_month': return arrivalsThisMonth();
            case 'get_today_tasks': return todayTasks();
            case 'get_stage_summary': return P().stageSummary();
            case 'list_candidates': return P().listCandidates({ stageKey: input.stage_key, status: input.stage_status, q: input.name_query, limit: Math.min(200, input.limit || 50) });
            case 'get_stale_candidates': return P().staleCandidates();
            case 'get_staff_workload': return P().staffWorkload();
            case 'get_overdue_tasks': return P().overdueTasks(50);
            case 'get_insights': return insights();
            case 'propose_stage_change': { const r = await proposeStageChange(req, input.candidate_id, input.to_stage_key, input.reason); if (!r.error) actions.push(r); return r.error ? r : { status: 'pending_admin_approval', summary: r.summary, warnings: r.details }; }
            case 'propose_work_order': { const r = await proposeWorkOrder(req, input); if (!r.error) actions.push(r); return r.error ? r : { status: 'pending_admin_approval', summary: r.summary }; }
            default: return { error: 'Bilinmeyen araç' };
        }
    }

    function systemPrompt() {
        const today = new Date().toLocaleDateString('tr-TR', { timeZone: 'Europe/Istanbul', day: 'numeric', month: 'long', year: 'numeric', weekday: 'long' });
        return `Sen BERLINER şirketinin aday takip sistemindeki yönetici asistanısın. Bugün: ${today}.
BERLINER, Türkiye'den Almanya'ya şoför ve kurye gibi meslek gruplarında aday yerleştirir. Her aday şu 9 aşamadan sırayla geçer:
${STAGE_DEFS.map((d, i) => `${i + 1}. ${d.name} (anahtar: ${d.key})`).join('\n')}
Her aşamanın durumu Bekliyor, Devam Ediyor, Tamamlandı veya Sorun Var olabilir.
"İptal" bir aşama değil, adayın durumudur: iptal edilen adaylar aktif sayılara dahil edilmez. Almanya aşamasındaki adaylar başarılı sayılır.

Kurallar:
- Her zaman Türkçe, kısa ve net yanıt ver. Sayıları ve isimleri araçlardan gelen GERÇEK verilere dayandır; tahmin etme, uydurma.
- Soru veri gerektiriyorsa önce uygun aracı çağır. Liste uzunsa ilk 15 kişiyi yaz ve toplamı belirt.
- Veri değiştirme (aşama değiştirme, iş emri oluşturma) yalnızca propose_* araçlarıyla ÖNERİ olarak yapılır; değişikliğin yapıldığını asla söyleme, "onayınıza sunuldu" de.
- Öneri ve analizlerde somut ol: hangi aday, hangi aşama, kaç gün, hangi personel.
- Biçim: kısa paragraflar, gerekirse "- " ile maddeler, önemli yerleri **kalın** yaz. Tablo veya HTML kullanma.`;
    }

    async function askClaude(req, message, history) {
        const key = process.env.ANTHROPIC_API_KEY;
        const actions = [];
        const msgs = [];
        for (const h of (history || []).slice(-8)) if (h && (h.role === 'user' || h.role === 'assistant') && typeof h.text === 'string' && h.text.trim()) msgs.push({ role: h.role, content: h.text.slice(0, 4000) });
        while (msgs.length && msgs[0].role !== 'user') msgs.shift();
        msgs.push({ role: 'user', content: message });
        let text = '';
        for (let round = 0; round < 6; round++) {
            const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 45000);
            let data;
            try {
                const r = await fetch(API_URL(), {
                    method: 'POST', signal: ctrl.signal,
                    headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
                    body: JSON.stringify({ model: MODEL(), max_tokens: 1500, system: systemPrompt(), tools: TOOLS, messages: msgs })
                });
                data = await r.json();
                if (!r.ok) throw new Error((data && data.error && data.error.message) || `HTTP ${r.status}`);
            } finally { clearTimeout(t); }
            const blocks = data.content || [];
            text = blocks.filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
            const uses = blocks.filter(b => b.type === 'tool_use');
            if (data.stop_reason !== 'tool_use' || !uses.length) break;
            msgs.push({ role: 'assistant', content: blocks });
            const results = [];
            for (const u of uses) {
                let out;
                try { out = await runTool(req, u.name, u.input, actions); } catch (e) { out = { error: e.message }; }
                results.push({ type: 'tool_result', tool_use_id: u.id, content: JSON.stringify(out).slice(0, 60000) });
            }
            msgs.push({ role: 'user', content: results });
        }
        return { mode: 'ai', model: MODEL(), text: text || 'Yanıt oluşturulamadı.', tables: [], actions };
    }

    // ------------------------------------------------------------------
    //  Yerel analiz motoru (API anahtarı yoksa veya hata olursa)
    // ------------------------------------------------------------------
    const candRows = (rows) => ({ columns: ['Aday', 'Aşama', 'Durum', 'Aşamada'], rows: rows.map(r => [r.name, r.stage, r.stageStatus || '—', r.days != null ? r.days + ' gün' : '—']), links: rows.map(r => `/admin/candidate/${r._id}#pipeline`) });

    async function localAnswer(req, message) {
        const n = norm(message);
        const out = { mode: 'local', text: '', tables: [], actions: [] };
        const stageKey = detectStage(n);
        const wantsList = /(kim|kimler|hangi|liste|isim|goster)/.test(n);
        const wantsCount = /(kac|sayi|toplam|adet)/.test(n);

        // 1) Veri değiştirme önerisi: "<aday> ... aşamasına geçir/taşı"
        if (/(gecir|tasi|ilerlet|aktar|al\b|ilerle)/.test(n) && !/(gecikme|gecik)/.test(n)) {
            const hits = await findCandidatesInText(message);
            if (hits.length === 1) {
                const c = hits[0];
                let toKey = stageKey;
                if (/sonraki|bir sonraki|ileri/.test(n) || !toKey) { const idx = (P().byName[c.currentStage] || { index: -1 }).index; toKey = STAGE_DEFS[idx + 1] ? STAGE_DEFS[idx + 1].key : null; }
                if (toKey) {
                    const r = await proposeStageChange(req, String(c._id), toKey, 'AI asistanı üzerinden yönetici talebi');
                    if (r.error) { out.text = r.error; return out; }
                    out.actions.push(r);
                    out.text = `**${c.firstName} ${c.lastName}** için aşama değişikliği hazırlandı: ${r.summary.split(': ')[1]}.\nDeğişiklik yapılmadı; uygulamak için aşağıdan **onaylayın**.${r.details.length ? '\n\nUyarılar:\n' + r.details.map(d => '- ' + d).join('\n') : ''}`;
                    return out;
                }
            } else if (hits.length > 1) {
                out.text = `Birden fazla aday eşleşti: ${hits.slice(0, 6).map(h => `${h.firstName} ${h.lastName}`).join(', ')}. Lütfen tam adı yazın.`; return out;
            }
        }

        // 1b) Aktif aday sayısı / genel sayılar
        if (/aktif/.test(n) && /aday/.test(n) && !stageKey) {
            const o = await overview();
            out.text = `Şu anda **${o.active} aktif aday** var (toplam ${o.total} kayıt; ${o.cancelled} iptal, ${o.arrived} Almanya'ya ulaşan${o.review ? `, ${o.review} aşama onayı bekleyen` : ''}).`;
            return out;
        }
        // 1c) Son N günde işlem yapılmayanlar
        const mDays = n.match(/son (\d{1,3}) gun/);
        if (/(islem yapilma|islem gorme|hareketsiz|hareket olmayan|islem olmayan|ilgilenilmeyen|dokunulmayan)/.test(n) || (mDays && /(islem|hareket)/.test(n))) {
            const r = await inactiveCandidates(mDays ? mDays[1] : 15);
            out.text = r.total ? `Son **${r.days} günde** işlem yapılmayan **${r.total} aktif aday** var.` : `Son ${r.days} günde işlem yapılmayan aktif aday yok.`;
            if (r.total) out.tables.push({ title: `Son ${r.days} günde işlem görmeyen adaylar`, columns: ['Aday', 'Aşama', 'Şirket', 'Son işlem'], rows: r.rows.map(x => [x.name, x.stage, x.company, x.days != null ? x.days + ' gün önce' : 'kayıt yok']), links: r.rows.map(x => `/admin/candidate/${x._id}`) });
            return out;
        }
        // 1d) Bu ay Almanya'ya gidenler
        if (/bu ay/.test(n) && /(almanya|gid|ulas|var)/.test(n)) {
            const r = await arrivalsThisMonth();
            out.text = r.total ? `**${r.month}** içinde **${r.total} aday** Almanya'ya gitti.` : `${r.month} içinde Almanya'ya giden aday henüz yok.`;
            if (r.total) out.tables.push({ title: `${r.month} — Almanya'ya gidenler`, columns: ['Aday', 'Şirket', 'Tarih'], rows: r.rows.map(x => [x.name, x.company, x.date ? new Date(x.date).toLocaleDateString('tr-TR') : '—']), links: r.rows.map(x => `/admin/candidate/${x._id}`) });
            return out;
        }
        // 1e) Şirket sıralaması
        if (/sirket/.test(n) && /(en cok|en fazla|hangi|sirala|dagilim)/.test(n)) {
            const o = await overview();
            const rk = o.companyRanking.filter(c => c.active);
            out.text = rk.length ? `En fazla aktif adayı olan şirket: **${rk[0].name}** (${rk[0].active} aktif aday${rk[0].cancelled ? `; ayrıca ${rk[0].cancelled} iptal` : ''}).` : 'Şirketlere atanmış aktif aday yok.';
            if (rk.length) out.tables.push({ title: 'Şirketlere göre aktif aday', columns: ['Şirket', 'Aktif', 'İptal'], rows: rk.map(c => [c.name, c.active, c.cancelled]), links: rk.map(c => c._id ? `/admin/sirketler/${c._id}` : null) });
            return out;
        }
        // 1f) Bugün yapılacaklar
        if (/bugun/.test(n) && /(gorev|yapil|is|randevu|teslim)/.test(n)) {
            const t = await todayTasks();
            out.text = `Bugün teslim: **${t.dueToday.length} görev** · Geciken: **${t.overdue.length} görev** · Bugünkü randevu: **${t.appointments.length}** · Onay bekleyen belge: **${t.pendingDocuments.reduce((a, c) => a + c.count, 0)}**.`;
            const rows = t.dueToday.map(x => ['Bugün', x.title, x.candidate, x.staff]).concat(t.overdue.map(x => ['Gecikmiş', x.title, x.candidate, x.staff]));
            if (rows.length) out.tables.push({ title: 'Bugün yapılması gereken görevler', columns: ['Durum', 'Görev', 'Aday', 'Personel'], rows, links: t.dueToday.concat(t.overdue).map(x => `/admin/is-emirleri/${x._id}`) });
            if (t.appointments.length) out.tables.push({ title: 'Bugünkü randevular', columns: ['Saat', 'Aday', 'Tür', 'Durum'], rows: t.appointments.map(a => [a.time || '—', a.candidate, a.type || 'Randevu', a.status]), links: t.appointments.map(() => null) });
            return out;
        }

        // 2) Personel iş yükü
        if (/personel/.test(n) && /(gorev|yuk|bekleyen|fazla|en cok|performans)/.test(n)) {
            const w = await P().staffWorkload();
            if (!w.length) { out.text = 'Sistemde kayıtlı personel yok.'; return out; }
            const top = w[0];
            out.text = top.open ? `Üzerinde en fazla bekleyen görev olan personel: **${top.name}** (${top.open} açık görev${top.overdue ? `, ${top.overdue} geciken` : ''}).` : 'Hiçbir personelin üzerinde açık görev yok.';
            out.tables.push({ title: 'Personel iş yükü', columns: ['Personel', 'Açık', 'Yeni', 'Geciken'], rows: w.map(x => [x.name + (x.status !== 'active' ? ' (pasif)' : ''), x.open, x.newCount, x.overdue]), links: w.map(x => `/admin/personel/${x._id}`) });
            return out;
        }

        // 3) Uzun süre bekleyenler
        if (/(uzun sure|uzun zaman|uzundur|takil|ayni asamada|bekleme sinir)/.test(n)) {
            const s = await P().staleCandidates();
            out.text = s.length ? `Bekleme sınırını aşan **${s.length} aday** var. En uzun bekleyen: **${s[0].name}** (${s[0].stage}, ${s[0].days} gün).` : 'Bekleme sınırını aşan aday yok.';
            if (s.length) out.tables.push({ title: 'Uzun süredir bekleyen adaylar', columns: ['Aday', 'Aşama', 'Bekleme', 'Sınır'], rows: s.map(x => [x.name, x.stage, x.days + ' gün', x.limit + ' gün']), links: s.map(x => `/admin/candidate/${x._id}#pipeline`) });
            return out;
        }

        // 4) Geciken görevler
        if (/gecik/.test(n)) {
            const o = await P().overdueTasks(50);
            out.text = o.length ? `**${o.length} geciken görev** var.` : 'Geciken görev yok.';
            if (o.length) out.tables.push({ title: 'Geciken görevler', columns: ['Görev', 'Aday', 'Personel', 'Gecikme'], rows: o.map(x => [x.title, x.candidate, x.staff, x.days + ' gün']), links: o.map(x => `/admin/is-emirleri/${x._id}`) });
            return out;
        }

        // 5) Aşama bazlı sorular
        if (stageKey) {
            const def = byKey[stageKey];
            let status = null;
            if (/sorun/.test(n)) status = 'Sorun Var';
            const r = await P().listCandidates({ stageKey, status, limit: 200 });
            const label = stageKey === 'almanya' ? "Almanya'ya ulaşan" : `${def.name} aşamasında`;
            if (wantsCount && !wantsList) out.text = `Şu anda **${label}** ${status ? '(sorunlu) ' : ''}**${r.total} aday** var.`;
            else out.text = r.total ? `**${label}** ${r.total} aday var${r.total > 15 ? ' (tablo tümünü gösterir)' : ''}:` : `${label} aday yok.`;
            if (r.total) out.tables.push({ title: `${def.name} — ${r.total} aday`, ...candRows(r.rows) });
            const long = r.rows.filter(x => x.days != null && x.days >= 14);
            if (long.length && stageKey !== 'almanya') out.text += `\n\nBunlardan **${long.length}** kişi 14 günden uzun süredir bu aşamada.`;
            return out;
        }

        // 6) Genel özet ve öneriler
        if (/(ozet|genel|durum|oneri|analiz|tavsiye|ne yapmali|rapor|dagilim)/.test(n) || wantsCount) {
            const ins = await insights();
            out.text = `Toplam **${ins.total} aktif aday** var (iptaller hariç).\n\n**Öneriler ve dikkat edilmesi gerekenler:**\n${ins.notes.map(x => '- ' + x).join('\n')}`;
            out.tables.push({ title: 'Aşamalara göre dağılım', columns: ['Aşama', 'Aday'], rows: ins.summary.map(s => [s.name, s.count]), links: ins.summary.map(() => null) });
            return out;
        }

        out.text = 'Bu soruyu anlayamadım. Şunları sorabilirsiniz:\n- "Şu anda kaç aktif aday var?"\n- "Ön onay aşamasındaki adaylar kimler?"\n- "Son 15 günde işlem yapılmayan adaylar"\n- "Bu ay Almanya\'ya giden adaylar"\n- "En fazla aday hangi şirkette?"\n- "Bugün yapılması gereken görevler"\n- "Evrak teslimi bekleyen adaylar kimler?"\n- "Tercüme işlemleri devam eden kaç adayımız var?"\n- "Hangi adaylar uzun süredir aynı aşamada bekliyor?"\n- "Hangi personelin üzerinde en fazla bekleyen görev var?"\n- "Genel durum özeti ve öneriler"\n- "Ahmet Yılmaz\'ı sonraki aşamaya geçir" (onayınızla uygulanır)';
        return out;
    }

    // ------------------------------------------------------------------
    //  Rotalar
    // ------------------------------------------------------------------
    app.get('/admin/asistan', adminAuthCheck, (req, res) => {
        res.render('admin_ai', { aiEnabled: !!process.env.ANTHROPIC_API_KEY, model: MODEL(), user: { firstName: 'Admin' } });
    });

    app.post('/admin/asistan/ask', adminAuthCheck, async (req, res) => {
        const message = typeof req.body.message === 'string' ? req.body.message.trim().slice(0, 2000) : '';
        if (!message) return res.status(400).json({ error: 'Mesaj boş.' });
        let history = [];
        try { history = JSON.parse(req.body.history || '[]'); } catch (e) { history = []; }
        try {
            let result;
            if (process.env.ANTHROPIC_API_KEY) {
                try { result = await askClaude(req, message, history); }
                catch (e) {
                    console.error('AI API hatası:', e.message);
                    result = await localAnswer(req, message);
                    result.notice = 'Yapay zekâ servisine ulaşılamadı; yanıt yerel analizle üretildi.';
                }
            } else result = await localAnswer(req, message);
            await S().audit(req, 'ai.question', 'AI', '', message.slice(0, 200));
            req.session.save(() => res.json(result));
        } catch (e) {
            console.error('Asistan hatası:', e);
            res.status(500).json({ error: 'Yanıt oluşturulamadı.' });
        }
    });

    app.post('/admin/asistan/confirm/:id', adminAuthCheck, async (req, res) => {
        const pend = req.session.aiPending && req.session.aiPending[req.params.id];
        if (!pend) return res.status(404).json({ error: 'Öneri bulunamadı veya süresi doldu.' });
        delete req.session.aiPending[req.params.id];
        if (Date.now() - pend.createdAt > 30 * 60 * 1000) return req.session.save(() => res.status(410).json({ error: 'Önerinin süresi doldu (30 dk). Lütfen tekrar sorun.' }));
        const actor = { type: 'admin', id: 'admin', name: 'Yönetici (AI önerisi)' };
        try {
            let msg;
            if (pend.type === 'stage_change') {
                const r = await P().move(pend.candidateId, pend.toKey, { actor, reason: pend.reason, force: true });
                if (!r.ok) throw new Error(r.message || 'Aşama değiştirilemedi.');
                msg = `Uygulandı: ${pend.summary}${r.automation && r.automation.created && r.automation.created.length ? ` · ${r.automation.created.length} otomatik görev oluşturuldu` : ''}`;
            } else if (pend.type === 'work_order') {
                const [c, s] = await Promise.all([Candidate.findById(pend.candidateId), Staff.findById(pend.staffId)]);
                if (!c || !s || s.deletedAt || s.status !== 'active') throw new Error('Aday veya personel artık geçerli değil.');
                const wo = await S().createWorkOrder({ candidate: c, staff: s, actor, title: pend.title, description: pend.description, priority: pend.priority, dueDate: pend.dueDays ? new Date(Date.now() + pend.dueDays * 864e5) : null, stageKey: P().keyOfName(c.currentStage), source: 'ai' });
                msg = `Uygulandı: ${wo.code} oluşturuldu ve ${s.fullName} kişisine atandı.`;
            } else throw new Error('Bilinmeyen işlem.');
            await S().audit(req, 'ai.action_confirmed', 'AI', pend.candidateId, pend.summary);
            req.session.save(() => res.json({ ok: true, message: msg }));
        } catch (e) {
            req.session.save(() => res.status(400).json({ error: e.message }));
        }
    });

    app.post('/admin/asistan/reject/:id', adminAuthCheck, (req, res) => {
        if (req.session.aiPending) delete req.session.aiPending[req.params.id];
        req.session.save(() => res.json({ ok: true }));
    });

    app.locals.aiTools = { localAnswer, insights, TOOLS, runTool };
};

// Birim testleri için yardımcılar
module.exports.detectStage = detectStage;
module.exports.norm = norm;
