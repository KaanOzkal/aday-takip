// =====================================================================
//  ADAY SÜREÇ YÖNETİMİ (9 AŞAMA) · OTOMASYON · SÜREÇ RAPORU
//  app.js içinden staff modülünden SONRA mountProcess(app, deps) ile bağlanır.
// =====================================================================
const mongoose = require('mongoose');
const CandidateStage = require('../models/CandidateStage');
const ProcessEvent = require('../models/ProcessEvent');
const StageConfig = require('../models/StageConfig');
const AutomationLog = require('../models/AutomationLog');
const Staff = require('../models/Staff');
const WorkOrder = require('../models/WorkOrder');
const { STAGE_DEFS, STAGE_KEYS, STAGE_NAMES, STAGE_STATUSES, byKey, byName, keyOfName } = require('./stages');

const isId = (v) => typeof v === 'string' && mongoose.Types.ObjectId.isValid(v);
const str = (v, max = 500) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const DAY = 864e5;
const withParam = (url, k, v) => { const u = new URL(url, 'http://x'); u.searchParams.delete('status'); u.searchParams.delete('error'); u.searchParams.set(k, v); return u.pathname + u.search + u.hash; };
const fullName = (c) => `${c.firstName || ''} ${c.lastName || ''}`.trim();
const norm = (x) => String(x || '').toLocaleLowerCase('tr-TR').replace(/ç/g, 'c').replace(/ğ/g, 'g').replace(/ı/g, 'i').replace(/i̇/g, 'i').replace(/ö/g, 'o').replace(/ş/g, 's').replace(/ü/g, 'u').replace(/['’`.]/g, '').replace(/\s+/g, ' ').trim();
// Eski / yazım farklı aşama adlarını yeni aşamaya eşleştirme tablosu (yalnızca kesin eşleşmeler)
const STAGE_ALIAS = {};
for (const d of STAGE_DEFS) { STAGE_ALIAS[norm(d.name)] = d.name; if (d.legacy) STAGE_ALIAS[norm(d.legacy)] = d.name; }
const ACTIVE = { status: { $ne: 'cancelled' } };

module.exports = function mountProcess(app, deps) {
    const { adminAuthCheck, Candidate } = deps;
    const svc = () => app.locals.services; // staff modülünden: createWorkOrder, notify, audit, actorOf ...
    app.locals.stageDefs = STAGE_DEFS;
    app.locals.stageKeys = STAGE_KEYS;
    app.locals.stageByKey = byKey;
    app.locals.stageStatusTone = (s) => ({ 'Bekliyor': 't-gray', 'Devam Ediyor': 't-info', 'Tamamlandı': 't-ok', 'Sorun Var': 't-bad' })[s] || 't-gray';

    const SYSTEM = { type: 'system', id: 'system', name: 'Sistem' };
    const actorFromReq = (req) => (req ? svc().actorOf(req) : SYSTEM);

    // ------------------------------------------------------------------
    //  Süreç geçmişi (yalnızca ekleme)
    // ------------------------------------------------------------------
    async function event(candidateId, stageKey, type, text, actor, meta) {
        try {
            const a = actor || SYSTEM;
            await ProcessEvent.create({ candidateId, stageKey, type, text: String(text || '').slice(0, 1000), actorType: ['admin', 'staff', 'system', 'ai'].includes(a.type) ? a.type : 'system', actorName: a.name, meta });
            if (type !== 'migrated') await Candidate.updateOne({ _id: candidateId }, { $set: { lastActivityAt: new Date() } });
        } catch (e) { console.error('Süreç olayı kaydedilemedi:', e.message); }
    }

    // ------------------------------------------------------------------
    //  Aşama ayarları
    // ------------------------------------------------------------------
    async function ensureConfigs() {
        for (const def of STAGE_DEFS) {
            const exists = await StageConfig.findOne({ stageKey: def.key }).select('_id').lean();
            if (!exists) {
                await StageConfig.create({
                    stageKey: def.key, automationEnabled: true, staleDays: ({ evrak_teslimi: 7, tercume_islemleri: 10, on_onay: 15, almanya: 60 })[def.key] || 14,
                    templates: def.templates.map(t => ({ ...t, category: def.category, description: '' }))
                });
            }
        }
    }
    async function configMap() {
        const list = await StageConfig.find().populate('defaultStaffId', 'fullName status deletedAt').populate('templates.staffId', 'fullName status deletedAt').lean();
        return Object.fromEntries(list.map(c => [c.stageKey, c]));
    }

    // ------------------------------------------------------------------
    //  Aday aşama kayıtları
    // ------------------------------------------------------------------
    async function ensureStates(candidate, { initial = false } = {}) {
        if (!byName[candidate.currentStage]) return []; // aşaması tanınmayan aday: yönetici onayı bekliyor
        const existing = await CandidateStage.find({ candidateId: candidate._id }).lean();
        if (existing.length === STAGE_DEFS.length) return existing;
        const have = new Set(existing.map(s => s.stageKey));
        const cur = byName[candidate.currentStage] ? byName[candidate.currentStage].index : 0;
        const now = new Date();
        const docs = STAGE_DEFS.filter(d => !have.has(d.key)).map(d => {
            const i = byKey[d.key].index;
            return {
                candidateId: candidate._id, stageKey: d.key, order: i,
                status: i < cur ? 'Tamamlandı' : i === cur ? 'Devam Ediyor' : 'Bekliyor',
                startedAt: i === cur ? (candidate.stageEnteredAt || now) : undefined,
                note: !initial && i < cur ? 'Süreç sistemine geçişten önce tamamlanmış.' : ''
            };
        });
        if (docs.length) {
            try { await CandidateStage.insertMany(docs, { ordered: false }); } catch (e) { if (e.code !== 11000 && !(e.writeErrors || []).every(w => w.code === 11000)) throw e; }
        }
        return CandidateStage.find({ candidateId: candidate._id }).lean();
    }

    // ------------------------------------------------------------------
    //  Otomasyon: aşamaya girişte şablon görevleri oluştur
    // ------------------------------------------------------------------
    async function runAutomation(candidate, stageKey, { trigger = 'stage_change', actor = SYSTEM, force = false } = {}) {
        const def = byKey[stageKey];
        const name = fullName(candidate);
        const log = { candidateId: candidate._id, candidateName: name, stageKey, trigger, actorName: actor.name, created: [], failures: [] };
        try {
            const cfg = await StageConfig.findOne({ stageKey }).lean();
            if (!cfg || !cfg.automationEnabled) { log.status = 'skipped'; log.message = `${def.name} aşaması için otomasyon kapalı.`; return await AutomationLog.create(log); }
            if (candidate.status === 'cancelled') { log.status = 'skipped'; log.message = 'Aday iptal edilmiş; otomasyon çalıştırılmadı.'; return await AutomationLog.create(log); }
            if (candidate.automationPaused && !force) { log.status = 'skipped'; log.message = 'Bu aday için otomasyon durdurulmuş.'; return await AutomationLog.create(log); }
            const templates = (cfg.templates || []).filter(t => t.active);
            if (!templates.length) { log.status = 'skipped'; log.message = 'Aktif görev şablonu yok.'; return await AutomationLog.create(log); }
            let dup = 0;
            for (const t of templates) {
                const automationKey = `${candidate._id}:${stageKey}:${t._id}`;
                if (await WorkOrder.exists({ automationKey })) { dup++; continue; }
                const staffId = t.staffId || cfg.defaultStaffId;
                if (!staffId) { log.failures.push(`"${t.title}": sorumlu personel tanımlı değil.`); continue; }
                const staff = await Staff.findById(staffId);
                if (!staff || staff.deletedAt || staff.status !== 'active') { log.failures.push(`"${t.title}": atanan personel aktif değil.`); continue; }
                try {
                    const wo = await svc().createWorkOrder({
                        candidate, staff, actor: { type: 'system', name: 'Otomasyon' }, category: t.category, title: t.title, description: t.description,
                        priority: t.priority, startDate: new Date(), dueDate: t.dueDays ? new Date(Date.now() + t.dueDays * DAY) : null,
                        stageKey, templateId: t._id, automationKey, source: 'automation', historyNote: `${def.name} aşaması otomasyonu · ${staff.fullName}`
                    });
                    log.created.push({ workOrderId: wo._id, title: wo.title, staffName: staff.fullName });
                } catch (e) {
                    if (e.code === 11000) { dup++; continue; } // eşzamanlı çalışmada mükerrer engellendi
                    log.failures.push(`"${t.title}": ${e.message}`);
                }
            }
            log.status = log.failures.length ? (log.created.length ? 'partial' : 'failed') : (log.created.length ? 'success' : 'skipped');
            log.message = [
                log.created.length ? `${log.created.length} görev oluşturuldu` : '',
                dup ? `${dup} görev zaten mevcut (mükerrer engellendi)` : '',
                log.failures.length ? `${log.failures.length} görev oluşturulamadı` : ''
            ].filter(Boolean).join(' · ') || 'Yapılacak işlem yok.';
            const saved = await AutomationLog.create(log);
            if (log.created.length) {
                const first = await WorkOrder.findById(log.created[0].workOrderId).select('assignedTo').lean();
                if (first) await CandidateStage.updateOne({ candidateId: candidate._id, stageKey, $or: [{ responsible: null }, { responsible: { $exists: false } }] }, { $set: { responsible: first.assignedTo } });
            }
            if (log.created.length) await event(candidate._id, stageKey, 'automation', `${def.name} otomasyonu: ${log.created.map(c => `${c.title} → ${c.staffName}`).join('; ')}`, { type: 'system', name: 'Otomasyon' });
            if (log.failures.length) {
                await event(candidate._id, stageKey, 'automation', `Otomasyon hatası: ${log.failures.join(' ')}`, { type: 'system', name: 'Otomasyon' });
                await svc().notify({ recipientType: 'admin', type: 'automation_failed', title: 'Otomasyon tamamlanamadı', message: `${name} · ${def.name}: ${log.failures[0]}`, workOrder: null });
            }
            return saved;
        } catch (e) {
            console.error('Otomasyon hatası:', e);
            log.status = 'failed'; log.message = 'Beklenmeyen hata'; log.failures.push(e.message);
            return AutomationLog.create(log).catch(() => null);
        }
    }

    // ------------------------------------------------------------------
    //  Aşama geçişi (tek giriş noktası)
    // ------------------------------------------------------------------
    async function move(candidateId, toKey, { actor = SYSTEM, reason = '', force = false, runAuto = true, dryRun = false } = {}) {
        if (!byKey[toKey]) return { ok: false, code: 'invalid_stage', message: 'Geçersiz aşama.' };
        const cand = await Candidate.findById(candidateId);
        if (!cand) return { ok: false, code: 'not_found', message: 'Aday bulunamadı.' };
        if (cand.status === 'cancelled') return { ok: false, code: 'cancelled', message: 'İptal edilmiş adayda aşama değiştirilemez. Önce adayı yeniden aktifleştirin.' };
        if (!byName[cand.currentStage]) {
            if (dryRun) return { ok: true, dryRun: true, warnings: [`Adayın eski aşaması ("${cand.legacyStage || cand.currentStage}") otomatik eşleşmedi; seçtiğiniz aşamaya yerleştirilecek.`], from: cand.legacyStage || cand.currentStage, to: byKey[toKey].name };
            return resolveReview(cand, toKey, { actor, reason });
        }
        const states = await ensureStates(cand);
        const sMap = Object.fromEntries(states.map(s => [s.stageKey, s]));
        const fromKey = keyOfName(cand.currentStage) || STAGE_KEYS[0];
        const fromIdx = byKey[fromKey].index, toIdx = byKey[toKey].index;
        if (fromIdx === toIdx) return { ok: false, code: 'same', message: 'Aday zaten bu aşamada.' };

        const warnings = [];
        if (toIdx > fromIdx) {
            if (sMap[fromKey] && sMap[fromKey].status !== 'Tamamlandı') warnings.push(`"${byKey[fromKey].name}" aşaması henüz tamamlanmadı (durum: ${sMap[fromKey].status}).`);
            if (toIdx > fromIdx + 1) warnings.push(`${toIdx - fromIdx - 1} aşama atlanacak: ${STAGE_DEFS.slice(fromIdx + 1, toIdx).map(d => d.name).join(', ')}.`);
            const openTasks = await WorkOrder.countDocuments({ candidateId: cand._id, stageKey: fromKey, status: { $in: ['Yeni', 'Devam Ediyor', 'Revizyon'] } });
            if (openTasks) warnings.push(`"${byKey[fromKey].name}" aşamasında ${openTasks} açık görev var.`);
        } else {
            warnings.push(`Aday geri bir aşamaya alınacak (${byKey[fromKey].name} → ${byKey[toKey].name}).`);
        }
        if (dryRun) return { ok: true, dryRun: true, warnings, from: byKey[fromKey].name, to: byKey[toKey].name };
        if (warnings.length && !(force && reason)) return { ok: false, code: 'needs_confirm', warnings, message: warnings.join(' ') };

        const now = new Date();
        const skipped = toIdx > fromIdx + 1 || (toIdx > fromIdx && sMap[fromKey] && sMap[fromKey].status !== 'Tamamlandı');
        if (toIdx > fromIdx) {
            for (let i = fromIdx; i < toIdx; i++) {
                const k = STAGE_KEYS[i], st = sMap[k];
                if (st && st.status === 'Tamamlandı' && !st.skipped) continue;
                const isSkip = i > fromIdx || st.status !== 'Tamamlandı';
                await CandidateStage.updateOne({ candidateId: cand._id, stageKey: k }, { $set: { status: 'Tamamlandı', completedAt: now, skipped: isSkip, skipReason: isSkip ? reason : '', skipType: !isSkip ? '' : i === fromIdx ? 'forced' : 'skipped', ...(st && !st.startedAt ? { startedAt: now } : {}) } });
            }
        } else {
            for (let i = toIdx + 1; i <= fromIdx; i++) {
                await CandidateStage.updateOne({ candidateId: cand._id, stageKey: STAGE_KEYS[i] }, { $set: { status: 'Bekliyor', skipped: false, skipReason: '', skipType: '' }, $unset: { completedAt: 1, staleNotifiedAt: 1 } });
            }
        }
        const cfg = await StageConfig.findOne({ stageKey: toKey }).select('defaultStaffId').lean();
        const target = sMap[toKey];
        await CandidateStage.updateOne({ candidateId: cand._id, stageKey: toKey }, {
            $set: { status: 'Devam Ediyor', startedAt: now, skipped: false, skipReason: '', skipType: '', ...(target && !target.responsible && cfg && cfg.defaultStaffId ? { responsible: cfg.defaultStaffId } : {}) },
            $unset: { completedAt: 1, staleNotifiedAt: 1 }
        });
        cand.currentStage = byKey[toKey].name;
        cand.stageEnteredAt = now;
        await cand.save();

        const txt = `${byKey[fromKey].name} → ${byKey[toKey].name}${skipped ? ' (aşama atlandı)' : ''}${reason ? ' · Gerekçe: ' + reason : ''}`;
        await event(cand._id, toKey, 'stage_change', txt, actor, { from: fromKey, to: toKey, skipped, forced: !!warnings.length });
        await svc().audit(null, 'candidate.stage_change', 'Candidate', cand._id, `${fullName(cand)}: ${txt}`, actor);
        await svc().notify({ recipientType: 'admin', type: 'stage_changed', title: 'Aday yeni aşamaya geçti', message: `${fullName(cand)} · ${txt}`, workOrder: null });
        let automation = null;
        if (runAuto && toIdx > fromIdx) automation = await runAutomation(cand, toKey, { trigger: 'stage_change', actor });
        return { ok: true, from: fromKey, to: toKey, skipped, automation };
    }

    // Eski aşaması eşleşmeyen adayı yöneticinin seçtiği aşamaya yerleştir (otomasyon çalıştırılmaz)
    async function resolveReview(cand, toKey, { actor = SYSTEM, reason = '' } = {}) {
        const old = cand.currentStage;
        if (!cand.legacyStage) cand.legacyStage = old;
        cand.currentStage = byKey[toKey].name;
        cand.stageReviewNeeded = false;
        cand.stageEnteredAt = new Date();
        await cand.save();
        await CandidateStage.deleteMany({ candidateId: cand._id });
        await ensureStates(cand);
        const cfg = await StageConfig.findOne({ stageKey: toKey }).select('defaultStaffId').lean();
        if (cfg && cfg.defaultStaffId) await CandidateStage.updateOne({ candidateId: cand._id, stageKey: toKey }, { $set: { responsible: cfg.defaultStaffId } });
        const txt = `Eski aşama "${old}" yönetici onayıyla "${byKey[toKey].name}" aşamasına eşleştirildi${reason ? ' · ' + reason : ''}`;
        await event(cand._id, toKey, 'stage_change', txt, actor, { from: null, to: toKey, legacy: old });
        await svc().audit(null, 'candidate.stage_resolve', 'Candidate', cand._id, `${fullName(cand)}: ${txt}`, actor);
        return { ok: true, from: null, to: toKey, resolved: true };
    }

    // İptal: 9 aşamadan bağımsız durum. Aşama bilgisi korunur; aktif sayımlara dahil edilmez.
    async function cancelCandidate(candidateId, { reason = '', actor = SYSTEM, cancelTasks = true } = {}) {
        const cand = await Candidate.findById(candidateId);
        if (!cand) return { ok: false, message: 'Aday bulunamadı.' };
        if (cand.status === 'cancelled') return { ok: false, message: 'Aday zaten iptal edilmiş.' };
        cand.status = 'cancelled'; cand.cancelledAt = new Date(); cand.cancelReason = String(reason).slice(0, 500); cand.cancelledBy = actor.name;
        await cand.save();
        let cancelledTasks = 0;
        if (cancelTasks) {
            const open = await WorkOrder.find({ candidateId: cand._id, status: { $in: ['Yeni', 'Devam Ediyor', 'Revizyon'] } });
            for (const wo of open) {
                wo.status = 'İptal'; wo.cancelledAt = new Date();
                wo.history.push({ action: 'İptal edildi', byType: actor.type, byName: actor.name, note: 'Aday iptal edildi' + (reason ? ': ' + reason : '') });
                await wo.save(); cancelledTasks++;
                await svc().notify({ recipientType: 'staff', recipientId: wo.assignedTo, type: 'cancelled', title: 'Görev iptal edildi', message: `${wo.code} · ${wo.title} — aday süreci iptal edildi.`, workOrder: wo });
            }
        }
        await event(cand._id, keyOfName(cand.currentStage), 'cancel', `Aday süreci iptal edildi${reason ? ' · Gerekçe: ' + reason : ''}${cancelledTasks ? ` · ${cancelledTasks} açık görev iptal edildi` : ''}`, actor);
        await svc().audit(null, 'candidate.cancel', 'Candidate', cand._id, `${fullName(cand)} iptal edildi${reason ? ': ' + reason : ''}`, actor);
        return { ok: true, cancelledTasks };
    }
    async function reactivateCandidate(candidateId, { reason = '', actor = SYSTEM } = {}) {
        const cand = await Candidate.findById(candidateId);
        if (!cand || cand.status !== 'cancelled') return { ok: false, message: 'Aday iptal durumunda değil.' };
        cand.status = 'active'; cand.cancelledAt = undefined; cand.cancelReason = ''; cand.cancelledBy = '';
        cand.stageEnteredAt = new Date();
        await cand.save();
        await event(cand._id, keyOfName(cand.currentStage), 'reactivate', `Aday yeniden aktifleştirildi · ${cand.currentStage} aşamasından devam ediyor${reason ? ' · ' + reason : ''}`, actor);
        await svc().audit(null, 'candidate.reactivate', 'Candidate', cand._id, `${fullName(cand)} yeniden aktifleştirildi`, actor);
        return { ok: true };
    }

    // Aday oluşturulduğunda: aşama kayıtları + ilk aşama otomasyonu
    async function onCandidateCreated(candidateId, actor) {
        const cand = await Candidate.findById(candidateId);
        if (!cand) return;
        if (!byName[cand.currentStage]) { cand.currentStage = STAGE_NAMES[0]; }
        cand.stageEnteredAt = new Date();
        await cand.save();
        await ensureStates(cand, { initial: true });
        const key = keyOfName(cand.currentStage);
        const cfg = await StageConfig.findOne({ stageKey: key }).select('defaultStaffId').lean();
        if (cfg && cfg.defaultStaffId) await CandidateStage.updateOne({ candidateId: cand._id, stageKey: key }, { $set: { responsible: cfg.defaultStaffId } });
        await event(cand._id, key, 'stage_change', `Aday oluşturuldu · ${cand.currentStage} aşamasından başladı`, actor);
        await runAutomation(cand, key, { trigger: 'candidate_created', actor });
    }

    // İş emri olaylarını aday geçmişine yaz (staff modülünden çağrılır)
    app.locals.processHooks = {
        workOrder(wo, action, actor) {
            const labels = { created: 'Görev oluşturuldu', started: 'Göreve başlandı', completed: 'Görev tamamlandı', cancelled: 'Görev iptal edildi', approved: 'Görev onaylandı' };
            if (!labels[action] || (action === 'created' && wo.source === 'automation')) return;
            event(wo.candidateId, wo.stageKey, action === 'completed' ? 'task_completed' : 'task', `${labels[action]}: ${wo.code} ${wo.title}`, actor && actor.type ? actor : SYSTEM, { workOrderId: wo._id });
        }
    };

    // ------------------------------------------------------------------
    //  Okuma: aday süreç görünümü, panolar, raporlar, AI araçları
    // ------------------------------------------------------------------
    async function candidatePipeline(candidateId) {
        const cand = await Candidate.findById(candidateId).select('firstName lastName currentStage stageEnteredAt automationPaused documents status cancelReason cancelledAt cancelledBy legacyStage stageReviewNeeded').lean();
        if (!cand) return null;
        if (!byName[cand.currentStage]) {
            const events = await ProcessEvent.find({ candidateId }).sort({ createdAt: -1 }).limit(100).lean();
            return { cand, review: true, stages: [], events, curKey: null, staffList: [], logs: [], ordersNoStage: [] };
        }
        const states = await ensureStates(cand);
        const [staffIds, events, orders, cfgs, staffList, logs] = await Promise.all([
            Staff.find({ _id: { $in: states.map(s => s.responsible).filter(Boolean) } }).select('fullName status deletedAt').lean(),
            ProcessEvent.find({ candidateId }).sort({ createdAt: -1 }).limit(300).lean(),
            WorkOrder.find({ candidateId }).select('code title status stageKey assignedTo dueDate attachments source createdAt').populate('assignedTo', 'fullName').lean(),
            configMap(),
            Staff.find({ deletedAt: null, status: 'active' }).sort({ fullName: 1 }).select('fullName title').lean(),
            AutomationLog.find({ candidateId }).sort({ createdAt: -1 }).limit(20).lean()
        ]);
        const staffById = Object.fromEntries(staffIds.map(s => [String(s._id), s]));
        const curKey = keyOfName(cand.currentStage) || STAGE_KEYS[0];
        const stages = STAGE_DEFS.map(def => {
            const st = states.find(s => s.stageKey === def.key) || { status: 'Bekliyor' };
            const cfg = cfgs[def.key] || {};
            const days = st.status === 'Devam Ediyor' || st.status === 'Sorun Var' ? Math.floor((Date.now() - new Date(st.startedAt || Date.now())) / DAY) : null;
            return {
                ...byKey[def.key], state: st, responsible: st.responsible ? staffById[String(st.responsible)] : null,
                orders: orders.filter(o => o.stageKey === def.key), events: events.filter(e => e.stageKey === def.key),
                isCurrent: def.key === curKey, days, stale: def.key === curKey && days !== null && days >= (cfg.staleDays || 14),
                staleDays: cfg.staleDays || 14, automationEnabled: cfg.automationEnabled !== false
            };
        });
        return { cand, stages, events, curKey, staffList, logs, ordersNoStage: orders.filter(o => !o.stageKey) };
    }

    async function staleCandidates() {
        const cfgs = await configMap();
        const cands = await Candidate.find({ ...ACTIVE, currentStage: { $in: STAGE_NAMES.slice(0, -1) } }).select('firstName lastName currentStage stageEnteredAt company').lean();
        const out = [];
        for (const c of cands) {
            const key = keyOfName(c.currentStage); if (!key) continue;
            const since = c.stageEnteredAt; if (!since) continue;
            const days = Math.floor((Date.now() - new Date(since)) / DAY);
            const lim = (cfgs[key] && cfgs[key].staleDays) || 14;
            if (days >= lim) out.push({ _id: c._id, name: fullName(c), stage: c.currentStage, stageKey: key, days, limit: lim, company: c.company });
        }
        return out.sort((a, b) => (b.days / b.limit) - (a.days / a.limit));
    }

    async function stageSummary() {
        const cands = await Candidate.find(ACTIVE).select('currentStage').lean();
        return STAGE_DEFS.map(d => ({ key: d.key, name: d.name, count: cands.filter(c => c.currentStage === d.name).length }));
    }

    async function listCandidates({ stageKey, status, q, limit = 50, includeCancelled = false } = {}) {
        const query = includeCancelled ? {} : { ...ACTIVE };
        if (stageKey && byKey[stageKey]) query.currentStage = byKey[stageKey].name;
        let cands = await Candidate.find(query).select('firstName lastName currentStage stageEnteredAt company job location').sort({ stageEnteredAt: 1 }).lean();
        if (q) { const n = q.toLocaleLowerCase('tr-TR'); cands = cands.filter(c => fullName(c).toLocaleLowerCase('tr-TR').includes(n)); }
        let statesById = {};
        if (cands.length) {
            const sts = await CandidateStage.find({ candidateId: { $in: cands.map(c => c._id) } }).select('candidateId stageKey status').lean();
            for (const s of sts) statesById[String(s.candidateId) + s.stageKey] = s.status;
        }
        let rows = cands.map(c => { const k = keyOfName(c.currentStage); return { _id: c._id, name: fullName(c), stage: c.currentStage, stageStatus: statesById[String(c._id) + k] || '—', days: c.stageEnteredAt ? Math.floor((Date.now() - new Date(c.stageEnteredAt)) / DAY) : null, company: c.company, job: c.job }; });
        if (status) rows = rows.filter(r => r.stageStatus === status);
        return { total: rows.length, rows: rows.slice(0, limit) };
    }

    async function staffWorkload() {
        const [staff, orders] = await Promise.all([
            Staff.find({ deletedAt: null }).select('fullName title status').lean(),
            WorkOrder.find({ status: { $in: ['Yeni', 'Devam Ediyor', 'Revizyon'] } }).select('assignedTo dueDate status').lean()
        ]);
        return staff.map(s => {
            const mine = orders.filter(o => String(o.assignedTo) === String(s._id));
            return { _id: s._id, name: s.fullName, title: s.title, status: s.status, open: mine.length, overdue: mine.filter(o => o.dueDate && new Date(o.dueDate) < new Date()).length, newCount: mine.filter(o => o.status === 'Yeni').length };
        }).sort((a, b) => b.open - a.open);
    }

    async function overdueTasks(limit = 30) {
        const list = await WorkOrder.find({ status: { $in: ['Yeni', 'Devam Ediyor', 'Revizyon'] }, dueDate: { $lt: new Date() } }).select('code title candidateName assignedTo dueDate stageKey candidateId').populate('assignedTo', 'fullName').sort({ dueDate: 1 }).limit(limit).lean();
        return list.map(w => ({ _id: w._id, code: w.code, title: w.title, candidate: w.candidateName, staff: w.assignedTo ? w.assignedTo.fullName : '—', days: Math.ceil((Date.now() - new Date(w.dueDate)) / DAY), stage: w.stageKey && byKey[w.stageKey] ? byKey[w.stageKey].name : '' }));
    }

    async function reportData() {
        const [cands, states, events, staffRows] = await Promise.all([
            Candidate.find(ACTIVE).select('firstName lastName currentStage stageEnteredAt').lean(),
            CandidateStage.find().select('candidateId stageKey status startedAt completedAt skipped').lean(),
            ProcessEvent.find({ type: 'stage_change', createdAt: { $gte: new Date(Date.now() - 30 * DAY) } }).select('createdAt meta').lean(),
            staffWorkload()
        ]);
        const candIds = new Set(cands.map(c => String(c._id)));
        const live = states.filter(s => candIds.has(String(s.candidateId)));
        const reachedIdx = Object.fromEntries(cands.map(c => [String(c._id), byName[c.currentStage] ? byName[c.currentStage].index : 0]));
        const stages = STAGE_DEFS.map((d, i) => {
            const here = cands.filter(c => c.currentStage === d.name);
            const done = live.filter(s => s.stageKey === d.key && s.status === 'Tamamlandı' && !s.skipped && s.startedAt && s.completedAt);
            const durs = done.map(s => (new Date(s.completedAt) - new Date(s.startedAt)) / DAY).filter(x => x >= 0);
            const reached = cands.filter(c => reachedIdx[String(c._id)] >= i).length;
            const reachedNext = i < STAGE_DEFS.length - 1 ? cands.filter(c => reachedIdx[String(c._id)] >= i + 1).length : null;
            return {
                ...byKey[d.key], count: here.length, issues: live.filter(s => s.stageKey === d.key && s.status === 'Sorun Var').length,
                avgDays: durs.length ? durs.reduce((a, b) => a + b, 0) / durs.length : null, samples: durs.length,
                reached, conversion: reachedNext === null || !reached ? null : Math.round(reachedNext / reached * 100)
            };
        });
        const [stale, overdue] = await Promise.all([staleCandidates(), overdueTasks(50)]);
        const moves30 = events.length, forward30 = events.filter(e => e.meta && byKey[e.meta.to] && byKey[e.meta.from] && byKey[e.meta.to].index > byKey[e.meta.from].index).length;
        return { stages, total: cands.length, arrived: stages[stages.length - 1].count, stale, overdue, staffRows, moves30, forward30 };
    }

    async function dashboardInfo() {
        const stale = await staleCandidates();
        const failed = await AutomationLog.countDocuments({ status: { $in: ['failed', 'partial'] }, resolvedAt: null, createdAt: { $gte: new Date(Date.now() - 14 * DAY) } });
        return { stale, failedAutomations: failed };
    }

    app.locals.processService = { cancelCandidate, reactivateCandidate, resolveReview, norm, STAGE_ALIAS, move, runAutomation, ensureStates, onCandidateCreated, candidatePipeline, staleCandidates, stageSummary, listCandidates, staffWorkload, overdueTasks, reportData, dashboardInfo, event, STAGE_DEFS, byKey, byName, keyOfName };

    // ==================================================================
    //  ADMIN ROTALARI
    // ==================================================================
    // Aşama değiştir (uyarı → gerekçe ile onay)
    app.post('/admin/candidate/:id/stage-move', adminAuthCheck, async (req, res) => {
        const back = `/admin/candidate/${req.params.id}#pipeline`;
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const reason = str(req.body.reason, 500);
        const r = await move(req.params.id, req.body.toKey, { actor: actorFromReq(req), reason, force: req.body.force === '1' });
        if (r.ok) return res.redirect(withParam(back, 'status', r.automation && r.automation.status === 'success' ? 'stage_moved_auto' : r.automation && ['failed', 'partial'].includes(r.automation.status) ? 'stage_moved_autofail' : 'stage_moved'));
        if (r.code === 'needs_confirm') return res.redirect(withParam(back, 'error', req.body.force === '1' ? 'reason_required' : 'needs_confirm'));
        res.redirect(withParam(back, 'error', r.code === 'same' ? 'same_stage' : r.code === 'cancelled' ? 'candidate_cancelled_locked' : 'invalid_action'));
    });

    // Aşama uyarılarını önceden getir (modal için)
    app.get('/admin/candidate/:id/stage-check', adminAuthCheck, async (req, res) => {
        if (!isId(req.params.id) || !byKey[req.query.to]) return res.status(400).json({ error: 'bad_request' });
        const r = await move(req.params.id, req.query.to, { dryRun: true }).catch(() => null);
        res.json(r || { ok: false });
    });

    // Tek bir aşamanın durum/sorumlu/not bilgisini güncelle
    app.post('/admin/candidate/:id/stage/:key', adminAuthCheck, async (req, res) => {
        const back = `/admin/candidate/${req.params.id}#pipeline`;
        if (!isId(req.params.id) || !byKey[req.params.key]) return res.redirect(withParam(back, 'error', 'invalid_action'));
        const cand = await Candidate.findById(req.params.id);
        if (!cand) return res.redirect('/admin?error=not_found');
        await ensureStates(cand);
        const st = await CandidateStage.findOne({ candidateId: cand._id, stageKey: req.params.key });
        const actor = actorFromReq(req);
        const changes = [];
        const status = STAGE_STATUSES.includes(req.body.status) ? req.body.status : st.status;
        if (status !== st.status) {
            changes.push(`durum: ${st.status} → ${status}`);
            st.status = status;
            if (status === 'Tamamlandı') st.completedAt = new Date(); else st.completedAt = undefined;
            if ((status === 'Devam Ediyor' || status === 'Sorun Var') && !st.startedAt) st.startedAt = new Date();
            if (status !== 'Tamamlandı') { st.skipped = false; st.skipType = ''; }
        }
        if (req.body.responsible !== undefined) {
            const rid = isId(req.body.responsible) ? req.body.responsible : null;
            if (String(rid || '') !== String(st.responsible || '')) {
                const s = rid ? await Staff.findById(rid).select('fullName') : null;
                st.responsible = rid || undefined; changes.push(`sorumlu: ${s ? s.fullName : 'kaldırıldı'}`);
            }
        }
        const note = str(req.body.note, 2000); if (req.body.note !== undefined && note !== (st.note || '')) { st.note = note; changes.push('açıklama güncellendi'); }
        const issue = str(req.body.issueNote, 1000); if (req.body.issueNote !== undefined && issue !== (st.issueNote || '')) { st.issueNote = issue; if (issue) changes.push(`sorun: ${issue}`); }
        if (!changes.length) return res.redirect(withParam(back, 'status', 'no_change'));
        await st.save();
        await event(cand._id, st.stageKey, 'stage_status', `${byKey[st.stageKey].name}: ${changes.join(' · ')}`, actor);
        await svc().audit(req, 'candidate.stage_update', 'Candidate', cand._id, `${fullName(cand)} · ${byKey[st.stageKey].name}: ${changes.join(', ')}`);
        if (status === 'Sorun Var') await svc().notify({ recipientType: 'admin', type: 'stale', title: 'Aşamada sorun bildirildi', message: `${fullName(cand)} · ${byKey[st.stageKey].name}${issue ? ': ' + issue : ''}`, workOrder: null });
        res.redirect(withParam(back, 'status', 'stage_updated'));
    });

    // Aday bazında otomasyon: durdur / devam / şimdi çalıştır
    app.post('/admin/candidate/:id/automation', adminAuthCheck, async (req, res) => {
        const back = `/admin/candidate/${req.params.id}#pipeline`;
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const cand = await Candidate.findById(req.params.id);
        if (!cand) return res.redirect('/admin?error=not_found');
        const actor = actorFromReq(req);
        if (req.body.action === 'pause' || req.body.action === 'resume') {
            cand.automationPaused = req.body.action === 'pause';
            await cand.save();
            await event(cand._id, keyOfName(cand.currentStage), cand.automationPaused ? 'pause' : 'resume', cand.automationPaused ? 'Bu aday için otomasyon durduruldu.' : 'Bu aday için otomasyon yeniden başlatıldı.', actor);
            await svc().audit(req, cand.automationPaused ? 'automation.pause' : 'automation.resume', 'Candidate', cand._id, fullName(cand));
            return res.redirect(withParam(back, 'status', cand.automationPaused ? 'auto_paused' : 'auto_resumed'));
        }
        if (req.body.action === 'run') {
            const key = keyOfName(cand.currentStage) || STAGE_KEYS[0];
            const log = await runAutomation(cand, key, { trigger: 'manual', actor, force: true });
            await svc().audit(req, 'automation.run', 'Candidate', cand._id, `${fullName(cand)} · ${byKey[key].name}: ${log ? log.message : ''}`);
            return res.redirect(withParam(back, 'status', log && log.status === 'success' ? 'auto_ran' : log && log.status === 'skipped' ? 'auto_nothing' : 'auto_failed'));
        }
        res.redirect(withParam(back, 'error', 'invalid_action'));
    });

    // ---------------- Otomasyon yönetimi ----------------
    app.get('/admin/otomasyon', adminAuthCheck, async (req, res) => {
        const tab = ['rules', 'logs', 'paused'].includes(req.query.tab) ? req.query.tab : 'rules';
        const logFilter = ['failed', 'success', 'skipped'].includes(req.query.log) ? req.query.log : '';
        const q = {}; if (logFilter === 'failed') q.status = { $in: ['failed', 'partial'] }; else if (logFilter) q.status = logFilter;
        const [cfgs, staffList, logs, paused, failedOpen] = await Promise.all([
            configMap(),
            Staff.find({ deletedAt: null, status: 'active' }).sort({ fullName: 1 }).select('fullName title').lean(),
            AutomationLog.find(q).sort({ createdAt: -1 }).limit(200).lean(),
            Candidate.find({ automationPaused: true }).select('firstName lastName currentStage').lean(),
            AutomationLog.countDocuments({ status: { $in: ['failed', 'partial'] }, resolvedAt: null })
        ]);
        res.render('admin_automation', { cfgs, staffList, logs, paused, tab, logFilter, failedOpen, CATEGORIES: WorkOrder.CATEGORIES, PRIORITIES: WorkOrder.PRIORITIES, user: { firstName: 'Admin' } });
    });

    app.post('/admin/otomasyon/:key/settings', adminAuthCheck, async (req, res) => {
        const key = req.params.key; const back = `/admin/otomasyon#stage-${key}`;
        if (!byKey[key]) return res.redirect(withParam('/admin/otomasyon', 'error', 'invalid_action'));
        const cfg = await StageConfig.findOne({ stageKey: key });
        const before = { e: cfg.automationEnabled, s: String(cfg.defaultStaffId || ''), d: cfg.staleDays };
        cfg.automationEnabled = req.body.automationEnabled === 'on';
        if (isId(req.body.defaultStaffId)) {
            const s = await Staff.findById(req.body.defaultStaffId);
            if (!s || s.deletedAt || s.status !== 'active') return res.redirect(withParam(back, 'error', 'staff_inactive'));
            cfg.defaultStaffId = s._id;
        } else cfg.defaultStaffId = undefined;
        const sd = parseInt(req.body.staleDays, 10); if (sd >= 1 && sd <= 365) cfg.staleDays = sd;
        await cfg.save();
        await svc().audit(req, 'automation.settings', 'StageConfig', cfg._id, `${byKey[key].name}: otomasyon ${cfg.automationEnabled ? 'açık' : 'kapalı'}, varsayılan sorumlu ${cfg.defaultStaffId ? 'atandı' : 'yok'}, bekleme sınırı ${cfg.staleDays} gün (önce: ${before.e ? 'açık' : 'kapalı'}, ${before.d} gün)`);
        res.redirect(withParam(back, 'status', 'auto_saved'));
    });

    function readTemplate(b) {
        const t = { title: str(b.title, 160), description: str(b.description, 2000), category: WorkOrder.CATEGORIES.includes(b.category) ? b.category : 'Diğer', priority: WorkOrder.PRIORITIES.includes(b.priority) ? b.priority : 'Normal', dueDays: Math.max(0, Math.min(365, parseInt(b.dueDays, 10) || 0)), active: b.active === 'on', staffId: isId(b.staffId) ? b.staffId : undefined };
        return t.title ? t : null;
    }
    app.post('/admin/otomasyon/:key/template', adminAuthCheck, async (req, res) => {
        const key = req.params.key; const back = `/admin/otomasyon#stage-${key}`;
        if (!byKey[key]) return res.redirect('/admin/otomasyon?error=invalid_action');
        const t = readTemplate({ ...req.body, active: 'on' }); if (!t) return res.redirect(withParam(back, 'error', 'missing_fields'));
        await StageConfig.updateOne({ stageKey: key }, { $push: { templates: t } });
        await svc().audit(req, 'automation.template_add', 'StageConfig', key, `${byKey[key].name}: "${t.title}" şablonu eklendi`);
        res.redirect(withParam(back, 'status', 'tpl_added'));
    });
    app.post('/admin/otomasyon/:key/template/:tid', adminAuthCheck, async (req, res) => {
        const key = req.params.key; const back = `/admin/otomasyon#stage-${key}`;
        if (!byKey[key] || !isId(req.params.tid)) return res.redirect('/admin/otomasyon?error=invalid_action');
        const cfg = await StageConfig.findOne({ stageKey: key });
        const tpl = cfg && cfg.templates.id(req.params.tid);
        if (!tpl) return res.redirect(withParam(back, 'error', 'not_found'));
        if (req.body._action === 'delete') {
            const title = tpl.title; tpl.deleteOne(); await cfg.save();
            await svc().audit(req, 'automation.template_delete', 'StageConfig', key, `${byKey[key].name}: "${title}" şablonu silindi`);
            return res.redirect(withParam(back, 'status', 'tpl_deleted'));
        }
        const t = readTemplate(req.body); if (!t) return res.redirect(withParam(back, 'error', 'missing_fields'));
        Object.assign(tpl, t); if (!t.staffId) tpl.staffId = undefined;
        await cfg.save();
        await svc().audit(req, 'automation.template_update', 'StageConfig', key, `${byKey[key].name}: "${t.title}" şablonu güncellendi`);
        res.redirect(withParam(back, 'status', 'tpl_saved'));
    });

    app.post('/admin/otomasyon/log/:id/retry', adminAuthCheck, async (req, res) => {
        if (!isId(req.params.id)) return res.redirect('/admin/otomasyon?tab=logs&error=not_found');
        const log = await AutomationLog.findById(req.params.id);
        const cand = log && await Candidate.findById(log.candidateId);
        if (!cand) return res.redirect('/admin/otomasyon?tab=logs&error=not_found');
        const r = await runAutomation(cand, log.stageKey, { trigger: 'retry', actor: actorFromReq(req), force: true });
        if (r && ['success', 'skipped'].includes(r.status)) { log.resolvedAt = new Date(); await log.save(); }
        await svc().audit(req, 'automation.retry', 'Candidate', cand._id, `${fullName(cand)} · ${byKey[log.stageKey].name}: ${r ? r.message : ''}`);
        res.redirect(`/admin/otomasyon?tab=logs&status=${r && r.status === 'success' ? 'auto_ran' : r && r.status === 'skipped' ? 'auto_nothing' : 'auto_failed'}`);
    });
    app.post('/admin/otomasyon/log/:id/resolve', adminAuthCheck, async (req, res) => {
        if (isId(req.params.id)) await AutomationLog.updateOne({ _id: req.params.id }, { $set: { resolvedAt: new Date() } });
        res.redirect('/admin/otomasyon?tab=logs&log=failed&status=log_resolved');
    });

    // ---------------- Süreç raporu ----------------
    app.get('/admin/surec-raporu', adminAuthCheck, async (req, res) => {
        const data = await reportData();
        res.render('admin_process_report', { ...data, user: { firstName: 'Admin' } });
    });

    // ---------------- Aday iptal / yeniden aktifleştirme ----------------
    app.post('/admin/candidate/:id/cancel', adminAuthCheck, async (req, res) => {
        const back = `/admin/candidate/${req.params.id}#pipeline`;
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const reason = str(req.body.reason, 500);
        if (reason.length < 3) return res.redirect(withParam(back, 'error', 'cancel_reason_required'));
        const r = await cancelCandidate(req.params.id, { reason, actor: actorFromReq(req), cancelTasks: req.body.cancelTasks === 'on' });
        res.redirect(withParam(back, r.ok ? 'status' : 'error', r.ok ? 'candidate_cancelled' : 'invalid_action'));
    });
    app.post('/admin/candidate/:id/reactivate', adminAuthCheck, async (req, res) => {
        const back = `/admin/candidate/${req.params.id}#pipeline`;
        if (!isId(req.params.id)) return res.redirect('/admin?error=not_found');
        const r = await reactivateCandidate(req.params.id, { reason: str(req.body.reason, 300), actor: actorFromReq(req) });
        res.redirect(withParam(back, r.ok ? 'status' : 'error', r.ok ? 'candidate_reactivated' : 'invalid_action'));
    });

    // ---------------- Veri kontrolü ve geçiş onayları ----------------
    const CANCEL_LIKE = /(iptal|vazgec|cancel|ayrildi|pasif aday)/;
    async function dataChecks() {
        const [review, companies, cands, orphanOpen, autoDup, staffOpen] = await Promise.all([
            Candidate.find({ stageReviewNeeded: true }).select('firstName lastName currentStage legacyStage company').lean(),
            mongoose.model('Company').find().lean(),
            Candidate.find().select('firstName lastName passportNo email phone phoneNumber company status currentStage').lean(),
            WorkOrder.aggregate([{ $match: { status: { $in: ['Yeni', 'Devam Ediyor', 'Revizyon'] } } }, { $lookup: { from: 'candidates', localField: 'candidateId', foreignField: '_id', as: 'c' } }, { $match: { c: { $size: 0 } } }, { $project: { code: 1, title: 1, candidateName: 1 } }]).catch(() => []),
            WorkOrder.aggregate([{ $match: { automationKey: { $type: 'string' } } }, { $group: { _id: '$automationKey', n: { $sum: 1 } } }, { $match: { n: { $gt: 1 } } }]).catch(() => []),
            WorkOrder.find({ status: { $in: ['Yeni', 'Devam Ediyor', 'Revizyon'] } }).select('assignedTo').populate('assignedTo', 'fullName status deletedAt').lean()
        ]);
        const byLegacy = {};
        review.forEach(c => { const k = c.legacyStage || c.currentStage || '(boş)'; (byLegacy[k] = byLegacy[k] || []).push(c); });
        const cancelCompanies = companies.filter(co => CANCEL_LIKE.test(norm(co.name))).map(co => ({ ...co, count: cands.filter(c => c.company === co.name).length, activeCount: cands.filter(c => c.company === co.name && c.status !== 'cancelled').length }));
        const pass = {}; cands.forEach(c => { const p = String(c.passportNo || '').trim().toUpperCase(); if (p) (pass[p] = pass[p] || []).push(c); });
        const dupPassports = Object.entries(pass).filter(([, l]) => l.length > 1).map(([p, l]) => ({ passport: p, list: l }));
        const unknownCompany = cands.filter(c => c.company && c.company !== 'Atanmadı' && !companies.some(co => co.name === c.company));
        const inactiveStaffOpen = {}; staffOpen.forEach(w => { if (w.assignedTo && (w.assignedTo.deletedAt || w.assignedTo.status !== 'active')) inactiveStaffOpen[w.assignedTo.fullName] = (inactiveStaffOpen[w.assignedTo.fullName] || 0) + 1; });
        const withStates = new Set((await CandidateStage.distinct('candidateId')).map(String));
        const missingStates = cands.filter(c => byName[c.currentStage] && !withStates.has(String(c._id))).length;
        return {
            byLegacy, reviewCount: review.length, cancelCompanies, dupPassports, unknownCompany, orphanOpen, autoDup, inactiveStaffOpen, missingStates,
            noContact: cands.filter(c => c.status !== 'cancelled' && !c.email && !(c.phone || c.phoneNumber)).length,
            totals: { all: cands.length, active: cands.filter(c => c.status !== 'cancelled').length, cancelled: cands.filter(c => c.status === 'cancelled').length }
        };
    }
    app.locals.dataChecks = dataChecks;

    app.get('/admin/veri-kontrol', adminAuthCheck, async (req, res) => {
        res.render('admin_data_checks', { d: await dataChecks(), stageDefs: STAGE_DEFS, user: { firstName: 'Admin' } });
    });
    app.post('/admin/veri-kontrol/legacy', adminAuthCheck, async (req, res) => {
        const legacy = typeof req.body.legacy === 'string' ? req.body.legacy : null;
        const ids = (Array.isArray(req.body.ids) ? req.body.ids : String(req.body.ids || '').split(',')).filter(isId);
        const target = req.body.target;
        if (!ids.length || !(byKey[target] || target === 'cancel')) return res.redirect('/admin/veri-kontrol?error=invalid_action');
        const actor = actorFromReq(req);
        let n = 0;
        for (const id of ids) {
            const c = await Candidate.findById(id);
            if (!c || !c.stageReviewNeeded) continue;
            if (target === 'cancel') {
                // Aşama bilinmediği için ilk aşamaya alınır ama aday İPTAL durumunda tutulur (aktif sayımlara girmez)
                await resolveReview(c, STAGE_KEYS[0], { actor, reason: `Eski aşama "${legacy || c.legacyStage}" iptal olarak değerlendirildi` });
                await cancelCandidate(id, { reason: `Geçişte iptal olarak işaretlendi (eski aşama: ${legacy || c.legacyStage})`, actor, cancelTasks: true });
            } else await resolveReview(c, target, { actor, reason: 'Veri kontrolü ekranından toplu eşleştirme' });
            n++;
        }
        res.redirect(`/admin/veri-kontrol?status=legacy_resolved&n=${n}`);
    });
    app.post('/admin/veri-kontrol/company-cancel', adminAuthCheck, async (req, res) => {
        if (!isId(req.body.companyId)) return res.redirect('/admin/veri-kontrol?error=invalid_action');
        const Company = mongoose.model('Company');
        const co = await Company.findById(req.body.companyId);
        if (!co) return res.redirect('/admin/veri-kontrol?error=not_found');
        const actor = actorFromReq(req);
        const list = await Candidate.find({ company: co.name });
        let n = 0;
        for (const c of list) {
            if (c.status !== 'cancelled') { await cancelCandidate(c._id, { reason: `"${co.name}" grubundan iptal durumuna taşındı`, actor, cancelTasks: true }); n++; }
            await Candidate.updateOne({ _id: c._id }, { $set: { company: 'Atanmadı' } });
        }
        if (req.body.deleteCompany === 'on') await Company.deleteOne({ _id: co._id });
        await svc().audit(req, 'data.company_to_cancel', 'Company', co._id, `"${co.name}" grubundaki ${list.length} adaydan ${n} tanesi iptal durumuna alındı${req.body.deleteCompany === 'on' ? ', grup silindi' : ''}`);
        res.redirect(`/admin/veri-kontrol?status=company_converted&n=${n}`);
    });
    app.post('/admin/veri-kontrol/orphan-tasks', adminAuthCheck, async (req, res) => {
        const d = await dataChecks();
        for (const w of d.orphanOpen) {
            const wo = await WorkOrder.findById(w._id); if (!wo) continue;
            wo.status = 'İptal'; wo.cancelledAt = new Date(); wo.history.push({ action: 'İptal edildi', byType: 'admin', byName: 'Yönetici', note: 'Aday kaydı silinmiş (veri kontrolü)' });
            await wo.save();
        }
        await svc().audit(req, 'data.orphan_tasks', 'WorkOrder', '', `${d.orphanOpen.length} sahipsiz görev iptal edildi`);
        res.redirect('/admin/veri-kontrol?status=orphans_cleaned');
    });

    // ==================================================================
    //  MIGRATION + ZAMANLAYICI
    // ==================================================================
    async function migrate() {
        try {
            // 0) Yeni alanlar için varsayılanlar (mevcut veriye dokunmadan)
            await Candidate.updateMany({ status: { $exists: false } }, { $set: { status: 'active' } });
            // 1) Eski aşama adlarını kesin eşleşmelerle yeni 9 aşamaya taşı; eşleşmeyenleri ASLA otomatik taşıma
            let renamed = 0, review = 0;
            const odd = await Candidate.find({ $or: [{ currentStage: { $nin: STAGE_NAMES } }, { currentStage: null }] }).select('currentStage legacyStage stageReviewNeeded').lean();
            for (const c of odd) {
                const target = STAGE_ALIAS[norm(c.currentStage)];
                if (target) {
                    await Candidate.updateOne({ _id: c._id }, { $set: { currentStage: target, legacyStage: c.legacyStage || c.currentStage, stageReviewNeeded: false } });
                    renamed++;
                } else if (!c.stageReviewNeeded) {
                    await Candidate.updateOne({ _id: c._id }, { $set: { stageReviewNeeded: true, legacyStage: c.legacyStage || c.currentStage || '(boş)' } });
                    review++;
                }
            }
            // 2) Aşama ayarları
            await ensureConfigs();
            // 3) Aşama kaydı olmayan (ve aşaması tanınan) adaylar için süreç kayıtları — otomasyon ÇALIŞTIRILMAZ
            const withStates = new Set((await CandidateStage.distinct('candidateId')).map(String));
            const cands = await Candidate.find({ currentStage: { $in: STAGE_NAMES } }).select('firstName lastName currentStage stageEnteredAt applicationDate lastActivityAt').lean();
            let created = 0;
            for (const c of cands) {
                if (!c.lastActivityAt) await Candidate.updateOne({ _id: c._id }, { $set: { lastActivityAt: c.stageEnteredAt || c.applicationDate || new Date() } });
                if (withStates.has(String(c._id))) continue;
                if (!c.stageEnteredAt) { await Candidate.updateOne({ _id: c._id }, { $set: { stageEnteredAt: new Date() } }); c.stageEnteredAt = new Date(); }
                await ensureStates(c);
                await event(c._id, keyOfName(c.currentStage), 'migrated', `9 aşamalı süreç sistemine aktarıldı · mevcut aşama: ${c.currentStage}`, SYSTEM);
                created++;
            }
            if (renamed || created || review) console.log(`✅ Süreç geçişi: ${renamed} aday eşleştirildi, ${created} aday için süreç kaydı oluşturuldu, ${review} aday yönetici onayına sunuldu`);
            await Promise.all([CandidateStage.syncIndexes(), StageConfig.syncIndexes(), AutomationLog.syncIndexes(), ProcessEvent.syncIndexes(), WorkOrder.syncIndexes()]).catch(e => console.error('Süreç indeks hatası:', e.message));
        } catch (e) { console.error('Süreç geçişi hatası:', e); }
    }
    app.locals.processMigrate = migrate;
    if (mongoose.connection.readyState === 1) migrate(); else mongoose.connection.once('open', migrate);

    // Uzun süre aynı aşamada bekleyen adaylar için yöneticiye tek seferlik uyarı
    async function staleScan() {
        try {
            const stale = await staleCandidates();
            for (const s of stale) {
                const st = await CandidateStage.findOne({ candidateId: s._id, stageKey: s.stageKey });
                if (!st || st.staleNotifiedAt) continue;
                st.staleNotifiedAt = new Date(); await st.save();
                await svc().notify({ recipientType: 'admin', type: 'stale', title: 'Aday uzun süredir aynı aşamada', message: `${s.name} · ${s.stage} aşamasında ${s.days} gündür bekliyor (sınır ${s.limit} gün)`, workOrder: null });
                if (st.responsible) {
                    const resp = await Staff.findById(st.responsible).select('status deletedAt').lean();
                    if (resp && !resp.deletedAt && resp.status === 'active') {
                        const wo = await WorkOrder.findOne({ candidateId: s._id, stageKey: s.stageKey, assignedTo: st.responsible, status: { $in: ['Yeni', 'Devam Ediyor', 'Revizyon'] } }).select('_id code title candidateName').lean();
                        await svc().notify({ recipientType: 'staff', recipientId: st.responsible, type: 'stale', title: 'Aday aşamada gecikti', message: `${s.name} · ${s.stage} aşamasında ${s.days} gündür bekliyor (sınır ${s.limit} gün). Lütfen işlemleri hızlandırın.`, workOrder: wo });
                    }
                }
            }
        } catch (e) { console.error('Bekleme taraması hatası:', e.message); }
    }
    setTimeout(staleScan, 30 * 1000).unref();
    setInterval(staleScan, 30 * 60 * 1000).unref();
};

// Birim testleri için yardımcılar
module.exports.norm = norm;
module.exports.STAGE_ALIAS = STAGE_ALIAS;
