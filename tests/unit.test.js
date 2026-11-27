// Birim testleri:  npm test
const test = require('node:test');
const assert = require('node:assert');
const { STAGE_DEFS } = require('../src/process/stages');
const proc = require('../src/process');
const ai = require('../src/ai');
const { sniff, isAllowedFile, safeName } = require('../src/lib/files');
const { rateLimit, safeEqual, hashPassword, verifyPassword, passwordProblem } = require('../src/lib/security');

test('9 resmi aşama sırayla tanımlı', () => {
    assert.deepStrictEqual(STAGE_DEFS.map(d => d.name), ['Hizmet Sözleşmesi', 'Evrak Teslimi', 'Tercüme İşlemleri', 'Giriş İşlemleri', 'Ön Onay Sözleşmesi', 'Ön Onay', 'Vize Randevusu', 'Seyahat Planı', 'Almanya']);
    assert.ok(!STAGE_DEFS.some(d => /iptal/i.test(d.name)), 'İptal bir aşama olmamalı');
});

test('eski aşama adları yalnızca kesin eşleşmede yeni aşamaya eşlenir', () => {
    const A = proc.STAGE_ALIAS, n = proc.norm;
    assert.strictEqual(A[n('Başvuru Alındı')], 'Hizmet Sözleşmesi');
    assert.strictEqual(A[n('EVRAK KONTROLÜ')], 'Evrak Teslimi');
    assert.strictEqual(A[n("Almanya'da")], 'Almanya');
    assert.strictEqual(A[n('  tercüme   işlemleri ')], 'Tercüme İşlemleri');
    assert.strictEqual(A[n('Bilinmeyen Aşama')], undefined);
    assert.strictEqual(A[n('İptal')], undefined, 'İptal hiçbir aşamaya eşlenmemeli');
});

test('AI aşama algılama', () => {
    const d = (s) => ai.detectStage(ai.norm(s));
    assert.strictEqual(d('Ön onay sözleşmesi bekleyenler'), 'on_onay_sozlesmesi');
    assert.strictEqual(d('Ön onay aşamasındaki adaylar kimler?'), 'on_onay');
    assert.strictEqual(d('Tercüme işlemleri devam eden'), 'tercume_islemleri');
    assert.strictEqual(d('kaç aktif aday var'), null);
});

test('dosya imzası kontrolü (uzantı/MIME sahteciliği reddedilir)', () => {
    const pdf = Buffer.from('%PDF-1.7\n...');
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0, 0, 0]);
    const exe = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00');
    assert.strictEqual(sniff(pdf), 'application/pdf');
    assert.strictEqual(sniff(png), 'image/png');
    const allowed = ['application/pdf', 'image/png', 'image/jpeg'];
    assert.ok(isAllowedFile({ mimetype: 'application/pdf', buffer: pdf }, allowed));
    assert.ok(!isAllowedFile({ mimetype: 'application/pdf', buffer: exe }, allowed), 'PDF gibi görünen exe reddedilmeli');
    assert.ok(!isAllowedFile({ mimetype: 'image/png', buffer: pdf }, allowed), 'MIME ile içerik uyuşmazlığı reddedilmeli');
    assert.ok(!safeName('../../etc/passwd').includes('/'));
});

test('şifre hash ve güç kontrolü', async () => {
    const h = await hashPassword('Guclu1234');
    assert.ok(!h.includes('Guclu1234'));
    assert.ok(await verifyPassword('Guclu1234', h));
    assert.ok(!(await verifyPassword('yanlis123', h)));
    assert.ok(passwordProblem('kisa'));
    assert.ok(!passwordProblem('Guclu1234'));
    assert.ok(safeEqual('abc', 'abc') && !safeEqual('abc', 'abd') && !safeEqual('abc', ''));
});

test('istek sınırlama 429 döndürür', () => {
    const mw = rateLimit({ windowMs: 60000, max: 2, key: () => 'k', message: 'çok' });
    let code = 200; const res = { status(c) { code = c; return this; }, json() { return this; }, send() { return this; }, set() { return this; }, setHeader() {}, type() { return this; } };
    const req = { ip: '1.1.1.1', method: 'POST', headers: {}, accepts: () => 'json', xhr: true, path: '/x', get: () => 'application/json' };
    let passed = 0; const next = () => passed++;
    mw(req, res, next); mw(req, res, next); mw(req, res, next);
    assert.strictEqual(passed, 2); assert.strictEqual(code, 429);
});

test('tekrarlayan görev sonraki çalışma zamanı', () => {
    process.env.TZ = 'Europe/Istanbul';
    const { computeNext } = require('../src/ops');
    const from = new Date(2026, 10, 27, 10, 0); // 27 Kasım 2026 Cuma 10:00
    const d1 = computeNext({ frequency: 'daily', time: '09:00' }, from);
    assert.strictEqual(d1.getDate(), 28); assert.strictEqual(d1.getHours(), 9);
    const d2 = computeNext({ frequency: 'daily', time: '15:30' }, from);
    assert.strictEqual(d2.getDate(), 27); assert.strictEqual(d2.getMinutes(), 30);
    const d3 = computeNext({ frequency: 'weekdays', time: '09:00' }, from);
    assert.strictEqual(d3.getDay(), 1, 'Cuma sonrası hafta içi → Pazartesi');
    const d4 = computeNext({ frequency: 'weekly', weekday: 3, time: '08:00' }, from);
    assert.strictEqual(d4.getDay(), 3);
    const d5 = computeNext({ frequency: 'monthly', monthDay: 1, time: '09:00' }, from);
    assert.strictEqual(d5.getMonth(), 11); assert.strictEqual(d5.getDate(), 1);
});

test('T.C. kimlik doğrulama ve belge kategorisi', () => {
    const { tcValid, categoryOf } = require('../src/dossier');
    assert.ok(tcValid('10000000146'));
    assert.ok(!tcValid('12345678901'));
    assert.ok(!tcValid('01234567890'));
    assert.strictEqual(categoryOf({ name: 'Pasaport' }), 'Pasaport');
    assert.strictEqual(categoryOf({ name: 'Sürücü Belgesi (Ehliyet)' }), 'Ehliyet');
    assert.strictEqual(categoryOf({ name: 'Adli Sicil' }), 'Resmi Kayıtlar');
    assert.strictEqual(categoryOf({ name: 'x', category: 'CV' }), 'CV');
});

test('CV modeli: kural tabanlı Almanca, uydurma yok, kronolojik', () => {
    const { buildCv } = require('../src/cv');
    const c = { firstName: 'Ali', lastName: 'Kaya', job: 'Tır şoförü', phone: '+90 5', dossier: {
        birthDate: new Date('1990-01-05T12:00:00'), birthPlace: 'Konya', maritalStatus: 'Bekar', nationality: 'Türkiye Cumhuriyeti',
        germanLevel: 'B1', otherLanguages: [{ lang: 'Türkçe', level: 'Anadil' }, { lang: 'Klingonca', level: 'A1' }], licenseClasses: ['C', 'CE'],
        work: [{ company: 'A', job: 'Şoför', start: new Date('2015-01-01'), end: new Date('2018-01-01') }, { company: 'B', job: 'Şoför', jobDe: 'Lkw-Fahrer', start: new Date('2018-02-01'), current: true }],
        cv: {} } };
    const de = buildCv(c, 'de');
    assert.strictEqual(de.experience[0].when.endsWith('heute'), true, 'en yeni üstte');
    assert.ok(de.personal.some(([k, v]) => k === 'Familienstand' && v === 'ledig'));
    assert.ok(de.personal.some(([k, v]) => v === 'türkisch'));
    assert.ok(de.languages.some(([n, l]) => n === 'Türkisch' && l === 'Muttersprache'));
    assert.ok(de.untranslated.some(x => /Klingonca/.test(x)), 'bilinmeyen dil adı uyarı verir');
    assert.ok(de.untranslated.some(x => /İş deneyimi/.test(x)), 'Almancası olmayan pozisyon uyarı verir');
    assert.ok(!de.languages.some(([n]) => n === 'Englisch'), 'girilmeyen dil eklenmez');
    assert.ok(de.warnings.includes('Eğitim bilgisi eklenmemiş'));
    const tr = buildCv(c, 'tr');
    assert.strictEqual(tr.l.doc, 'Özgeçmiş');
});

test('requiredDocs: kategori ve durumdan zorunlu belge durumu', () => {
    const { requiredDocs } = require('../src/dossier/c360');
    const r = requiredDocs({ documents: [
        { name: 'Pasaport ön yüz', status: 'Onaylandı' },
        { name: 'Sağlık raporu', status: 'İnceleniyor' },
        { name: 'SGK hizmet dökümü', status: 'Reddedildi' },
        { name: 'x', category: 'CV', status: 'Onaylandı' }
    ] });
    const by = Object.fromEntries(r.map(x => [x.key, x.state]));
    assert.equal(by.passport, 'approved'); assert.equal(by.health, 'pending'); assert.equal(by.work, 'rejected');
    assert.equal(by.cv, 'approved'); assert.equal(by.id, 'missing'); assert.equal(r.filter(x => x.done).length, 3);
});

test('applyOverrides: aşama adı yerinde değişir, varsayılana döner', () => {
    const st = require('../src/process/stages');
    const ref = st.STAGE_NAMES;
    st.applyOverrides([{ stageKey: 'evrak_teslimi', display: { name: 'Evrak Toplama', time: '5-10 Gün' } }]);
    assert.equal(ref[1], 'Evrak Toplama'); assert.equal(st.byKey.evrak_teslimi.name, 'Evrak Toplama');
    assert.equal(st.keyOfName('Evrak Toplama'), 'evrak_teslimi'); assert.equal(st.byName['Evrak Teslimi'], undefined);
    assert.ok(st.formerNames.evrak_teslimi.includes('Evrak Teslimi'));
    st.applyOverrides([{ stageKey: 'evrak_teslimi', display: {} }]);
    assert.equal(ref[1], 'Evrak Teslimi'); assert.equal(st.byKey.evrak_teslimi.time, '3-7 Gün');
});
