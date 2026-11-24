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
