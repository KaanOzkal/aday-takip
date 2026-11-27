// BERLINER resmi 9 aşamalı aday süreci.
// key: sistem anahtarı (değişmez) · name: ekranda görünen ad (Candidate.currentStage bu değeri tutar)
// legacy: eski sürümdeki aşama adı (otomatik geçiş için)
const STAGE_DEFS = [
    {
        key: 'hizmet_sozlesmesi', name: 'Hizmet Sözleşmesi', legacy: 'Başvuru Alındı', icon: 'fa-file-signature', time: '1-3 Gün', category: 'Sözleşme',
        desc: 'Hizmet sözleşmeniz hazırlanıyor ve imzanıza sunuluyor.',
        templates: [
            { title: 'Hizmet sözleşmesinin hazırlanması', dueDays: 1, priority: 'Yüksek' },
            { title: 'Adaya sözleşmenin gönderilmesi', dueDays: 2, priority: 'Normal' },
            { title: 'İmzalı sözleşmenin kontrol edilmesi', dueDays: 5, priority: 'Normal' }
        ]
    },
    {
        key: 'evrak_teslimi', name: 'Evrak Teslimi', legacy: 'Evrak Kontrolü', icon: 'fa-folder-open', time: '3-7 Gün', category: 'Evrak Takibi',
        desc: 'Gerekli belgelerinizi teslim ediyorsunuz; belgeleriniz kontrol ediliyor.',
        templates: [
            { title: 'Gerekli belgelerin adaydan istenmesi', dueDays: 1, priority: 'Yüksek' },
            { title: 'Gelen belgelerin kontrol edilmesi', dueDays: 5, priority: 'Normal' },
            { title: 'Eksik belgelerin tespit edilmesi', dueDays: 6, priority: 'Normal' }
        ]
    },
    {
        key: 'tercume_islemleri', name: 'Tercüme İşlemleri', legacy: 'Tercüme Süreci', icon: 'fa-language', time: '3-7 Gün', category: 'Tercüme',
        desc: 'Belgelerinizin yeminli tercümesi yapılıyor.',
        templates: [
            { title: 'Belgelerin tercümeye gönderilmesi', dueDays: 1, priority: 'Yüksek' },
            { title: 'Tercüme durumunun takip edilmesi', dueDays: 5, priority: 'Normal' },
            { title: 'Tercüme edilen belgelerin kontrol edilmesi', dueDays: 7, priority: 'Normal' }
        ]
    },
    {
        key: 'giris_islemleri', name: 'Giriş İşlemleri', legacy: 'İşveren Onayı', icon: 'fa-keyboard', time: '1-2 Hafta', category: 'Başvuru Girişi',
        desc: 'Başvurunuz ilgili sistemlere giriliyor ve kontrol ediliyor.',
        templates: [
            { title: 'Gerekli sistem ve başvuru girişlerinin yapılması', dueDays: 3, priority: 'Yüksek' },
            { title: 'Başvuru bilgilerinin kontrol edilmesi', dueDays: 4, priority: 'Normal' },
            { title: 'İşlem sonucunun kaydedilmesi', dueDays: 10, priority: 'Normal' }
        ]
    },
    {
        key: 'on_onay_sozlesmesi', name: 'Ön Onay Sözleşmesi', legacy: 'Vize Hazırlığı', icon: 'fa-file-contract', time: '1 Hafta', category: 'Sözleşme',
        desc: 'Ön onay sözleşmesi hazırlanıyor ve ilgili tarafa iletiliyor.',
        templates: [
            { title: 'Ön onay sözleşmesinin hazırlanması', dueDays: 2, priority: 'Yüksek' },
            { title: 'Sözleşmenin ilgili tarafa gönderilmesi', dueDays: 3, priority: 'Normal' },
            { title: 'İmzalı belgenin kontrol edilmesi', dueDays: 7, priority: 'Normal' }
        ]
    },
    {
        key: 'on_onay', name: 'Ön Onay', legacy: 'Vize Ön Onay', icon: 'fa-stamp', time: 'Değişken', category: 'Ön Onay',
        desc: 'Alman makamlarından ön onay (Vorabzustimmung) bekleniyor.',
        templates: [
            { title: 'Ön onay başvuru sürecinin takip edilmesi', dueDays: 14, priority: 'Normal' },
            { title: 'Eksik bilgi ve belgelerin kontrol edilmesi', dueDays: 5, priority: 'Yüksek' },
            { title: 'Ön onay sonucunun kaydedilmesi', dueDays: 30, priority: 'Normal' }
        ]
    },
    {
        key: 'vize_randevusu', name: 'Vize Randevusu', legacy: 'Vize Başvurusu', icon: 'fa-passport', time: 'Değişken', category: 'Vize İşlemleri',
        desc: 'Konsolosluk vize randevunuz planlanıyor.',
        templates: [
            { title: 'Randevu sürecinin takibi', dueDays: 7, priority: 'Yüksek' },
            { title: 'Randevu tarihinin sisteme girilmesi', dueDays: 7, priority: 'Normal' },
            { title: 'Adayın bilgilendirilmesi', dueDays: 8, priority: 'Normal' }
        ]
    },
    {
        key: 'seyahat_plani', name: 'Seyahat Planı', legacy: 'Seyahat Planı', icon: 'fa-plane', time: '3-7 Gün', category: 'Seyahat & Konaklama',
        desc: 'Uçuş ve Almanya’ya gidiş organizasyonunuz yapılıyor.',
        templates: [
            { title: 'Uçuş ve seyahat bilgilerinin hazırlanması', dueDays: 3, priority: 'Yüksek' },
            { title: 'Adayın Almanya’ya gidiş organizasyonu', dueDays: 7, priority: 'Normal' },
            { title: 'Gerekli bilgilendirmelerin yapılması', dueDays: 7, priority: 'Normal' }
        ]
    },
    {
        key: 'almanya', name: 'Almanya', legacy: "Almanya'da", icon: 'fa-flag-checkered', time: 'Son adım', category: 'Almanya Entegrasyonu',
        desc: 'Tebrikler! Almanya’daki yeni hayatınız başladı.',
        templates: [
            { title: 'Adayın Almanya’ya ulaştığının doğrulanması', dueDays: 1, priority: 'Yüksek' },
            { title: 'Varış tarihinin kaydedilmesi', dueDays: 1, priority: 'Normal' },
            { title: 'Yerleşim ve iş başlangıç sürecinin takibi', dueDays: 14, priority: 'Normal' },
            { title: 'Aday dosyasının tamamlanması', dueDays: 21, priority: 'Düşük' }
        ]
    }
];

const STAGE_KEYS = STAGE_DEFS.map(s => s.key);
// Varsayılan değerler (yönetici özelleştirmesini geri almak için)
const DEFAULTS = Object.fromEntries(STAGE_DEFS.map(s => [s.key, { name: s.name, desc: s.desc, icon: s.icon, time: s.time }]));
// Aşağıdaki nesneler YERİNDE güncellenir; böylece modülü içe aktaran her yer yeni adları görür.
const STAGE_NAMES = [];
const byKey = {};
const byName = {};
const formerNames = {}; // key -> önceki adlar (eski kayıtları eşleştirmek için)
function rebuild() {
    STAGE_NAMES.length = 0; STAGE_DEFS.forEach(s => STAGE_NAMES.push(s.name));
    for (const k of Object.keys(byKey)) delete byKey[k];
    for (const k of Object.keys(byName)) delete byName[k];
    STAGE_DEFS.forEach((s, i) => { byKey[s.key] = { ...s, index: i }; byName[s.name] = { ...s, index: i }; });
}
rebuild();
const keyOfName = (n) => (byName[n] ? byName[n].key : null);
const finalName = () => STAGE_NAMES[STAGE_NAMES.length - 1];
const nameOf = (key) => (byKey[key] ? byKey[key].name : key);
// StageConfig kayıtlarındaki yönetici özelleştirmelerini uygula (ad, açıklama, ikon, süre)
function applyOverrides(configs) {
    for (const c of configs || []) {
        const d = STAGE_DEFS.find(x => x.key === c.stageKey); if (!d) continue;
        const o = c.display || {};
        const name = (o.name || '').trim() || DEFAULTS[d.key].name;
        if (name !== d.name) { (formerNames[d.key] = formerNames[d.key] || []).push(d.name); }
        d.name = name;
        d.desc = (o.desc || '').trim() || DEFAULTS[d.key].desc;
        d.icon = (o.icon || '').trim() || DEFAULTS[d.key].icon;
        d.time = (o.time || '').trim() || DEFAULTS[d.key].time;
        for (const n of (o.previousNames || [])) { const f = (formerNames[d.key] = formerNames[d.key] || []); if (!f.includes(n)) f.push(n); }
    }
    rebuild();
}
const STAGE_STATUSES = ['Bekliyor', 'Devam Ediyor', 'Tamamlandı', 'Sorun Var'];

module.exports = { STAGE_DEFS, STAGE_KEYS, STAGE_NAMES, STAGE_STATUSES, DEFAULTS, byKey, byName, keyOfName, finalName, nameOf, applyOverrides, formerNames };
