// Hata loglarında erişim belirteçleri/başlıklar görünmesin: Error nesneleri yalnızca stack olarak yazılır,
// nesnelerdeki parola / token / authorization alanları maskelenir.
const SENSITIVE = /(pass(word)?|token|secret|authorization|cookie|api[-_]?key|refresh)/i;
function scrub(v, depth = 0) {
    if (v instanceof Error) return v.stack || v.message;
    if (!v || typeof v !== 'object' || depth > 3) return v;
    if (Array.isArray(v)) return v.map(x => scrub(x, depth + 1));
    const out = {};
    for (const [k, val] of Object.entries(v)) out[k] = SENSITIVE.test(k) ? '[gizlendi]' : scrub(val, depth + 1);
    return out;
}
const orig = console.error.bind(console);
console.error = (...args) => orig(...args.map(a => scrub(a)));
module.exports = { scrub };
