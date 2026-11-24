const crypto = require('crypto');

// --- Şifre hashleme (Node yerleşik scrypt; ek bağımlılık gerektirmez) ---
const SCRYPT_N = 16384, KEYLEN = 64;

function hashPassword(password) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(16);
        crypto.scrypt(password, salt, KEYLEN, { N: SCRYPT_N }, (err, key) => {
            if (err) return reject(err);
            resolve(`scrypt$${SCRYPT_N}$${salt.toString('base64')}$${key.toString('base64')}`);
        });
    });
}

function verifyPassword(password, stored) {
    return new Promise((resolve) => {
        try {
            const [algo, n, saltB64, keyB64] = String(stored || '').split('$');
            if (algo !== 'scrypt') return resolve(false);
            const expected = Buffer.from(keyB64, 'base64');
            crypto.scrypt(password, Buffer.from(saltB64, 'base64'), expected.length, { N: Number(n) }, (err, key) => {
                if (err) return resolve(false);
                resolve(key.length === expected.length && crypto.timingSafeEqual(key, expected));
            });
        } catch (e) { resolve(false); }
    });
}

// Şifre kuralı: en az 8 karakter, en az bir harf ve bir rakam
function passwordProblem(pw) {
    if (typeof pw !== 'string' || pw.length < 8) return 'Şifre en az 8 karakter olmalı.';
    if (pw.length > 128) return 'Şifre çok uzun.';
    if (!/[A-Za-zÇĞİÖŞÜçğıöşü]/.test(pw) || !/\d/.test(pw)) return 'Şifre en az bir harf ve bir rakam içermeli.';
    return null;
}

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// --- Basit, bellek içi giriş denemesi sınırlayıcı (IP + kullanıcı adı) ---
const attempts = new Map();
const WINDOW_MS = 15 * 60 * 1000, MAX_ATTEMPTS = 8;

function loginLimiter(key) {
    const now = Date.now();
    const rec = attempts.get(key);
    if (rec && now - rec.first > WINDOW_MS) attempts.delete(key);
    return {
        blocked() { const r = attempts.get(key); return !!(r && r.count >= MAX_ATTEMPTS && now - r.first <= WINDOW_MS); },
        fail() { const r = attempts.get(key) || { count: 0, first: now }; r.count++; attempts.set(key, r); },
        reset() { attempts.delete(key); }
    };
}
setInterval(() => { const now = Date.now(); for (const [k, r] of attempts) if (now - r.first > WINDOW_MS) attempts.delete(k); }, 10 * 60 * 1000).unref();

module.exports = { hashPassword, verifyPassword, passwordProblem, randomToken, sha256, loginLimiter };
