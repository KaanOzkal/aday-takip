// Server-Sent Events (SSE) merkezi. Kanal anahtarı: 'staff:<id>' veya 'admin'.
const channels = new Map();

function subscribe(key, req, res) {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.flushHeaders && res.flushHeaders();
    res.write('retry: 10000\n\n');
    if (!channels.has(key)) channels.set(key, new Set());
    channels.get(key).add(res);
    const ping = setInterval(() => res.write(': ping\n\n'), 25000);
    req.on('close', () => { clearInterval(ping); const s = channels.get(key); if (s) { s.delete(res); if (!s.size) channels.delete(key); } });
}

function publish(key, event, data) {
    const s = channels.get(key);
    if (!s) return 0;
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of s) { try { res.write(payload); } catch (e) { /* bağlantı kapanmış */ } }
    return s.size;
}

// Belirli bir kanalı kapat (ör. personel pasife alındığında)
function closeChannel(key) {
    const s = channels.get(key);
    if (!s) return;
    for (const res of s) { try { res.write('event: logout\ndata: {}\n\n'); res.end(); } catch (e) {} }
    channels.delete(key);
}

module.exports = { subscribe, publish, closeChannel };
