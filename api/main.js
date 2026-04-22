import { createServer } from 'http';
import { get } from 'https';

const PROTECTED_URL = "https://raw.githubusercontent.com/stokompetgacor23-dotcom/PinatHubSettingsMap/refs/heads/main/main.lua";
const PORT = process.env.PORT || 3000;

// ============ FAKE HEADER DETECTION ============
function isFakeRequest(headers, ip) {
    const ua = headers['user-agent'] || '';
    const origin = headers['origin'] || '';
    const referer = headers['referer'] || '';
    const accept = headers['accept'] || '';
    
    // 1. Empty User-Agent = fake
    if (!ua || ua.length < 5) {
        console.log(`[FAKE] Empty UA from ${ip}`);
        return true;
    }
    
    // 2. Curl/Wget detection
    if (ua.toLowerCase().includes('curl') || ua.toLowerCase().includes('wget')) {
        console.log(`[FAKE] Curl/Wget from ${ip}`);
        return true;
    }
    
    // 3. Python requests
    if (ua.toLowerCase().includes('python') || ua.toLowerCase().includes('urllib')) {
        console.log(`[FAKE] Python from ${ip}`);
        return true;
    }
    
    // 4. Node fetch / axios
    if (ua.toLowerCase().includes('node') || ua.toLowerCase().includes('axios')) {
        console.log(`[FAKE] Node.js from ${ip}`);
        return true;
    }
    
    // 5. Fake origin (null origin without referer)
    if (origin === 'null' && !referer) {
        console.log(`[FAKE] Null origin from ${ip}`);
        return true;
    }
    
    // 6. Missing Accept header
    if (!accept || accept === '*/*') {
        console.log(`[FAKE] Suspicious accept from ${ip}`);
        return true;
    }
    
    // 7. Roblox valid detection (yang ini diizinkan)
    const isRoblox = ua.includes('Roblox') || ua.includes('WinInet');
    if (isRoblox) {
        console.log(`[ROBLOX] Valid request from ${ip}`);
        return false;
    }
    
    // 8. Browser valid (punya origin/referer yang reasonable)
    const isBrowser = origin.includes('http') || referer.includes('http');
    if (!isBrowser && !isRoblox) {
        console.log(`[FAKE] No browser origin from ${ip}`);
        return true;
    }
    
    return false;
}

// ============ BYTE TABLE ENCODE ============
function toByteTable(content) {
    let bytes = [];
    for (let i = 0; i < content.length; i++) {
        bytes.push(content.charCodeAt(i));
    }
    return JSON.stringify(bytes);
}

// ============ LOADSCRIPT WRAPPER ============
function wrapForRoblox(originalContent) {
    const byteTable = toByteTable(originalContent);
    
    return `-- PROTECTED BY PINAT-OBFUSCATOR
-- Unauthorized access will be blocked

local _bytes = ${byteTable}
local _code = ""
for _i = 1, #_bytes do
    _code = _code .. string.char(_bytes[_i])
end

local _valid, _err = pcall(function()
    return game and game:GetService("Players")
end)

if _valid then
    loadstring(_code)()
else
    error("This script requires Roblox environment")
end`;
}

// ============ MAIN SERVER ============
const server = createServer(async (req, res) => {
    const ip = req.socket.remoteAddress?.split(':').pop() || 'unknown';
    
    // Hanya endpoint /api/main.js
    if (!req.url?.startsWith('/api/main.js')) {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
        return;
    }
    
    // CEK FAKE HEADERS
    if (isFakeRequest(req.headers, ip)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Access Denied: This script has been protected by PinatObfuscator');
        return;
    }
    
    // AMBIL SCRIPT ASLI
    let originalContent;
    try {
        const content = await new Promise((resolve, reject) => {
            get(PROTECTED_URL, (resp) => {
                let data = '';
                resp.on('data', chunk => data += chunk);
                resp.on('end', () => resolve(data));
            }).on('error', reject);
        });
        originalContent = content;
    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error loading script');
        return;
    }
    
    // BUNGKUS + KIRIM
    const output = wrapForRoblox(originalContent);
    
    res.writeHead(200, {
        'Content-Type': 'text/plain',
        'Cache-Control': 'no-store'
    });
    res.end(output);
    
    console.log(`[OK] Served to ${ip} | Size: ${originalContent.length} → ${output.length}`);
});

server.listen(PORT, () => {
    console.log(`PinatProtect running on port ${PORT}`);
});
