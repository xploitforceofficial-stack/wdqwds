import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// --- CONFIGURATION: WHITELISTED IPs ---
const WHITELISTED_IPS = [
    '202.58.78.13', 
    // You can add other IPs here if needed
];

// ============ TAMBAHAN: ANTI FAKE HEADERS ============
function isFakeHeaders(req, ip) {
    const headers = req.headers;
    const ua = headers['user-agent'] || '';
    const origin = headers['origin'] || '';
    const referer = headers['referer'] || '';
    const accept = headers['accept'] || '';
    const acceptLanguage = headers['accept-language'] || '';
    
    // 1. Empty atau terlalu pendek User-Agent
    if (!ua || ua.length < 10) {
        console.log(`[FAKE] Empty/short UA from ${ip}`);
        return { fake: true, reason: 'Empty or invalid User-Agent' };
    }
    
    // 2. Deteksi curl/wget
    const curlPatterns = ['curl', 'wget', 'libcurl', 'aria2', 'axel', 'httrack'];
    for (const pattern of curlPatterns) {
        if (ua.toLowerCase().includes(pattern)) {
            console.log(`[FAKE] ${pattern} detected from ${ip}`);
            return { fake: true, reason: `Tool detected: ${pattern}` };
        }
    }
    
    // 3. Deteksi Python, Node, Go
    const scriptPatterns = ['python', 'node-fetch', 'axios', 'go-http', 'ruby', 'perl', 'php', 'java/', 'okhttp'];
    for (const pattern of scriptPatterns) {
        if (ua.toLowerCase().includes(pattern)) {
            console.log(`[FAKE] ${pattern} detected from ${ip}`);
            return { fake: true, reason: `Script client: ${pattern}` };
        }
    }
    
    // 4. Deteksi fake origin (null tanpa referer valid)
    if (origin === 'null' && (!referer || referer === '')) {
        console.log(`[FAKE] Null origin without referer from ${ip}`);
        return { fake: true, reason: 'Null origin + missing referer' };
    }
    
    // 5. Missing required headers (browser normal harus punya)
    const hasBrowserHeaders = accept && acceptLanguage && (origin || referer);
    if (!hasBrowserHeaders) {
        const missing = [];
        if (!accept) missing.push('Accept');
        if (!acceptLanguage) missing.push('Accept-Language');
        if (!origin && !referer) missing.push('Origin/Referer');
        console.log(`[FAKE] Missing headers: ${missing.join(', ')} from ${ip}`);
        return { fake: true, reason: `Missing headers: ${missing.join(', ')}` };
    }
    
    // 6. Accept header mencurigakan
    if (accept === '*/*' && !ua.toLowerCase().includes('roblox')) {
        console.log(`[FAKE] Suspicious Accept header from ${ip}`);
        return { fake: true, reason: 'Suspicious Accept header' };
    }
    
    // 7. Roblox Client = aman (allowed)
    const isRoblox = ua.toLowerCase().includes('roblox') || 
                     ua.toLowerCase().includes('wininet') ||
                     ua.toLowerCase().includes('luau');
    if (isRoblox) {
        console.log(`[ROBLOX] Valid Roblox client from ${ip}`);
        return { fake: false, reason: null };
    }
    
    // 8. Browser normal = aman
    const isBrowser = ua.toLowerCase().includes('mozilla') || 
                      ua.toLowerCase().includes('chrome') ||
                      ua.toLowerCase().includes('safari') ||
                      ua.toLowerCase().includes('firefox') ||
                      ua.toLowerCase().includes('edge');
    if (isBrowser && origin && referer) {
        console.log(`[BROWSER] Valid browser from ${ip}`);
        return { fake: false, reason: null };
    }
    
    // 9. Default: curiga, block
    console.log(`[FAKE] Unknown/untrusted client from ${ip} | UA: ${ua.substring(0, 100)}`);
    return { fake: true, reason: 'Untrusted client signature' };
}

// --- CONFIGURATION: DISCORD LOGGING ---
async function sendDiscordLog(ip, reason, ua, tool) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: "PinatHub Security",
        avatar_url: "https://files.catbox.moe/s6agav.png",
        embeds: [{
          title: "⚠️ PERMANENT BLACKLIST TRIGGERED",
          color: 9838400,
          fields: [
            { name: "🚫 IP Address", value: `\`${ip}\``, inline: true },
            { name: "🔍 Threat", value: `\`${tool || 'Unknown'}\``, inline: true },
            { name: "📝 Reason", value: `\`${reason}\``, inline: false },
            { name: "🕵️ User Agent", value: `\`\`\`${ua.substring(0, 150)}\`\`\`` }
          ],
          footer: { text: "PinatHub Guard • Zero Tolerance" },
          timestamp: new Date()
        }]
      })
    });
  } catch (e) { console.error("Discord Log Error:", e); }
}

// --- PAGE: BLACKLIST SCREEN ---
function renderBlacklist(ip, reason, tool) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Alert • PinatHub</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }</style>
    </head>
    <body class="bg-[#050505] text-[#ededed] flex items-center justify-center min-h-screen p-4">
        <div class="w-full max-w-md bg-[#111] border border-[#333] rounded-xl p-8 shadow-2xl text-center relative overflow-hidden">
            <div class="absolute top-0 left-1/2 -translate-x-1/2 w-full h-1 bg-gradient-to-r from-transparent via-red-600 to-transparent opacity-50"></div>
            
            <div class="mb-6 flex justify-center">
                <div class="w-16 h-16 rounded-full bg-red-900/10 flex items-center justify-center text-red-500 border border-red-900/30">
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                </div>
            </div>
            
            <h1 class="text-2xl font-bold text-white mb-2 tracking-tight">Access Denied</h1>
            <p class="text-zinc-400 text-sm mb-6 leading-relaxed">
                Our security system has detected malicious activity originating from your device.
                <br>Your IP has been <span class="text-red-400 font-semibold">Permanently Blacklisted</span>.
            </p>

            <div class="bg-[#0a0a0a] rounded-lg p-4 border border-[#222] text-left mb-6 text-sm font-mono space-y-2">
                <div class="flex justify-between text-zinc-500">
                    <span>Target IP:</span>
                    <span class="text-zinc-300">${ip}</span>
                </div>
                <div class="flex justify-between text-zinc-500">
                    <span>Threat:</span>
                    <span class="text-red-400">${tool || 'Suspicious Pattern'}</span>
                </div>
                <div class="flex justify-between text-zinc-500">
                    <span>Reason:</span>
                    <span class="text-red-400 break-all">${reason}</span>
                </div>
            </div>

            <p class="text-xs text-zinc-600 uppercase tracking-widest">PinatHub Security Layer v4.0</p>
        </div>
    </body>
    </html>
  `;
}

// --- LOGIC: TOOL DETECTION (DILEDUPKAN UNTUK ROBLOX) ---
function isMaliciousTool(userAgent) {
  // Jika UA kosong, kita anggap aman (bisa terjadi di Roblox)
  if (!userAgent) return { isMalicious: false, reason: 'Empty UA (Allowed)', tool: null };
  
  const ua = userAgent.toLowerCase();
  
  // 🔥 FIX PENTING: JANGAN BLACKLIST ROBLOX
  // Jika UA mengandung kata kunci Roblox, langsung anggap AMAN
  if (ua.includes("roblox") || ua.includes("wininet") || ua.includes("lua")) {
      return { isMalicious: false, reason: 'Roblox Client', tool: null };
  }

  // Jika UA terlalu pendek (bukan browser beneran)
  if (userAgent.length < 15) return { isMalicious: true, reason: 'Empty/Invalid UA', tool: 'Unknown' };
  
  const maliciousPatterns = [
    'curl', 'wget', 'aria2', 'axel', 'httrack', 'httpie', 'postman', 'insomnia', 'bruno', 'swagger', 
    'openapi', 'graphql', 'python-requests', 'aiohttp', 'httpx', 'urllib', 'pycurl', 'scrapy', 'beautifulsoup',
    'mechanize', 'selenium', 'puppeteer', 'playwright', 'phantomjs', 'headless', 'chrome-headless', 'webkit',
    'geckodriver', 'chromedriver', 'node-fetch', 'axios', 'superagent', 'got', 'undici', 'request', 'http',
    'https', 'curl/', 'wget/', 'libwww-perl', 'lwp-trivial', 'libcurl', 'winhttp',
    
    'python', 'java/', 'jdk', 'jre', 'ruby', 'perl', 'php', 'golang', 'go-http', 'rust', 'curl/', 'node', 
    'npm/', 'yarn/', 'pip/', 'maven', 'gradle', 'composer', 'nuget', 'cargo', 'go-', 'dart/',
    
    'nmap', 'masscan', 'zmap', 'gobuster', 'dirb', 'dirbuster', 'wfuzz', 'ffuf', 'nikto', 'wapiti', 'zap', 
    'burp', 'sqlmap', 'hydra', 'medusa', 'john', 'hashcat', 'metasploit', 'beef', 'xsser', 'commix', 
    'dnsrecon', 'theharvester', 'recon-ng', 'sn1per', 'autosploit', 'shodan', 'censys', 'binaryedge',
    
    'bot', 'spider', 'crawler', 'scraper', 'scraping', 'crawl', 'slurp', 'spider', 'curl', 'wget', 
    'python-urllib', 'libwww', 'lwp::simple', 'httpunit', 'htmlunit', 'jakarta', 'pippo', 'grub',
    'architextspider', 'xenu', 'zeus', 'checkbot', 'linkbot', 'linkwalker', 'scooter', 'mercator',
    'validator', 'webcopier', 'webzip', 'offline', 'teleport', 'webstrip', 'webmirror', 'webspider',
    'webbandit', 'webmasterworld', 'webwatch', 'webwombat', 'wget', 'linkextractorpro', 'linkscan',
    'msiecrawler', 'netscape', 'microsoft internet explorer', 'internet explore', 'mozilla/', 'gecko/',
    'trident/', 'webkit/', 'presto/', 'khtml/', 'browsex', 'amaya', 'amigavoyager', 'amiga-aweb',
    'bison', 'camino', 'chimera', 'cyberdog', 'dillo', 'docomo', 'dreamcast', 'ecatch', 'elinks',
    'emacs-w3', 'ewbrowser', 'galeon', 'ibrowse', 'icab', 'konqueror', 'links', 'lynx', 'omniweb',
    'opera', 'oregano', 'safari', 'voyager', 'w3m', 'curl', 'wget', 'python', 'java', 'perl', 'php',
    
    'vpn', 'proxy', 'tor/', 'tord', 'vps', 'hosting', 'cloud', 'server', 'scan', 'audit', 'test',
    'monitor', 'check', 'health', 'ping', 'trace', 'route', 'whois', 'dig', 'nslookup', 'bind',
    
    'cheerio', 'jsdom', 'axios', 'superagent', 'request-promise', 'node-superfetch', 'node-fetch',
    'unirest', 'fetch-api', 'restsharp', 'resteasy', 'retrofit', 'volley', 'okhttp', 'asynchttpclient',
    'httpurlconnection', 'httpclient', 'webclient', 'resttemplate', 'feign', 'axis', 'cxf', 'jaxrs',
    
    'okhttp', 'dart:io', 'java/', 'dalvik/', 'linux', 'android', 'iphone', 'ipad', 'ipod', 'windows',
    'macintosh', 'mac os x', 'x11', 'ubuntu', 'debian', 'fedora', 'centos', 'red hat', 'suse',
    'mandriva', 'gentoo', 'slackware', 'arch', 'freebsd', 'openbsd', 'netbsd', 'sunos', 'solaris',
    'hp-ux', 'aix', 'irix', 'os/2', 'amigaos', 'morphos', 'risc os', 'syllable', 'beos', 'haiku',
    'qnx', 'vms', 'z/os', 'os/400', 'dos', 'windows 95', 'windows 98', 'windows nt', 'windows 2000',
    'windows xp', 'windows vista', 'windows 7', 'windows 8', 'windows 10', 'windows 11', 'macos',
    'ios', 'android', 'blackberry', 'symbian', 'windows phone', 'firefoxos', 'tizen', 'sailfish',
    'kaios', 'ubuntu touch', 'firefox mobile', 'chrome mobile', 'safari mobile', 'opera mobile',
    'edge mobile', 'samsunginternet', 'uc browser', 'qq browser', 'baidu browser', 'yandex browser',
    'opera mini', 'ucweb', 'bolt', 'teashark', 'skyfire', 'blazer', 'icecat', 'iceape', 'seamonkey',
    'waterfox', 'pale moon', 'basilisk', 'k-meleon', 'galeon', 'epiphany', 'dillo', 'links2', 'elinks',
    'w3m', 'lynx', 'edbrowse', 'netpositive', 'voyager', 'aweb', 'ibrowse', 'amaya', 'wmosaic',
    'mosaic', 'cern linemode', 'lynx', 'www-mirror', 'netscape', 'mosaic', 'worldwideweb', 'libwww',
    'wwwlib', 'getright', 'goto', 'getweb', 'go-ahead-got', 'go!zilla', 'gotit', 'grabber', 'grabnet',
    'grafula', 'greed', 'gridbot', 'gromit', 'grub-client', 'gulliver', 'harvest', 'havindex', 'hazel',
    'htdig', 'htmlgobble', 'hyperdecontextualizer', 'h�m�h�kki', 'ia_archiver', 'ibm_planetwork',
    'imagemosaic', 'incywincy', 'informant', 'infospider', 'inktomi', 'inspectorwww', 'intelliagent',
    'internetseer', 'iral', 'irobot', 'iron33', 'israelisearch', 'jBot', 'jeeves', 'jobo', 'jpeg',
    'jobo', 'join', 'jubii', 'jumpstation', 'katipo', 'kdd-explorer', 'kilroy', 'ko_yappo_robot',
    'labelgrabber', 'larbin', 'legs', 'libwww-perl', 'link', 'linkidator', 'linkscan', 'linkwalker',
    'lockon', 'logo_gif', 'lwp', 'lycos', 'magpie', 'mantraagent', 'martin', 'marvin', 'mattie',
    'mediafox', 'mediapartners', 'mercator', 'merzscope', 'microsoft url control', 'minotaur',
    'miixpc', 'miva', 'mj12bot', 'mnogosearch', 'moget', 'momspider', 'monster', 'motor', 'muncher',
    'muscatferret', 'mwd.search', 'myweb', 'nazio', 'nec-meshexplorer', 'nederland.zoek', 'netants',
    'netmechanic', 'netscoop', 'newscan-online', 'nhse', 'nomad', 'noyona', 'nutch', 'nzexplorer',
    'occam', 'octopus', 'openfind', 'openintegrity', 'orbsearch', 'packrat', 'pageboy', 'pager',
    'patric', 'pegasus', 'perlcrawler', 'perman', 'petersnews', 'phantom', 'phpdig', 'picosearch',
    'piltdownman', 'pimptrain', 'pinpoint', 'pioneer', 'plucker', 'pogodak', 'pompos', 'poppi',
    'poppy', 'portalb', 'psbot', 'python', 'rambler', 'raven', 'rbse', 'resume', 'roadhouse', 'robbie',
    'robofox', 'robozilla', 'roverbot', 'rules', 'safetynet', 'salmagundi', 'scooter', 'scoutjet',
    'scrubby', 'search', 'searchprocess', 'semanticdiscovery', 'senrigan', 'sg-scout', 'shagseeker',
    'shai', 'simmany', 'sitemapper', 'sitevalet', 'sitetech', 'slcrawler', 'sleek', 'smartwit', 'snooper',
    'solbot', 'spider', 'spiderlytics', 'spidermonkey', 'spiderview', 'spry', 'sqworm', 'ssearcher',
    'suke', 'suntek', 'surfer', 'sven', 'sygol', 'tach', 'tarantula', 'tarspider', 'tcl_http',
    'techbot', 'templeton', 'teoma', 'teradex', 'titin', 'titan', 'tkens', 'tlspider', 'toutatis',
    't-h-u-n-d-e-r-s-t-o-n-e', 'turnitinbot', 'turtle', 'tv33', 'twiceler', 'twisted PageGetter',
    'ucmore', 'udmsearch', 'urlck', 'urlresolver', 'valkyrie', 'victoria', 'vision-search', 'voidbot',
    'voyager', 'vwbot_k', 'w3index', 'w3m2', 'wallpaper', 'wanderer', 'wapspider', 'watchdog',
    'wavefire', 'webbandit', 'webcatcher', 'webclipping', 'webcollage', 'webcopy', 'webcraft',
    'webdevil', 'webdownloader', 'webdup', 'webfetch', 'webfoot', 'webinator', 'weblayers',
    'weblinker', 'weblog', 'webmirror', 'webmonkey', 'webquest', 'webreaper', 'websquash',
    'webspider', 'webster', 'webstripper', 'webvac', 'webwalk', 'webwalker', 'webwatch',
    'webwombat', 'webzip', 'wget', 'whizbang', 'whowhere', 'wildferret', 'worldlight', 'wwwc',
    'wwwster', 'xget', 'xyleme', 'yacy', 'yandex', 'yanga', 'yeti', 'yodao', 'yooglifetchagent',
    'zeal', 'zeus', 'zippy', 'zoom', 'zspider'
  ];

  for (const pattern of maliciousPatterns) {
    if (ua.includes(pattern)) {
      return { isMalicious: true, reason: 'Blacklisted Tool Detected', tool: pattern };
    }
  }

  return { isMalicious: false, reason: 'Clean', tool: null };
}

export default async function handler(req, res) {
  const userAgent = req.headers['user-agent'] || '';
  const ua = userAgent.toLowerCase();
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

  // ============ TAMBAHAN: CEK FAKE HEADERS (DI AWAL) ============
  const fakeCheck = isFakeHeaders(req, ip);
  if (fakeCheck.fake) {
    console.log(`[BLOCKED] Fake headers from ${ip}: ${fakeCheck.reason}`);
    res.setHeader('Content-Type', 'text/html');
    return res.status(403).send(renderBlacklist(ip, fakeCheck.reason, 'FakeHeaders'));
  }

  // --- STEP 1: SECURITY BYPASS ---
  if (WHITELISTED_IPS.includes(ip)) {
    console.log(`[ACCESS ALLOWED] Whitelisted IP detected: ${ip}`);
  } else {
    // --- STEP 2: CHECK BLACKLIST (LOOSE MODE) ---
    const check = isMaliciousTool(userAgent);
    if (check.isMalicious) {
      try {
        await client.connect();
        const db = client.db('pinat_protection');
        await db.collection('blacklisted_ips').updateOne(
          { ip: ip }, 
          { $set: { reason: check.reason, tool: check.tool, date: new Date() } }, 
          { upsert: true }
        );
      } catch (e) { console.error(e); } finally { await client.close(); }
      await sendDiscordLog(ip, check.reason, userAgent, check.tool);
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklist(ip, check.reason, check.tool));
    }
  }

  // --- STEP 3: INTELLIGENT CLIENT DETECTION (ROBLOX VS BROWSER) ---
  
  // Deteksi Roblox Client
  const isRobloxClient = 
    ua.includes("roblox") || 
    ua.includes("wininet") || 
    ua.includes("lua");

  // Jika Roblox -> KIRIM SCRIPT
  if (isRobloxClient) {
    try {
      // Pastikan ini link script asli
      const response = await fetch('https://raw.githubusercontent.com/stokompetgacor23-dotcom/PinatHubSettingsMap/refs/heads/main/main.lua');
      const scriptContent = await response.text();
      
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.status(200).send(scriptContent);
    } catch (err) {
      return res.status(500).send('print("Error loading script from source")');
    }
  }

  // --- STEP 4: FALLBACK (NORMAL BROWSER) ---
  // Kalau bukan Roblox -> Tampilkan UI Premium
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(`
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PinatHub • Premium Scripts</title>
        
        <!-- Fonts -->
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
        
        <!-- Tailwind CSS -->
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {
                darkMode: 'class',
                theme: {
                    extend: {
                        colors: {
                            bg: "#020203",
                            surface: "#0a0a0c",
                            surfaceHighlight: "#121214",
                            border: "#27272a",
                            primary: "#ffffff",
                            secondary: "#71717a",
                            accent: "#6366f1",
                            accentGlow: "#818cf8",
                        },
                        fontFamily: {
                            sans: ['Inter', 'sans-serif'],
                            mono: ['JetBrains Mono', 'monospace'],
                            display: ['Orbitron', 'sans-serif'],
                        },
                        backgroundImage: {
                            'grid-pattern': "linear-gradient(to right, #1f1f22 1px, transparent 1px), linear-gradient(to bottom, #1f1f22 1px, transparent 1px)",
                            'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
                        },
                        animation: {
                            'fade-in': 'fadeIn 0.8s ease-out forwards',
                            'slide-up': 'slideUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards',
                            'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                            'float': 'float 6s ease-in-out infinite',
                            'scan': 'scan 4s linear infinite',
                            'glow-pulse': 'glowPulse 3s ease-in-out infinite',
                        },
                        keyframes: {
                            fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
                            slideUp: { '0%': { opacity: '0', transform: 'translateY(20px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
                            float: { '0%, 100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-8px)' } },
                            scan: { '0%': { backgroundPosition: '0% 0%' }, '100%': { backgroundPosition: '0% 100%' } },
                            glowPulse: { '0%, 100%': { opacity: '0.6' }, '50%': { opacity: '1' } },
                        }
                    }
                }
            }
        </script>
        
        <style>
            /* Base Reset & Scroll */
            :root { --cursor-size: 20px; }
            html { scroll-behavior: smooth; }
            body { 
                background-color: #020203; 
                color: #e4e4e7;
                overflow-x: hidden;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            /* Background Layers */
            .bg-layer-base {
                position: fixed;
                inset: 0;
                z-index: -2;
                background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #020203 40%);
            }
            .bg-layer-grid {
                position: fixed;
                inset: 0;
                z-index: -1;
                background-size: 50px 50px;
                opacity: 0.15;
                mask-image: linear-gradient(to bottom, black 20%, transparent 90%);
                -webkit-mask-image: linear-gradient(to bottom, black 20%, transparent 90%);
            }
            .bg-layer-orb {
                position: fixed;
                border-radius: 50%;
                filter: blur(80px);
                z-index: -1;
                opacity: 0.4;
                animation: float 10s ease-in-out infinite;
            }
            .orb-1 { top: -10%; left: -10%; width: 50vw; height: 50vw; background: #4f46e5; animation-delay: 0s; }
            .orb-2 { bottom: 10%; right: -10%; width: 40vw; height: 40vw; background: #c026d3; animation-delay: -5s; }

            /* Glassmorphism Card System */
            .glass-card {
                background: rgba(18, 18, 20, 0.6);
                backdrop-filter: blur(16px);
                -webkit-backdrop-filter: blur(16px);
                border: 1px solid rgba(255, 255, 255, 0.06);
                box-shadow: 
                    0 4px 6px -1px rgba(0, 0, 0, 0.1),
                    0 2px 4px -1px rgba(0, 0, 0, 0.06),
                    inset 0 1px 0 0 rgba(255, 255, 255, 0.05);
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }
            .glass-card:hover {
                border-color: rgba(99, 102, 241, 0.3);
                box-shadow: 
                    0 20px 25px -5px rgba(0, 0, 0, 0.2),
                    0 10px 10px -5px rgba(0, 0, 0, 0.1),
                    0 0 0 1px rgba(99, 102, 241, 0.1);
                transform: translateY(-2px);
            }

            /* Terminal / Code Box */
            .terminal-window {
                background: #09090b;
                border: 1px solid #27272a;
                box-shadow: inset 0 0 20px rgba(0,0,0,0.5);
                position: relative;
                overflow: hidden;
            }
            .terminal-header {
                background: #18181b;
                border-bottom: 1px solid #27272a;
                padding: 8px 12px;
                display: flex;
                align-items: center;
                gap: 6px;
            }
            .dot { width: 10px; height: 10px; border-radius: 50%; }
            .dot-red { background: #ef4444; }
            .dot-yellow { background: #f59e0b; }
            .dot-green { background: #10b981; }
            
            .code-content {
                font-family: 'JetBrains Mono', monospace;
                color: #a5b4fc;
                text-shadow: 0 0 10px rgba(165, 180, 252, 0.15);
            }
            .scanline {
                width: 100%;
                height: 2px;
                background: rgba(255,255,255,0.05);
                position: absolute;
                z-index: 10;
                top: 0;
                left: 0;
                animation: scan 4s linear infinite;
                pointer-events: none;
            }

            /* Scrollbar */
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: #020203; }
            ::-webkit-scrollbar-thumb { background: #27272a; border-radius: 4px; }
            ::-webkit-scrollbar-thumb:hover { background: #3f3f46; }

            /* Utilities */
            .text-glow { text-shadow: 0 0 20px rgba(99, 102, 241, 0.4); }
            .text-gradient {
                background: linear-gradient(to right, #fff, #a5b4fc);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            .logo-container {
                position: relative;
                z-index: 10;
            }
            .logo-glow {
                position: absolute;
                inset: -20px;
                background: radial-gradient(circle, rgba(99,102,241,0.3) 0%, transparent 70%);
                filter: blur(30px);
                z-index: -1;
                animation: glowPulse 3s ease-in-out infinite;
            }
            
            /* Section Dividers */
            .section-divider {
                height: 1px;
                background: linear-gradient(to right, transparent, #27272a, transparent);
                margin: 3rem 0;
                opacity: 0.5;
            }

            /* Toast */
            #toast-container {
                position: fixed;
                bottom: 24px;
                right: 24px;
                z-index: 100;
                display: flex;
                flex-direction: column;
                gap: 12px;
                pointer-events: none;
            }
            .toast {
                pointer-events: auto;
                background: rgba(18, 18, 20, 0.95);
                backdrop-filter: blur(10px);
                border: 1px solid #27272a;
                border-left: 3px solid #6366f1;
                padding: 16px 20px;
                border-radius: 8px;
                box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                gap: 12px;
                color: #fff;
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
                min-width: 300px;
            }
            .toast.show { opacity: 1; transform: translateY(0); }
        </style>
    </head>
    <body class="antialiased min-h-screen flex flex-col items-center relative selection:bg-accent selection:text-white overflow-x-hidden">
        
        <!-- Background Layers -->
        <div class="bg-layer-base"></div>
        <div class="bg-layer-grid bg-grid-pattern"></div>
        <div class="bg-layer-orb orb-1"></div>
        <div class="bg-layer-orb orb-2"></div>

        <!-- Main Wrapper -->
        <main class="w-full max-w-7xl px-5 md:px-8 py-16 md:py-24 relative z-10 flex flex-col items-center">
            
            <!-- Header / Hero Section -->
            <header class="w-full flex flex-col items-center text-center mb-20 md:mb-32 animate-slide-up max-w-4xl mx-auto">
                <div class="logo-container mb-8 group cursor-default">
                    <div class="logo-glow"></div>
                    <img src="https://files.catbox.moe/s6agav.png" alt="PinatHub Logo" 
                         class="w-28 h-28 md:w-40 md:h-40 rounded-full relative z-10 border border-white/10 shadow-2xl transition-transform duration-500 group-hover:scale-105">
                </div>
                
                <h1 class="text-5xl md:text-7xl font-display font-black tracking-tighter mb-6 leading-[1.1]">
                    <span class="text-white">Pinat</span><span class="text-transparent bg-clip-text bg-gradient-to-r from-accent to-purple-400 text-glow">Hub</span>
                </h1>
                
                <p class="text-secondary text-lg md:text-xl font-light tracking-wide leading-relaxed max-w-2xl">
                    Next-Generation Roblox Execution Infrastructure
                    <span class="block mt-2 text-xs font-mono text-accent/70 uppercase tracking-widest border-t border-white/10 pt-2 inline-block">Secure • Encrypted • Undetected</span>
                </p>
            </header>

            <!-- Content Grid -->
            <div class="w-full grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-start">
                
                <!-- Left Column: Loader Card (Span 5) -->
                <div class="lg:col-span-5 w-full animate-slide-up" style="animation-delay: 0.15s;">
                    <div class="glass-card rounded-2xl p-1 relative overflow-hidden group">
                        <!-- Inner Gradient Border Glow -->
                        <div class="absolute inset-0 bg-gradient-to-br from-accent/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"></div>
                        
                        <div class="bg-[#0c0c0e]/80 rounded-xl p-6 md:p-8 relative z-10 backdrop-blur-sm">
                            <div class="flex items-center justify-between mb-6">
                                <h2 class="text-xl font-display font-bold text-white flex items-center gap-3">
                                    <div class="p-2.5 bg-accent/10 rounded-lg border border-accent/20 text-accent shadow-[0_0_15px_rgba(99,102,241,0.3)]">
                                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                                    </div>
                                    Universal Loader
                                </h2>
                                <div class="flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20">
                                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                    <span class="text-[10px] font-mono font-bold uppercase text-emerald-400 tracking-wider">Active</span>
                                </div>
                            </div>
                            
                            <p class="text-secondary text-sm leading-relaxed mb-6 border-l border-white/10 pl-4">
                                Inject this payload into your executor. The heuristic engine will automatically identify the active game context and deploy the correct module silently.
                            </p>
                            
                            <!-- Terminal Code Block -->
                            <div class="terminal-window rounded-lg mb-6 group/code">
                                <div class="terminal-header">
                                    <div class="dot dot-red"></div>
                                    <div class="dot dot-yellow"></div>
                                    <div class="dot dot-green"></div>
                                    <span class="ml-2 text-[10px] font-mono text-zinc-500 uppercase tracking-wider">bash — 80x24</span>
                                </div>
                                <div class="p-4 overflow-x-auto custom-scrollbar relative">
                                    <div class="scanline"></div>
                                    <code id="loader-code" class="font-mono text-xs md:text-sm code-content block break-all whitespace-pre-wrap">loadstring(game:HttpGet("https://raw.githubusercontent.com/xploitforceofficial-stack/pinatpublicloader/refs/heads/main/pinatloader.lua"))()</code>
                                </div>
                            </div>
                        
                            <button onclick="copyLoader()" class="w-full py-4 bg-white text-black font-display font-bold text-sm rounded-xl hover:bg-gray-50 transition-all duration-200 transform hover:scale-[1.02] active:scale-[0.98] flex items-center justify-center gap-3 shadow-[0_0_20px_-5px_rgba(255,255,255,0.15)] relative overflow-hidden group/btn border border-white/5">
                                <div class="absolute inset-0 bg-gradient-to-r from-transparent via-white/40 to-transparent translate-x-[-100%] group-hover/btn:animate-shine"></div>
                                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="relative z-10"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                <span id="copy-text" class="relative z-10">Copy Payload</span>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Right Column: Games & Info (Span 7) -->
                <div class="lg:col-span-7 w-full flex flex-col gap-6 animate-slide-up" style="animation-delay: 0.3s;">
                    
                    <!-- Info Card -->
                    <div class="glass-card rounded-2xl p-6 md:p-8 border-l-4 border-l-accent relative overflow-hidden">
                        <div class="absolute -right-10 -top-10 w-40 h-40 bg-accent/5 rounded-full blur-3xl pointer-events-none"></div>
                        <h2 class="text-2xl font-display font-bold text-white mb-4 flex items-center gap-3">
                            System Architecture
                            <span class="text-xs font-mono font-normal text-secondary bg-white/5 px-2 py-1 rounded border border-white/5">v4.2.0</span>
                        </h2>
                        <p class="text-secondary text-sm leading-relaxed">
                            PinatHub utilizes a proprietary heuristic engine to deliver <span class="text-white font-medium">Auto-Farming</span>, <span class="text-white font-medium">PVP Dominance</span>, and <span class="text-white font-medium">ESP Visualization</span>. Our scripts are protected by enterprise-grade obfuscation, ensuring integrity against modern anti-tamper mechanisms.
                        </p>
                    </div>

                    <div class="section-divider"></div>

                    <!-- Games Grid -->
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        
                        <!-- Game 1: TSB -->
                        <a href="https://www.roblox.com/games/10449761463/The-Strongest-Battlegrounds" target="_blank" class="glass-card p-4 rounded-xl group/game flex flex-col gap-3 relative overflow-hidden">
                            <div class="absolute inset-0 bg-blue-500/5 opacity-0 group-hover/game:opacity-100 transition-opacity duration-300"></div>
                            <div class="flex items-center justify-between relative z-10">
                                <img src="https://files.catbox.moe/6gpc09.png" alt="TSB" class="w-12 h-12 rounded-lg object-cover border border-white/10 shadow-lg">
                                <div class="w-8 h-8 rounded-full bg-blue-500/10 flex items-center justify-center text-blue-400 group-hover/game:scale-110 transition-transform">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                </div>
                            </div>
                            <div class="relative z-10">
                                <h3 class="font-bold text-white text-sm md:text-base tracking-wide">The Strongest Battlegrounds</h3>
                            </div>
                        </a>

                        <!-- Game 2: Blade Ball -->
                        <a href="https://www.roblox.com/games/13772394625/Blade-Ball" target="_blank" class="glass-card p-4 rounded-xl group/game flex flex-col gap-3 relative overflow-hidden">
                            <div class="absolute inset-0 bg-purple-500/5 opacity-0 group-hover/game:opacity-100 transition-opacity duration-300"></div>
                            <div class="flex items-center justify-between relative z-10">
                                <img src="https://files.catbox.moe/uosaqi.png" alt="Blade Ball" class="w-12 h-12 rounded-lg object-cover border border-white/10 shadow-lg">
                                <div class="w-8 h-8 rounded-full bg-purple-500/10 flex items-center justify-center text-purple-400 group-hover/game:scale-110 transition-transform">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                </div>
                            </div>
                            <div class="relative z-10">
                                <h3 class="font-bold text-white text-sm md:text-base tracking-wide">Blade Ball</h3>
                            </div>
                        </a>

                        <!-- Game 3: Apocalypse -->
                        <a href="https://www.roblox.com/games/90148635862803/Survive-the-Apocalypse" target="_blank" class="glass-card p-4 rounded-xl group/game flex flex-col gap-3 relative overflow-hidden">
                            <div class="absolute inset-0 bg-red-500/5 opacity-0 group-hover/game:opacity-100 transition-opacity duration-300"></div>
                            <div class="flex items-center justify-between relative z-10">
                                <img src="https://files.catbox.moe/tua3ov.png" alt="Apocalypse" class="w-12 h-12 rounded-lg object-cover border border-white/10 shadow-lg">
                                <div class="w-8 h-8 rounded-full bg-red-500/10 flex items-center justify-center text-red-400 group-hover/game:scale-110 transition-transform">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                </div>
                            </div>
                            <div class="relative z-10">
                                <h3 class="font-bold text-white text-sm md:text-base tracking-wide">Survive The Apocalypse</h3>
                            </div>
                        </a>

                        <!-- Game 4: Heavyweight Fishing -->
                        <a href="https://www.roblox.com/games/98502499119821/Heavyweight-Fishing" target="_blank" class="glass-card p-4 rounded-xl group/game flex flex-col gap-3 relative overflow-hidden">
                            <div class="absolute inset-0 bg-yellow-500/5 opacity-0 group-hover/game:opacity-100 transition-opacity duration-300"></div>
                            <div class="flex items-center justify-between relative z-10">
                                <img src="https://files.catbox.moe/bewcvm.png" alt="Fishing" class="w-12 h-12 rounded-lg object-cover border border-white/10 shadow-lg">
                                <div class="w-8 h-8 rounded-full bg-yellow-500/10 flex items-center justify-center text-yellow-400 group-hover/game:scale-110 transition-transform">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                </div>
                            </div>
                            <div class="relative z-10">
                                <h3 class="font-bold text-white text-sm md:text-base tracking-wide">Heavyweight Fishing</h3>
                            </div>
                        </a>

                        <!-- Game 5: Be A Lucky Block -->
                        <a href="https://www.roblox.com/games/124473577469410/Be-a-Lucky-Block" target="_blank" class="glass-card p-4 rounded-xl group/game flex flex-col gap-3 relative overflow-hidden">
                            <div class="absolute inset-0 bg-green-500/5 opacity-0 group-hover/game:opacity-100 transition-opacity duration-300"></div>
                            <div class="flex items-center justify-between relative z-10">
                                <img src="https://files.catbox.moe/kgafaq.png" alt="Lucky Block" class="w-12 h-12 rounded-lg object-cover border border-white/10 shadow-lg">
                                <div class="w-8 h-8 rounded-full bg-green-500/10 flex items-center justify-center text-green-400 group-hover/game:scale-110 transition-transform">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
                                </div>
                            </div>
                            <div class="relative z-10">
                                <h3 class="font-bold text-white text-sm md:text-base tracking-wide">Be A Lucky Block</h3>
                            </div>
                        </a>

                    </div>
                </div>
            </div>

            <!-- Footer -->
            <div class="mt-24 w-full border-t border-white/5 pt-8 flex flex-col md:flex-row justify-between items-center gap-4 animate-fade-in">
                <div class="flex items-center gap-2 text-zinc-500 text-xs font-mono">
                    <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                    <span>PINATHUB GUARD // ALL SYSTEMS OPERATIONAL</span>
                </div>
                <div class="text-zinc-600 text-xs font-mono">
                    © 2024 PinatHub. Secure Connection.
                </div>
            </div>

        </main>

        <!-- Toast Notification Container -->
        <div id="toast-container"></div>

        <script>
            // Custom Toast Notification System
            function showToast(message, type = 'success') {
                const container = document.getElementById('toast-container');
                const toast = document.createElement('div');
                toast.className = 'toast';
                
                const icon = type === 'success' 
                    ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>'
                    : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';

                toast.innerHTML = icon + '<span class="font-medium text-sm tracking-wide">' + message + '</span>';
                container.appendChild(toast);

                requestAnimationFrame(() => {
                    toast.classList.add('show');
                });

                setTimeout(() => {
                    toast.classList.remove('show');
                    setTimeout(() => toast.remove(), 400);
                }, 3000);
            }

            // Copy Loader Function
            function copyLoader() {
                const code = document.getElementById('loader-code').innerText;
                const btnText = document.getElementById('copy-text');
                const originalText = btnText.innerText;

                navigator.clipboard.writeText(code).then(() => {
                    btnText.innerText = 'Copied!';
                    showToast('Payload copied to clipboard');

                    setTimeout(() => {
                        btnText.innerText = originalText;
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                    showToast('Failed to copy payload', 'error');
                });
            }
        </script>
    </body>
    </html>
  `);
}
