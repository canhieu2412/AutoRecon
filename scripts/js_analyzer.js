#!/usr/bin/env node
// ============================================================================
// AUTO RECON - JavaScript Analyzer & Deobfuscator
// Extracts secrets, deobfuscates, and analyzes JS files from targets
// ============================================================================

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

// ── Deobfuscation Patterns ──
function deobfuscateJS(code) {
    let result = code;
    
    // 1. Decode hex strings: "\x48\x65\x6c\x6c\x6f" → "Hello"
    result = result.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => 
        String.fromCharCode(parseInt(hex, 16))
    );
    
    // 2. Decode unicode: "\u0048\u0065" → "He"
    result = result.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
    );
    
    // 3. Decode octal: "\110\145" → "He"
    result = result.replace(/\\([0-7]{1,3})/g, (_, oct) =>
        String.fromCharCode(parseInt(oct, 8))
    );
    
    // 4. Decode String.fromCharCode(72,101,108) → "Hel"
    result = result.replace(/String\.fromCharCode\(([^)]+)\)/g, (_, args) => {
        try {
            const chars = args.split(',').map(n => String.fromCharCode(parseInt(n.trim())));
            return `"${chars.join('')}"`;
        } catch { return _; }
    });
    
    // 5. Decode atob("base64") → decoded
    result = result.replace(/atob\(["']([^"']+)["']\)/g, (_, b64) => {
        try {
            return `"${Buffer.from(b64, 'base64').toString()}"`;
        } catch { return _; }
    });
    
    // 6. Decode parseInt with radix tricks
    result = result.replace(/parseInt\(["']([^"']+)["'],\s*(\d+)\)/g, (_, val, radix) => {
        try { return String(parseInt(val, parseInt(radix))); }
        catch { return _; }
    });
    
    // 7. Resolve simple string concatenation: "a"+"b"+"c" → "abc"
    result = result.replace(/"([^"]*?)"\s*\+\s*"([^"]*?)"/g, '"$1$2"');
    // Do it multiple passes
    for (let i = 0; i < 5; i++) {
        result = result.replace(/"([^"]*?)"\s*\+\s*"([^"]*?)"/g, '"$1$2"');
    }
    
    // 8. Unescape HTML entities
    result = result.replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(dec));
    result = result.replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    
    return result;
}

// ── Beautify/Format JS ──
function beautifyJS(code) {
    let indent = 0;
    let result = '';
    let inString = false;
    let stringChar = '';
    
    for (let i = 0; i < code.length; i++) {
        const c = code[i];
        const next = code[i + 1] || '';
        
        if (inString) {
            result += c;
            if (c === stringChar && code[i - 1] !== '\\') inString = false;
            continue;
        }
        
        if (c === '"' || c === "'" || c === '`') {
            inString = true;
            stringChar = c;
            result += c;
            continue;
        }
        
        if (c === '{') {
            indent++;
            result += ' {\n' + '  '.repeat(indent);
        } else if (c === '}') {
            indent = Math.max(0, indent - 1);
            result += '\n' + '  '.repeat(indent) + '}';
            if (next !== ';' && next !== ',' && next !== ')' && next !== '\n') {
                result += '\n' + '  '.repeat(indent);
            }
        } else if (c === ';') {
            result += ';\n' + '  '.repeat(indent);
        } else if (c === ',' && !inString) {
            result += ',\n' + '  '.repeat(indent);
        } else {
            result += c;
        }
    }
    
    // Clean multiple blank lines
    result = result.replace(/\n{3,}/g, '\n\n');
    return result;
}

// ── Extract Secrets & Interesting Patterns ──
function extractSecrets(code, sourceUrl) {
    const findings = [];
    
    const patterns = [
        { name: 'API Key', regex: /['"]?(api[_-]?key|apikey|api[_-]?token)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]|['"](AIza[0-9A-Za-z_-]{35})['"]/gi },
        { name: 'AWS Key', regex: /['"]?(AKIA[0-9A-Z]{16})['"]/g },
        { name: 'Secret/Password', regex: /['"]?(secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token|bearer)['"]?\s*[:=]\s*['"]([^'"]{4,})['"]|['"](sk-[a-zA-Z0-9]{20,})['"]/gi },
        { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
        { name: 'Private Key', regex: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g },
        { name: 'Internal URL', regex: /(https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'"]*)/gi },
        { name: 'API Endpoint', regex: /['"](\/?api\/v?\d*\/[a-zA-Z0-9_/.-]+)['"]/gi },
        { name: 'Email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
        { name: 'IP Address', regex: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g },
        { name: 'AWS S3 Bucket', regex: /(?:s3\.amazonaws\.com\/([^\/'"]+)|([a-z0-9.-]+)\.s3\.amazonaws\.com)/gi },
        { name: 'Firebase URL', regex: /https?:\/\/[a-z0-9-]+\.firebaseio\.com/gi },
        { name: 'Google Maps Key', regex: /AIza[0-9A-Za-z_-]{35}/g },
        { name: 'Slack Token', regex: /xox[baprs]-[0-9a-zA-Z-]+/g },
        { name: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/g },
        { name: 'Base64 (long)', regex: /['"]([A-Za-z0-9+/]{40,}={0,2})['"]/g },
        { name: 'Hidden Path', regex: /['"](\/?(?:admin|backup|debug|test|staging|internal|private|config|\.env|wp-config|database|phpmyadmin|dashboard)[^\s'"]*)['"]/gi },
        { name: 'SQL Query', regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.{5,}(?:FROM|INTO|TABLE|WHERE)/gi },
        { name: 'DOM XSS Sink', regex: /\.(innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval|Function)\s*[\(=]/g },
        { name: 'Postmessage', regex: /\.postMessage\s*\(|addEventListener\s*\(\s*['"]message['"]/g },
        { name: 'Fetch/XHR URL', regex: /(?:fetch|axios|XMLHttpRequest[\s\S]*?open)\s*\(\s*['"]([^'"]+)['"]/gi },
        { name: 'Comment TODO/FIXME', regex: /\/\/\s*(TODO|FIXME|HACK|BUG|XXX|NOTE):?\s*(.+)/gi },
        { name: 'Hardcoded Credentials', regex: /(?:admin|root|user|login)\s*[:=]\s*['"]([^'"]+)['"]\s*[,;]?\s*(?:pass|password|pwd)\s*[:=]\s*['"]([^'"]+)['"]/gi },
    ];
    
    for (const { name, regex } of patterns) {
        let match;
        const cloned = new RegExp(regex.source, regex.flags);
        while ((match = cloned.exec(code)) !== null) {
            const value = match[0].substring(0, 200);
            findings.push({ type: name, value, source: sourceUrl });
        }
    }
    
    return findings;
}

// ── Fetch JS file ──
function fetchUrl(targetUrl, redirectCount = 0) {
    return new Promise((resolve, reject) => {
        const lib = targetUrl.startsWith('https') ? https : http;
        const options = {
            rejectUnauthorized: false,
            timeout: 10000,
            headers: { 'User-Agent': 'Mozilla/5.0 AutoRecon/3.0' }
        };
        
        lib.get(targetUrl, options, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                if (redirectCount >= 5) {
                    reject(new Error('too many redirects'));
                    return;
                }
                const redirectUrl = url.resolve(targetUrl, res.headers.location);
                res.resume();
                resolve(fetchUrl(redirectUrl, redirectCount + 1));
                return;
            }

            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({
                body: data,
                finalUrl: targetUrl,
                statusCode: res.statusCode || 0,
            }));
        }).on('error', reject)
          .on('timeout', () => reject(new Error('timeout')));
    });
}

function safeFilenameFromUrl(resourceUrl, fallback = 'unknown.js') {
    const parsed = url.parse(resourceUrl);
    const host = (parsed.host || 'unknown').replace(/[^A-Za-z0-9._-]+/g, '_');
    let pathname = parsed.pathname || `/${fallback}`;
    if (pathname.endsWith('/')) pathname += fallback;

    const pathPart = pathname.replace(/^\/+/, '').replace(/[^A-Za-z0-9._-]+/g, '_') || fallback;
    const queryPart = parsed.query ? `__${parsed.query.replace(/[^A-Za-z0-9._-]+/g, '_')}` : '';
    return `${host}__${pathPart}${queryPart}`;
}

// ── Extract JS URLs from HTML ──
function extractJSUrls(html, baseUrl) {
    const urls = new Set();
    const parsed = url.parse(baseUrl);
    const base = `${parsed.protocol}//${parsed.host}`;
    
    // <script src="...">
    const srcRegex = /<script[^>]+src=["']([^"']+)["']/gi;
    let match;
    while ((match = srcRegex.exec(html)) !== null) {
        let jsUrl = match[1];
        if (jsUrl.startsWith('//')) jsUrl = parsed.protocol + jsUrl;
        else if (jsUrl.startsWith('/')) jsUrl = base + jsUrl;
        else if (!jsUrl.startsWith('http')) jsUrl = base + '/' + jsUrl;
        urls.add(jsUrl);
    }
    
    // Inline <script> blocks
    const inlineRegex = /<script(?:\s[^>]*)?>(?!.*?src=)([\s\S]*?)<\/script>/gi;
    while ((match = inlineRegex.exec(html)) !== null) {
        if (match[1].trim().length > 20) {
            urls.add(`inline://${match[1].substring(0, 50)}...`);
        }
    }
    
    return { external: [...urls].filter(u => u.startsWith('http')), 
             inline: [...urls].filter(u => u.startsWith('inline://')) };
}

// ── Main ──
async function main() {
    const args = process.argv.slice(2);
    if (args.length < 2) {
        console.log('Usage: js_analyzer.js <URL> <OUTPUT_DIR>');
        process.exit(1);
    }
    
    const targetUrl = args[0];
    const outputDir = args[1];
    
    fs.mkdirSync(path.join(outputDir, 'js'), { recursive: true });
    
    console.log(`\n  [*] JS Analyzer - Target: ${targetUrl}\n`);
    
    // 1. Fetch HTML page
    let html;
    let effectiveUrl = targetUrl;
    try {
        const pageResponse = await fetchUrl(targetUrl);
        html = pageResponse.body;
        effectiveUrl = pageResponse.finalUrl;
    } catch (e) {
        console.log(`  [!] Failed to fetch ${targetUrl}: ${e.message}`);
        process.exit(1);
    }
    
    // 2. Extract JS URLs
    const { external, inline } = extractJSUrls(html, effectiveUrl);
    console.log(`  [+] Found ${external.length} external JS files`);
    console.log(`  [+] Found ${inline.length} inline script blocks`);
    
    const allFindings = [];
    const allDeobfuscated = [];
    
    // 3. Analyze inline scripts
    const inlineRegex = /<script(?:\s[^>]*)?>(?!.*?src=)([\s\S]*?)<\/script>/gi;
    let inlineMatch;
    let inlineIdx = 0;
    while ((inlineMatch = inlineRegex.exec(html)) !== null) {
        const code = inlineMatch[1].trim();
        if (code.length < 20) continue;
        inlineIdx++;
        
        console.log(`  [*] Analyzing inline script #${inlineIdx} (${code.length} chars)`);
        
        const deobfuscated = deobfuscateJS(code);
        const findings = extractSecrets(deobfuscated, `inline#${inlineIdx}`);
        allFindings.push(...findings);
        
        if (deobfuscated !== code) {
            allDeobfuscated.push({ source: `inline#${inlineIdx}`, original: code, deobfuscated });
        }
    }
    
    // 4. Fetch and analyze external JS
    for (const jsUrl of external) {
        console.log(`  [*] Fetching: ${jsUrl}`);
        try {
            const jsResponse = await fetchUrl(jsUrl);
            const jsCode = jsResponse.body;
            const finalJsUrl = jsResponse.finalUrl;
            const fname = safeFilenameFromUrl(finalJsUrl);
            
            // Save original
            fs.writeFileSync(path.join(outputDir, 'js', `original_${fname}`), jsCode);
            
            // Deobfuscate
            const deobfuscated = deobfuscateJS(jsCode);
            const beautified = beautifyJS(deobfuscated);
            fs.writeFileSync(path.join(outputDir, 'js', `clean_${fname}`), beautified);
            
            // Extract secrets
            const findings = extractSecrets(deobfuscated, finalJsUrl);
            allFindings.push(...findings);
            
            if (findings.length > 0) {
                console.log(`  [!] ${findings.length} secrets/interesting patterns in ${fname}`);
            }
            
            if (deobfuscated !== jsCode) {
                allDeobfuscated.push({ source: finalJsUrl, chars: jsCode.length });
                console.log(`  [+] Deobfuscated ${fname} → clean_${fname}`);
            }
            
        } catch (e) {
            console.log(`  [!] Failed: ${jsUrl} (${e.message})`);
        }
    }
    
    // 5. Write findings report
    const report = path.join(outputDir, 'js', 'js_analysis_report.txt');
    let reportContent = `=== JavaScript Analysis Report ===\n`;
    reportContent += `Target: ${targetUrl}\n`;
    reportContent += `Date: ${new Date().toISOString()}\n`;
    reportContent += `JS Files Analyzed: ${external.length} external + ${inlineIdx} inline\n`;
    reportContent += `Findings: ${allFindings.length}\n\n`;
    
    if (allFindings.length > 0) {
        reportContent += `== FINDINGS ==\n\n`;
        
        // Group by type
        const grouped = {};
        for (const f of allFindings) {
            if (!grouped[f.type]) grouped[f.type] = [];
            grouped[f.type].push(f);
        }
        
        for (const [type, items] of Object.entries(grouped)) {
            reportContent += `--- ${type} (${items.length}) ---\n`;
            for (const item of items) {
                reportContent += `  Source: ${item.source}\n`;
                reportContent += `  Value:  ${item.value}\n\n`;
            }
        }
    }
    
    if (allDeobfuscated.length > 0) {
        reportContent += `\n== DEOBFUSCATED FILES ==\n\n`;
        for (const d of allDeobfuscated) {
            reportContent += `  ${d.source}\n`;
        }
    }
    
    fs.writeFileSync(report, reportContent);
    console.log(`\n  [+] Report: ${report}`);
    console.log(`  [+] Total findings: ${allFindings.length}`);
    
    // Print critical findings to stdout
    const critical = allFindings.filter(f => 
        ['API Key', 'AWS Key', 'Secret/Password', 'JWT Token', 'Private Key', 
         'Hardcoded Credentials', 'GitHub Token', 'Slack Token'].includes(f.type)
    );
    if (critical.length > 0) {
        console.log(`\n  [!!!] CRITICAL FINDINGS:`);
        for (const f of critical) {
            console.log(`    → [${f.type}] ${f.value.substring(0, 100)}`);
        }
    }
}

main().catch(e => console.error(`Error: ${e.message}`));
