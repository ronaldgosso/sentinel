// Copy Button Handler for pip install
const copyBtn = document.getElementById('copy-btn');
const copyLabel = document.getElementById('copy-label');

if (copyBtn) {
    copyBtn.addEventListener('click', function() {
        navigator.clipboard.writeText('pip install sentinel-scanner');
        copyLabel.innerText = 'Copied!';
        setTimeout(() => copyLabel.innerText = 'Copy', 2000);
    });
}

// Copy Button Handler for sentinel init --github-action
const copyInitBtn = document.getElementById('copy-init-btn');
if (copyInitBtn) {
    copyInitBtn.addEventListener('click', function() {
        navigator.clipboard.writeText('sentinel init --github-action');
        this.innerText = 'Copied!';
        setTimeout(() => this.innerText = 'Copy', 2000);
    });
}

// Interactive Terminal Typing Animation with Dual-Tier AI & Live Scans
const terminalLines = [
    '<span style="color: #60a5fa;">$ sentinel scan . --ai</span>',
    '<span style="color: #94a3b8;">🔍 Sentinel v1.0.12 – AI-Powered Security Hardening</span>',
    '<span style="color: #eab308;">ℹ️ Using default Sentinel AI key (1.0 req/s pacing).</span>',
    '<span style="color: #38bdf8;">[1/3] SAST: AST analysis of Python & TypeScript...</span>',
    '<span style="color: #ef4444;">🔴 Critical: SQL Injection found in auth/login.py:42</span>',
    '<span style="color: #f59e0b;">🟠 High: Hardcoded Secret found in config/db.py:5</span>',
    '<span style="color: #a855f7;">🤖 AI (Mistral): Evaluating exploit scenarios & fixes...</span>',
    '<span style="color: #10b981;">✅ AI Verified: Attack path confirmed (CWE-89).</span>',
    '<span style="color: #e2e8f0;">Apply auto-hardening fix to auth/login.py? [y/N]: </span><span style="color: #10b981;">y</span>',
    '<span style="color: #10b981;">✨ Applied parameterized query auto-fix successfully!</span>'
];

const terminalElement = document.getElementById('terminal-typing');
let currentLine = 0;

// Cursor animation
const cursorStyle = document.createElement('style');
cursorStyle.innerHTML = `
    @keyframes terminal-blink {
        0%, 100% { opacity: 1; }
        50% { opacity: 0; }
    }
    .terminal-cursor {
        display: inline-block;
        width: 8px;
        height: 15px;
        background-color: var(--accent-cyan, #06b6d4);
        margin-left: 4px;
        vertical-align: middle;
        animation: terminal-blink 1s infinite;
    }
`;
document.head.appendChild(cursorStyle);

function typeLine() {
    if (!terminalElement) return;

    const oldCursor = terminalElement.querySelector('.terminal-cursor');
    if (oldCursor) oldCursor.remove();

    if (currentLine < terminalLines.length) {
        terminalElement.innerHTML += terminalLines[currentLine] + '<br>';
        currentLine++;
        
        if (currentLine < terminalLines.length) {
            terminalElement.innerHTML += '<span class="terminal-cursor"></span>';
        }
        
        let delay = Math.random() * 250 + 120;
        if (currentLine === 1 || currentLine === 8) {
            delay = 700;
        } else if (currentLine === 6) {
            delay = 900; // Simulating AI response time
        }
        
        setTimeout(typeLine, delay);
    }
}

setTimeout(typeLine, 600);

// Interactive Playground Data
const vulnData = {
    sqli: {
        title: "SQL Injection (CWE-89)",
        badge: "OWASP Top 10 — Critical",
        desc: "Concatenating untrusted user inputs directly into SQL query strings, allowing attackers to execute arbitrary database queries.",
        remediation: "Protocol: Parameterized Queries. Replace string concatenation with database driver placeholders (?, %s, :val) and pass variables as parameterized tuples. Never format raw strings into execute().",
        vulnCode: `# Unsafe SQL String Interpolation
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)`,
        fixedCode: `# Safe Parameterized Query (Auto-Fix)
def get_user(username: str):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))`
    },
    xss: {
        title: "Cross-Site Scripting (CWE-79)",
        badge: "OWASP Top 10 — High",
        desc: "Rendering unescaped user inputs directly in HTML templates or browser DOM, permitting malicious JavaScript execution.",
        remediation: "Protocol: Output Encoding & Auto-Escaping. Avoid raw rendering filters like '|safe' or 'dangerouslySetInnerHTML'. Ensure HTML auto-escaping is active or sanitize inputs using DOMPurify / html.escape().",
        vulnCode: `<!-- Unsafe Raw Template Rendering -->
<div class="user-bio">
    <h3>User Profile:</h3>
    <p>{{ user_bio | safe }}</p>
</div>`,
        fixedCode: `<!-- Safe Escaped Rendering (Auto-Fix) -->
<div class="user-bio">
    <h3>User Profile:</h3>
    <p>{{ user_bio | escape }}</p>
</div>`
    },
    cmd: {
        title: "Command Injection (CWE-78)",
        badge: "Critical Exploit Risk",
        desc: "Executing operating system shell commands with user-supplied arguments and shell=True, giving attackers shell execution.",
        remediation: "Protocol: Argument Separation. Set shell=False in subprocess execution calls (run, Popen, check_output). Pass command names and flags as a list of separate strings.",
        vulnCode: `# Unsafe Shell Execution
import subprocess

def ping_host(host_ip):
    return subprocess.run(f"ping -c 1 {host_ip}", shell=True)`,
        fixedCode: `# Safe List-Based Execution (Auto-Fix)
import subprocess

def ping_host(host_ip: str):
    return subprocess.run(["ping", "-c", "1", host_ip], shell=False)`
    },
    secrets: {
        title: "Hardcoded Secrets (CWE-798)",
        badge: "Credential Leak",
        desc: "Storing plain-text API keys, passwords, and private tokens directly inside source code repositories.",
        remediation: "Protocol: Externalized Secrets. Move API keys to local '.env' configuration files added to '.gitignore'. Load credentials dynamically via python-dotenv / os.getenv().",
        vulnCode: `# Hardcoded Plain-Text Key
MISTRAL_API_KEY = "21st_sk_4f88e05a718167041182d13"`,
        fixedCode: `# Secure Environment Variable Loading (Auto-Fix)
import os
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")`
    },
    crypto: {
        title: "Insecure Cryptography (CWE-326)",
        badge: "Weak Cipher Risk",
        desc: "Utilizing broken or collision-vulnerable hash algorithms (MD5, SHA-1) and weak ciphers (DES, RC4).",
        remediation: "Protocol: Modern Cryptographic Standards. Upgrade hash routines to SHA-256 / SHA-3 or bcrypt for passwords. Use authenticated ciphers like AES-GCM or ChaCha20-Poly1305.",
        vulnCode: `# Deprecated Insecure Hashing
import hashlib

def hash_token(token):
    return hashlib.md5(token.encode()).hexdigest()`,
        fixedCode: `# Secure SHA-256 Hashing (Auto-Fix)
import hashlib

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()`
    },
    frontend: {
        title: "Frontend & DOM XSS (CWE-79 & CWE-1022)",
        badge: "Client-Side Security",
        desc: "Un-sanitized DOM injections (dangerouslySetInnerHTML) and un-sandboxed iframe tags enabling clickjacking/XSS.",
        remediation: "Protocol: Client-Side Hardening. Sanitize rich HTML using DOMPurify. Always add sandbox='allow-scripts' to iframes and rel='noopener noreferrer' to external links.",
        vulnCode: `<!-- Unsafe dangerouslySetInnerHTML & Un-sandboxed iframe -->
<div dangerouslySetInnerHTML={{ __html: userInput }} />
<iframe src="https://untrusted-site.com/embed"></iframe>`,
        fixedCode: `<!-- Hardened DOMPurify & Sandboxed iframe (Auto-Fix) -->
import DOMPurify from 'dompurify';

<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />
<iframe sandbox="allow-scripts" src="https://untrusted-site.com/embed"></iframe>`
    }
};

// Playground Interactions
let activeVuln = 'sqli';
const tabs = document.querySelectorAll('.pg-tab');
const fixBtn = document.getElementById('fix-btn');
const blurOverlay = document.getElementById('blur-overlay');
const codeFixed = document.getElementById('code-fixed');

function selectVuln(vulnKey) {
    if (!vulnData[vulnKey]) return;
    activeVuln = vulnKey;
    const data = vulnData[vulnKey];
    
    // Update active tab class & aria-selected
    tabs.forEach(tab => {
        const isCurrent = tab.getAttribute('data-vuln') === vulnKey;
        tab.classList.toggle('active', isCurrent);
        tab.setAttribute('aria-selected', isCurrent ? 'true' : 'false');
    });
    
    // Update texts
    const titleEl = document.getElementById('vuln-title');
    const badgeEl = document.getElementById('vuln-badge');
    const descEl = document.getElementById('vuln-desc');
    const remEl = document.getElementById('vuln-remediation');
    const vulnCodeEl = document.getElementById('code-vuln');
    
    if (titleEl) titleEl.innerText = data.title;
    if (badgeEl) badgeEl.innerText = data.badge;
    if (descEl) descEl.innerText = data.desc;
    if (remEl) remEl.innerText = data.remediation;
    if (vulnCodeEl) vulnCodeEl.innerText = data.vulnCode;
    
    // Reset fixed code state
    if (codeFixed) {
        codeFixed.innerText = "# Click 'Apply AI Auto-Fix' to see secure code";
        codeFixed.classList.remove('fixed-applied');
    }
    if (blurOverlay) {
        blurOverlay.style.display = 'flex';
    }
}

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const key = tab.getAttribute('data-vuln');
        if (key) selectVuln(key);
    });
});

if (fixBtn && blurOverlay && codeFixed) {
    fixBtn.addEventListener('click', () => {
        blurOverlay.style.display = 'none';
        const data = vulnData[activeVuln];
        codeFixed.innerText = data.fixedCode;
        codeFixed.classList.add('fixed-applied');
    });
}
