document.getElementById('copy-btn').addEventListener('click', function() {
    navigator.clipboard.writeText('pip install sentinel-scanner');
    this.innerText = 'Copied!';
    setTimeout(() => this.innerText = 'Copy', 2000);
});

const terminalLines = [
    '<span style="color: #c9d1d9;">$ sentinel scan .</span>',
    '<span style="color: #8b949e;">[+] Starting SAST scan...</span>',
    '<span style="color: #ff7b72;">[!] Found SQL Injection in db.py:42</span>',
    '<span style="color: #8b949e;">[+] Sending finding to Mistral AI...</span>',
    '<span style="color: #00ff41;">[AI] Risk evaluated as HIGH.</span>',
    '<span style="color: #58a6ff;">[AI] Suggestion: Use parameterized query.</span>',
    '<span style="color: #c9d1d9;">Apply auto-fix? [y/N]: y</span>',
    '<span style="color: #3fb950;">[+] Fix applied successfully to db.py.</span>'
];

const terminalElement = document.getElementById('terminal-typing');
let currentLine = 0;

function typeLine() {
    if (currentLine < terminalLines.length) {
        terminalElement.innerHTML += terminalLines[currentLine] + '<br>';
        currentLine++;
        setTimeout(typeLine, Math.random() * 800 + 400);
    }
}

setTimeout(typeLine, 1000);

// Interactive Playground Data
const vulnData = {
    sqli: {
        title: "SQL Injection (CWE-89)",
        desc: "Concatenating untrusted user inputs directly into SQL query strings.",
        remediation: "Protocol: Parameterized Queries. Replace string concatenation or formatting inside SQL executions with placeholders and pass query parameters as a tuple. Example: Change cursor.execute(f'SELECT * FROM users WHERE username = \"{user}\"') to cursor.execute('SELECT * FROM users WHERE username = ?', (user,)).",
        vulnCode: `# Unsafe SQL Construction
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)`,
        fixedCode: `# Safe Parameterized Query
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))`
    },
    xss: {
        title: "Cross-Site Scripting (CWE-79)",
        desc: "Rendering untrusted user inputs in HTML templates or outputs without escaping.",
        remediation: "Protocol: Output Encoding & Context-Aware Escaping. Remove raw rendering filters like '|safe' or 'mark_safe()' for user-controlled inputs. Always HTML-escape variables using template engine auto-escaping (e.g. Jinja/Django default) or escape values explicitly using python's 'html.escape()' module.",
        vulnCode: `<!-- Unsafe Raw Rendering -->
<div>
    <h3>User Comments:</h3>
    <p>{{ user_input | safe }}</p>
</div>`,
        fixedCode: `<!-- Safe Escaped Rendering -->
<div>
    <h3>User Comments:</h3>
    <p>{{ user_input | escape }}</p>
</div>`
    },
    cmd: {
        title: "Command Injection (CWE-78)",
        desc: "Executing OS commands via subprocess calls with dynamic strings and shell=True.",
        remediation: "Protocol: Argument Separation. Set 'shell=False' in subprocess execution calls (such as subprocess.run, call, Popen). Pass commands and arguments as a list of strings rather than a single interpolated command string. Example: Change subprocess.run(f'ping -c 1 {ip}', shell=True) to subprocess.run(['ping', '-c', '1', ip], shell=False).",
        vulnCode: `# Unsafe Shell execution
def ping_host(ip):
    return subprocess.run(f"ping -c 1 {ip}", shell=True)`,
        fixedCode: `# Safe List-based Argument execution
def ping_host(ip):
    return subprocess.run(["ping", "-c", "1", ip], shell=False)`
    },
    secrets: {
        title: "Hardcoded Secrets (CWE-798)",
        desc: "Storing passwords, API tokens, keys, and private credentials directly inside source code.",
        remediation: "Protocol: Externalized Configuration. Remove plain-text credentials, API keys, and tokens from the source code. Save them to a local '.env' file (which must be added to your '.gitignore') and load them dynamically using python-dotenv. Access them via environment variables: os.getenv('VARIABLE_NAME').",
        vulnCode: `# Hardcoded plain-text API Key
API_KEY = "sk-proj-47A1B39D4C2F89"`,
        fixedCode: `# Safe Environment Variable Load
import os
API_KEY = os.getenv("MISTRAL_API_KEY")`
    },
    crypto: {
        title: "Insecure Cryptography (CWE-326)",
        desc: "Utilizing weak or deprecated hashing algorithms (like MD5 or SHA-1) and weak ciphers.",
        remediation: "Protocol: Strong Cryptographic Standards. Replace weak, collision-prone hash algorithms (MD5, SHA-1, SHA-0) with secure hashes (SHA-256, SHA-3, or bcrypt for passwords). For symmetric encryption, replace insecure ciphers (DES, RC4) with AES-GCM (e.g., using python's cryptography package) or ChaCha20-Poly1305.",
        vulnCode: `# Deprecated Insecure Hashing
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()`,
        fixedCode: `# Secure Cryptographic Standard
import hashlib
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()`
    }
};

// Playground interactions
let activeVuln = 'sqli';
const tabs = document.querySelectorAll('.pg-tab');
const fixBtn = document.getElementById('fix-btn');
const blurOverlay = document.getElementById('blur-overlay');
const codeFixed = document.getElementById('code-fixed');

function selectVuln(vulnKey) {
    activeVuln = vulnKey;
    const data = vulnData[vulnKey];
    
    // Update active tab class
    tabs.forEach(tab => {
        if (tab.getAttribute('data-vuln') === vulnKey) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });
    
    // Update texts
    document.getElementById('vuln-title').innerText = data.title;
    document.getElementById('vuln-desc').innerText = data.desc;
    document.getElementById('vuln-remediation').innerText = data.remediation;
    document.getElementById('code-vuln').innerText = data.vulnCode;
    
    // Reset fixed code state
    codeFixed.innerText = "# Click 'Apply Auto-Fix' to see secure code";
    codeFixed.classList.remove('fixed-applied');
    blurOverlay.style.display = 'flex';
}

tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        selectVuln(tab.getAttribute('data-vuln'));
    });
});

fixBtn.addEventListener('click', () => {
    // Hide overlay with a smooth transition
    blurOverlay.style.display = 'none';
    
    // Render fixed code
    const data = vulnData[activeVuln];
    codeFixed.innerText = data.fixedCode;
    codeFixed.classList.add('fixed-applied');
});
