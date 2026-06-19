document.getElementById('copy-btn').addEventListener('click', function() {
    navigator.clipboard.writeText('pip install sentinel-security');
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
