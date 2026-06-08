// ═══════════════════════════════════════════════════════════
//  CYBER DEFENSE SIMULATOR — Main Logic
// ═══════════════════════════════════════════════════════════

'use strict';

// ── DATA ────────────────────────────────────────────────────
// No MITRE codes in option text — all three options look equally authoritative.
// Codes only appear post-answer in the feedback reveal.

const NODE_DATA = [
  {
    id: 'web',
    label: 'Public Website',
    icon: '🌐',
    pos: { x: 50, y: 18 },
    technique: 'T1190 · Exploit Public-Facing Application',
    scenario: 'Automated scanners have detected an unpatched SQL injection vulnerability in the login form. The threat actor is probing authentication endpoints and attempting to dump the user credentials database.',
    question: 'What is the most effective defensive action?',
    options: [
      { text: 'Enforce HTTPS-only access and install an SSL certificate renewal', correct: false, mitreHint: 'M1013 — Software Configuration' },
      { text: 'Deploy a Web Application Firewall with OWASP Core Rule Set exploit protection', correct: true,  mitreHint: 'M1050 — Exploit Protection' },
      { text: 'Isolate the web server to a DMZ and harden OS-level file permissions', correct: false, mitreHint: 'M1030 — Network Segmentation' }
    ],
    mitreId: 'M1050',
    mitreName: 'Exploit Protection',
    feedback: {
      correct: 'A WAF with OWASP CRS rules intercepts and blocks SQLi payloads at the perimeter before they reach the application layer. SSL hardening and DMZ segmentation are valuable hygiene measures but do not address the active exploit in flight.',
      wrong: 'The active threat is an SQL injection attack against the application itself. A WAF (M1050) would have blocked the malicious queries at the perimeter — SSL certificates and network segmentation do not stop injection payloads.'
    }
  },
  {
    id: 'email',
    label: 'Email Gateway',
    icon: '📧',
    pos: { x: 14, y: 32 },
    technique: 'T1566 · Phishing',
    scenario: 'A spear-phishing campaign is underway. Spoofed emails appear to come from the CEO, requesting urgent wire transfers. The threat actor has registered a lookalike domain with no email authentication records.',
    question: 'Which control stops domain spoofing at the protocol level?',
    options: [
      { text: 'Deploy a secure email gateway with sandboxed URL detonation and attachment scanning', correct: false, mitreHint: 'M1021 — Restrict Web-Based Content' },
      { text: 'Enable advanced anti-spam heuristics and block newly-registered domains at the gateway', correct: false, mitreHint: 'M1054 — Software Configuration' },
      { text: 'Publish and enforce SPF, DKIM, and DMARC records with a reject policy on your sending domains', correct: true,  mitreHint: 'M1026 — Privileged Account Management' }
    ],
    mitreId: 'M1026',
    mitreName: 'Privileged Account Management / Sender Auth',
    feedback: {
      correct: 'SPF, DKIM, and DMARC together cryptographically verify the sender\'s domain. A DMARC p=reject policy causes receiving mail servers to silently drop any message that fails authentication — the spoofed CEO emails never arrive.',
      wrong: 'Sandboxing and anti-spam filters catch some threats but cannot cryptographically verify sender identity. Only SPF/DKIM/DMARC (M1026) creates an unforgeable link between the domain\'s DNS records and every outbound message.'
    }
  },
  {
    id: 'workstation',
    label: 'Employee Workstations',
    icon: '💻',
    pos: { x: 82, y: 28 },
    technique: 'T1204 · User Execution',
    scenario: 'A malicious macro-enabled document arrived via a phishing email and was opened by a user. PowerShell is executing encoded commands to establish a reverse shell to a command-and-control server.',
    question: 'What endpoint control would prevent this execution?',
    options: [
      { text: 'Disable Office macros via Group Policy and deploy an endpoint EDR with application whitelisting', correct: true,  mitreHint: 'M1038 — Execution Prevention' },
      { text: 'Isolate the affected workstation from the network and reset the user\'s domain credentials', correct: false, mitreHint: 'M1018 — User Account Management' },
      { text: 'Push an emergency antivirus signature update and initiate a full disk scan on all endpoints', correct: false, mitreHint: 'M1049 — Antivirus/Antimalware' }
    ],
    mitreId: 'M1038',
    mitreName: 'Execution Prevention',
    feedback: {
      correct: 'Disabling macros at the GPO level prevents the initial stage from running. An EDR with application whitelisting then blocks the spawned PowerShell process regardless of obfuscation. This stops the attack at execution — before C2 contact is made.',
      wrong: 'Isolating the machine is incident response, not prevention — the macro already executed. AV signature updates are reactive and often lag novel payloads. Execution Prevention (M1038) stops malicious code before it runs, not after.'
    }
  },
  {
    id: 'database',
    label: 'Database Server',
    icon: '🗄️',
    pos: { x: 50, y: 52 },
    technique: 'T1048 · Exfiltration Over Alt Protocol',
    scenario: 'The database server is communicating with an unknown external IP over port 443. Query logs reveal bulk SELECT statements on the customer PII table. Data exfiltration appears imminent.',
    question: 'Which combination of controls best limits the impact of this exfiltration attempt?',
    options: [
      { text: 'Apply column-level AES-256 encryption to PII fields and enforce strict network micro-segmentation', correct: true,  mitreHint: 'M1030 — Network Segmentation / M1041 — Encrypt Sensitive Information' },
      { text: 'Enable database activity monitoring and alert on anomalous query volume thresholds', correct: false, mitreHint: 'M1047 — Audit' },
      { text: 'Rotate all database service account credentials and enforce certificate-based authentication', correct: false, mitreHint: 'M1026 — Privileged Account Management' }
    ],
    mitreId: 'M1030 + M1041',
    mitreName: 'Network Segmentation + Encrypt Sensitive Information',
    feedback: {
      correct: 'Encryption renders the exfiltrated data worthless even if it reaches the attacker. Micro-segmentation breaks the network path used for exfiltration. Together they address both the channel and the payload — the strongest dual-layer defence here.',
      wrong: 'Activity monitoring (M1047) is detective, not preventive — it alerts after the fact. Credential rotation removes the access vector but doesn\'t protect data already being read by an active session or make intercepted data unreadable.'
    }
  },
  {
    id: 'ad',
    label: 'Active Directory',
    icon: '🏛️',
    pos: { x: 26, y: 55 },
    technique: 'T1078 · Valid Accounts / Credential Stuffing',
    scenario: 'A credential stuffing attack has successfully authenticated as three domain users whose passwords were reused from a previous data breach. Lateral movement across the domain has begun.',
    question: 'What is the single most impactful control to stop this class of attack at scale?',
    options: [
      { text: 'Force an immediate domain-wide password reset and enforce a complexity and length policy', correct: false, mitreHint: 'M1027 — Password Policies' },
      { text: 'Enable phishing-resistant Multi-Factor Authentication across all accounts via Conditional Access', correct: true,  mitreHint: 'M1032 — Multi-Factor Authentication' },
      { text: 'Implement Privileged Access Workstations and tier the Active Directory administrative model', correct: false, mitreHint: 'M1026 — Privileged Account Management' }
    ],
    mitreId: 'M1032',
    mitreName: 'Multi-Factor Authentication',
    feedback: {
      correct: 'MFA means a valid username and password are no longer sufficient — the attacker would also need the physical second factor. Credential stuffing is instantly defeated because the reused passwords provide no usable access.',
      wrong: 'Password resets and complexity rules (M1027) help but users will eventually reuse or leak new passwords too. PAW tiering (M1026) is excellent for admins but doesn\'t protect standard user accounts from credential stuffing at scale.'
    }
  },
  {
    id: 'physical',
    label: 'Physical Security',
    icon: '🏢',
    pos: { x: 74, y: 62 },
    technique: 'T1078.001 · Tailgating / Physical Intrusion',
    scenario: 'CCTV footage shows an unknown individual tailgating an employee through a secure server room door. The intruder has been inside for 4 minutes and is accessing unlocked terminals.',
    question: 'Which physical security control addresses both the entry method and the terminal access?',
    options: [
      { text: 'Install a mantrap airlock with anti-passback enforcement and configure automatic screen lock on all terminals', correct: true,  mitreHint: 'M1022 — Restrict File and Directory Permissions' },
      { text: 'Upgrade CCTV to AI-based facial recognition and trigger security alerts on unrecognised individuals', correct: false, mitreHint: 'M1047 — Audit' },
      { text: 'Issue proximity badge access logs to security staff for daily review and enforce a visitor escort policy', correct: false, mitreHint: 'M1018 — User Account Management' }
    ],
    mitreId: 'M1022',
    mitreName: 'Restrict File and Directory Permissions',
    feedback: {
      correct: 'A mantrap airlock physically prevents a second person entering behind a valid badge holder. Automatic screen lock ensures that even a successful intruder finds terminals locked and unusable — addressing both the intrusion vector and the end goal.',
      wrong: 'CCTV and badge log reviews are detective controls — they record what happened but don\'t prevent tailgating or terminal access. A mantrap (M1022) is a physical preventive control that stops the attack at the door.'
    }
  },
  {
    id: 'human',
    label: 'Human Layer',
    icon: '👥',
    pos: { x: 18, y: 75 },
    technique: 'T1566.001 · Spear Phishing with Link',
    scenario: 'Analysis shows 34% of staff clicked a simulated phishing link last month. An employee just provided VPN credentials to a fraudulent IT support caller who claimed their account would be suspended.',
    question: 'What is the most durable long-term defence against social engineering?',
    options: [
      { text: 'Deploy a Zero Trust architecture requiring continuous identity verification for all resource access', correct: false, mitreHint: 'M1032 — Multi-Factor Authentication' },
      { text: 'Implement mandatory security awareness training with regular simulated phishing and vishing exercises', correct: true,  mitreHint: 'M1017 — User Training' },
      { text: 'Enforce a strict out-of-band verification callback procedure for all IT support credential requests', correct: false, mitreHint: 'M1026 — Privileged Account Management' }
    ],
    mitreId: 'M1017',
    mitreName: 'User Training',
    feedback: {
      correct: 'Ongoing security awareness training (M1017) builds a human firewall that scales across the entire workforce. Simulated exercises create muscle memory so staff recognise and report social engineering before credentials are surrendered.',
      wrong: 'Zero Trust and callback procedures are valuable technical and process controls, but they don\'t address the root cause: users who cannot recognise social engineering. Training (M1017) is the primary defence for the human attack surface.'
    }
  },
  {
    id: 'cloud',
    label: 'Cloud Storage',
    icon: '☁️',
    pos: { x: 50, y: 82 },
    technique: 'T1530 · Data from Cloud Storage Object',
    scenario: 'A misconfigured S3 bucket containing sensitive HR documents has been indexed by a public search engine. An automated scanner has flagged the bucket as publicly accessible with no authentication required.',
    question: 'What is the correct remediation to secure the bucket and prevent recurrence?',
    options: [
      { text: 'Enable server-side encryption on the bucket and rotate the AWS IAM access keys immediately', correct: false, mitreHint: 'M1041 — Encrypt Sensitive Information' },
      { text: 'Enable S3 Block Public Access at the account level, enforce bucket policies, and enable CloudTrail logging', correct: true,  mitreHint: 'M1041 — Encrypt Sensitive Information / M1047 — Audit' },
      { text: 'Migrate the bucket to a private VPC endpoint and restrict access via security group rules', correct: false, mitreHint: 'M1030 — Network Segmentation' }
    ],
    mitreId: 'M1041 + M1047',
    mitreName: 'Encrypt Sensitive Information + Audit',
    feedback: {
      correct: 'S3 Block Public Access is an account-level guardrail that prevents any bucket from becoming public regardless of individual misconfiguration. CloudTrail logging provides an audit trail. This addresses both the immediate exposure and the systemic misconfiguration risk.',
      wrong: 'Encryption protects data if intercepted but doesn\'t close a public bucket. Key rotation is good hygiene but unrelated to the access control issue. VPC endpoints restrict network paths but don\'t stop a bucket that is explicitly set to public — the ACL policy must be corrected directly.'
    }
  },
  {
    id: 'network',
    label: 'Network Router',
    icon: '🔀',
    pos: { x: 82, y: 72 },
    technique: 'T1040 · Network Sniffing',
    scenario: 'An attacker on a compromised switch is performing ARP poisoning. Unencrypted credentials are being captured from legacy HTTP traffic across the network segment.',
    question: 'Which control directly prevents credential capture even if the attacker maintains network access?',
    options: [
      { text: 'Deploy 802.1X port-based Network Access Control to authenticate every device on the segment', correct: false, mitreHint: 'M1032 — Multi-Factor Authentication' },
      { text: 'Enable Dynamic ARP Inspection on managed switches and segment the LAN with private VLANs', correct: false, mitreHint: 'M1030 — Network Segmentation' },
      { text: 'Enforce TLS 1.3 for all internal traffic and enable HSTS to prevent protocol downgrade attacks', correct: true,  mitreHint: 'M1009 — Encrypt Communications' }
    ],
    mitreId: 'M1009',
    mitreName: 'Encrypt Communications',
    feedback: {
      correct: 'TLS 1.3 with HSTS means all intercepted traffic is ciphertext — the attacker captures packets but cannot read credentials because the data is encrypted in transit. This is effective even when the attacker has persistent access to the switch.',
      wrong: 'DAI and VLANs (M1030) disrupt ARP poisoning but are preventive network controls — they don\'t help once the attacker is already on the segment. 802.1X controls device access but not eavesdropping on permitted devices. Encryption (M1009) makes captured data worthless regardless of access method.'
    }
  },
  {
    id: 'cicd',
    label: 'CI/CD Pipeline',
    icon: '⚙️',
    pos: { x: 31, y: 20 },
    technique: 'T1195.002 · Compromise Software Supply Chain',
    scenario: 'A malicious pull request has introduced a typosquatted dependency. The package contains a credential harvester that will deploy to production on the next build.',
    question: 'Which DevSecOps control catches malicious dependencies automatically before they deploy?',
    options: [
      { text: 'Require two-person code review approval on all pull requests affecting dependency files', correct: false, mitreHint: 'M1047 — Audit' },
      { text: 'Integrate Software Composition Analysis with dependency pinning and cryptographic hash verification in CI', correct: true,  mitreHint: 'M1016 — Vulnerability Scanning' },
      { text: 'Run the build in an ephemeral sandboxed environment and diff the filesystem against a known-good baseline', correct: false, mitreHint: 'M1048 — Application Isolation and Sandboxing' }
    ],
    mitreId: 'M1016',
    mitreName: 'Vulnerability Scanning / SCA',
    feedback: {
      correct: 'SCA automatically checks every dependency against databases of known-malicious and typosquatted packages. Pinning with hash verification ensures the exact approved version is fetched — any substitution fails the build before it ever reaches production.',
      wrong: 'Manual review (M1047) doesn\'t scale to every transitive dependency and misses sophisticated typosquatting. Sandboxed diffing is detective — it runs the malicious code first. SCA (M1016) blocks the threat at the package resolution stage, before execution.'
    }
  },
  {
    id: 'mobile',
    label: 'Mobile Devices',
    icon: '📱',
    pos: { x: 68, y: 18 },
    technique: 'T1416 · Mobile — URI Hijacking',
    scenario: 'Company iPhones have been targeted via a fake "security update" SMS distributing a malicious MDM profile. The profile grants remote access and can intercept 2FA SMS tokens.',
    question: 'What is the primary mobile security control to detect and remediate this attack?',
    options: [
      { text: 'Enforce a Mobile Application Management policy blocking sideloaded apps and untrusted app stores', correct: false, mitreHint: 'M1006 — Use Recent OS Version' },
      { text: 'Deploy a corporate MDM solution with device compliance enforcement to automatically quarantine non-compliant devices', correct: true,  mitreHint: 'M1006 — Use Recent OS Version / M1051 — Update Software' },
      { text: 'Require certificate-based VPN authentication for all mobile access to corporate resources', correct: false, mitreHint: 'M1032 — Multi-Factor Authentication' }
    ],
    mitreId: 'M1006 + M1051',
    mitreName: 'Use Recent OS Version / Update Software',
    feedback: {
      correct: 'A corporate MDM can detect unauthorised configuration profiles, enforce compliance policies, and remotely remove malicious MDM profiles from enrolled devices — directly remediating the attack. Compliance enforcement ensures devices that fail checks are quarantined automatically.',
      wrong: 'MAM policies and VPN certificate auth are access controls, not detection/remediation mechanisms. Once a malicious MDM profile is installed, only a management platform with visibility into device configuration can detect and remove it (M1006/M1051).'
    }
  },
  {
    id: 'vendor',
    label: 'Third-Party Vendor API',
    icon: '🔌',
    pos: { x: 31, y: 85 },
    technique: 'T1199 · Trusted Relationship',
    scenario: 'A third-party vendor\'s API key — with write access to 80,000 customer records in your CRM — has been exfiltrated and is actively exporting your customer database.',
    question: 'Which vendor access control best limits the blast radius of this compromise?',
    options: [
      { text: 'Immediately revoke the compromised API key and issue a replacement with the same permission scope', correct: false, mitreHint: 'M1026 — Privileged Account Management' },
      { text: 'Enforce OAuth 2.0 with short-lived scoped tokens, least-privilege access, and API gateway anomaly logging', correct: true,  mitreHint: 'M1018 — User Account Management' },
      { text: 'Require the vendor to conduct a penetration test and supply an updated security attestation', correct: false, mitreHint: 'M1016 — Vulnerability Scanning' }
    ],
    mitreId: 'M1018',
    mitreName: 'User Account Management',
    feedback: {
      correct: 'Least-privilege OAuth scopes mean a compromised token can only access what the vendor strictly needs — not 80,000 records. Short-lived tokens expire quickly, limiting the attack window. API gateway logging provides real-time anomaly detection to catch bulk exports as they happen.',
      wrong: 'Revoking and reissuing a key with the same permissions fixes the immediate credential but doesn\'t reduce future blast radius. Pen tests are periodic assessments, not runtime controls. Principle of least privilege (M1018) limits what any single compromised credential can access.'
    }
  }
];

// Connections between nodes (pairs of node IDs)
const CONNECTIONS = [
  ['web', 'email'], ['web', 'workstation'], ['web', 'database'],
  ['email', 'human'], ['email', 'workstation'],
  ['workstation', 'ad'], ['workstation', 'database'],
  ['ad', 'database'], ['ad', 'human'], ['ad', 'cicd'],
  ['database', 'cloud'], ['database', 'vendor'],
  ['cloud', 'network'], ['cloud', 'vendor'],
  ['network', 'physical'], ['network', 'mobile'],
  ['physical', 'human'],
  ['cicd', 'vendor'], ['cicd', 'web'],
  ['mobile', 'vendor'], ['mobile', 'email'],
  ['human', 'vendor']
];

// ── STATE ────────────────────────────────────────────────────

const state = {
  nodeStates: {},
  health: 5,
  maxHealth: 5,
  secured: 0,
  compromised: 0,
  currentAttackNode: null,
  spriteTargetPos: { x: 50, y: 50 },
  modalOpen: false,
  answered: false,
  running: false
};

// ── DOM REFS ─────────────────────────────────────────────────

const dom = {
  map: document.getElementById('map'),
  svg: document.getElementById('svg-connections'),
  sprite: document.getElementById('sprite'),
  securedVal: document.getElementById('secured-val'),
  compromisedVal: document.getElementById('compromised-val'),
  healthVal: document.getElementById('health-val'),
  healthFill: document.getElementById('health-fill'),
  modalOverlay: document.getElementById('modal-overlay'),
  modalNodeIcon: document.getElementById('modal-node-icon'),
  modalNodeName: document.getElementById('modal-node-name'),
  modalTechnique: document.getElementById('modal-technique'),
  modalScenario: document.getElementById('modal-scenario'),
  modalQuestion: document.getElementById('modal-question'),
  modalOptions: document.getElementById('modal-options'),
  modalFeedback: document.getElementById('modal-feedback'),
  modalMitre: document.getElementById('modal-mitre-tag'),
  modalContinue: document.getElementById('modal-continue-btn'),
  logEntries: document.getElementById('log-entries'),
  endScreen: document.getElementById('end-screen'),
  endTitle: document.getElementById('end-title'),
  endSubtitle: document.getElementById('end-subtitle'),
  endScore: document.getElementById('end-score'),
  intro: document.getElementById('intro'),
  startBtn: document.getElementById('start-btn'),
  restartBtn: document.getElementById('restart-btn')
};

// ── UTILS ────────────────────────────────────────────────────

function addLog(msg, type = '') {
  const el = document.createElement('div');
  el.className = `log-entry ${type}`;
  const time = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  el.textContent = `[${time}] ${msg}`;
  dom.logEntries.prepend(el);
  while (dom.logEntries.children.length > 20) dom.logEntries.removeChild(dom.logEntries.lastChild);
}

function spawnParticles(x, y, color, count = 8) {
  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    const angle = (i / count) * Math.PI * 2;
    const dist = 30 + Math.random() * 40;
    p.style.cssText = `
      left:${x}px;top:${y}px;
      width:${3+Math.random()*4}px;height:${3+Math.random()*4}px;
      background:${color};box-shadow:0 0 4px ${color};
      --tx:${Math.cos(angle)*dist}px;--ty:${Math.sin(angle)*dist}px;
      position:fixed;z-index:999;
      animation-duration:${0.4+Math.random()*0.4}s;
    `;
    document.body.appendChild(p);
    setTimeout(() => p.remove(), 800);
  }
}

// ── DRAWING ──────────────────────────────────────────────────

function drawConnections() {
  dom.svg.innerHTML = '';
  const map = dom.map.getBoundingClientRect();
  CONNECTIONS.forEach(([aId, bId]) => {
    const a = NODE_DATA.find(n => n.id === aId);
    const b = NODE_DATA.find(n => n.id === bId);
    if (!a || !b) return;
    const ax = (a.pos.x/100)*map.width,  ay = (a.pos.y/100)*map.height;
    const bx = (b.pos.x/100)*map.width,  by = (b.pos.y/100)*map.height;
    const isActive = state.currentAttackNode === aId || state.currentAttackNode === bId;
    const line = document.createElementNS('http://www.w3.org/2000/svg','path');
    const mx = (ax+bx)/2 + (by-ay)*0.1;
    const my = (ay+by)/2 + (ax-bx)*0.1;
    line.setAttribute('d', `M ${ax} ${ay} Q ${mx} ${my} ${bx} ${by}`);
    line.setAttribute('class', `connection-line${isActive ? ' active' : ''}`);
    dom.svg.appendChild(line);
  });
}

// ── SPRITE ───────────────────────────────────────────────────

function positionSprite(xPct, yPct, animate = true) {
  const map = dom.map.getBoundingClientRect();
  dom.sprite.style.transition = animate
    ? 'left 0.8s cubic-bezier(0.4,0,0.2,1), top 0.8s cubic-bezier(0.4,0,0.2,1)'
    : 'none';
  dom.sprite.style.left = (xPct/100)*map.width  + 'px';
  dom.sprite.style.top  = (yPct/100)*map.height + 'px';
}

function moveSpriteTo(nodeId) {
  const node = NODE_DATA.find(n => n.id === nodeId);
  if (!node) return;
  state.spriteTargetPos = { x: node.pos.x, y: node.pos.y };
  positionSprite(node.pos.x, node.pos.y, true);
}

// ── NODE DOM ─────────────────────────────────────────────────

function createNodeElements() {
  NODE_DATA.forEach(node => {
    const el = document.createElement('div');
    el.className = 'node idle';
    el.id = `node-${node.id}`;
    el.style.left = node.pos.x + '%';
    el.style.top  = node.pos.y + '%';
    el.innerHTML = `<div class="node-inner"><div class="node-icon">${node.icon}</div><div class="node-label">${node.label}</div></div>`;
    el.addEventListener('click', () => onNodeClick(node.id));
    dom.map.appendChild(el);
    state.nodeStates[node.id] = 'idle';
  });
}

function setNodeState(nodeId, newState) {
  state.nodeStates[nodeId] = newState;
  const el = document.getElementById(`node-${nodeId}`);
  if (el) el.className = `node ${newState}`;
}

// ── ATTACK LOGIC ─────────────────────────────────────────────

function getAttackableNodes() {
  return NODE_DATA.filter(n => state.nodeStates[n.id] === 'idle').map(n => n.id);
}

function launchNextAttack() {
  if (!state.running || state.modalOpen) return;
  const targets = getAttackableNodes();
  if (targets.length === 0) { triggerVictory(); return; }

  const targetId = targets[Math.floor(Math.random() * targets.length)];
  state.currentAttackNode = targetId;
  const node = NODE_DATA.find(n => n.id === targetId);
  addLog(`INTRUSION DETECTED → ${node.label}`, 'attack');
  moveSpriteTo(targetId);
  drawConnections();

  setTimeout(() => {
    if (!state.running) return;
    setNodeState(targetId, 'under-attack');
    drawConnections();
    const nodeEl = document.getElementById(`node-${targetId}`);
    if (nodeEl) {
      nodeEl._autoCompromise = setTimeout(() => {
        if (state.nodeStates[targetId] === 'under-attack') {
          compromiseNode(targetId);
          scheduleNextAttack();
        }
      }, 7000);
    }
  }, 900);
}

function scheduleNextAttack() {
  if (!state.running) return;
  clearTimeout(state._nextAttackTimer);
  state._nextAttackTimer = setTimeout(launchNextAttack, 2500);
}

function compromiseNode(nodeId) {
  if (state.nodeStates[nodeId] !== 'under-attack') return;
  const node = NODE_DATA.find(n => n.id === nodeId);
  setNodeState(nodeId, 'compromised');
  state.compromised++;
  state.health = Math.max(0, state.health - 1);
  dom.map.style.transform = 'translateX(-3px)';
  setTimeout(() => { dom.map.style.transform = 'translateX(3px)'; }, 80);
  setTimeout(() => { dom.map.style.transform = ''; }, 160);
  const nodeEl = document.getElementById(`node-${nodeId}`);
  if (nodeEl) {
    const r = nodeEl.getBoundingClientRect();
    spawnParticles(r.left + r.width/2, r.top + r.height/2, '#ff2244', 10);
  }
  addLog(`SYSTEM COMPROMISED: ${node.label} — health -1`, 'breach');
  updateHUD();
  if (state.health <= 0) triggerGameOver();
}

// ── NODE CLICK ───────────────────────────────────────────────

function onNodeClick(nodeId) {
  if (!state.running || state.modalOpen) return;
  if (state.nodeStates[nodeId] !== 'under-attack') return;
  const nodeEl = document.getElementById(`node-${nodeId}`);
  if (nodeEl && nodeEl._autoCompromise) {
    clearTimeout(nodeEl._autoCompromise);
    nodeEl._autoCompromise = null;
  }
  openModal(nodeId);
}

// ── MODAL ────────────────────────────────────────────────────

function openModal(nodeId) {
  const node = NODE_DATA.find(n => n.id === nodeId);
  if (!node) return;

  state.modalOpen = true;
  state.answered  = false;
  state._activeModalNode = nodeId;

  dom.modalNodeIcon.textContent  = node.icon;
  dom.modalNodeName.textContent  = node.label;
  dom.modalTechnique.textContent = node.technique;
  dom.modalScenario.textContent  = node.scenario;
  dom.modalQuestion.textContent  = node.question;
  dom.modalFeedback.className    = 'modal-feedback';
  dom.modalFeedback.innerHTML    = '';
  dom.modalMitre.className       = 'modal-mitre-tag';
  dom.modalContinue.className    = 'modal-continue-btn';

  // Shuffle and render — NO codes visible yet
  const shuffled = [...node.options].sort(() => Math.random() - 0.5);
  dom.modalOptions.innerHTML = '';
  shuffled.forEach((opt, i) => {
    const btn = document.createElement('button');
    btn.className = 'option-btn';
    btn.dataset.correct = opt.correct;
    btn.dataset.mitreHint = opt.mitreHint || '';
    // Just a neutral letter key, plain text — no codes
    btn.innerHTML = `<span class="option-key">${['A','B','C'][i]}</span><span class="option-text">${opt.text}</span>`;
    btn.addEventListener('click', () => onOptionClick(btn, opt, node, shuffled));
    dom.modalOptions.appendChild(btn);
  });

  dom.modalOverlay.classList.add('active');
}

function onOptionClick(btn, opt, node, allOptions) {
  if (state.answered) return;
  state.answered = true;

  // Lock all buttons and reveal MITRE codes on every option
  Array.from(dom.modalOptions.children).forEach(b => {
    b.style.pointerEvents = 'none';
    const hint = b.dataset.mitreHint;
    if (hint) {
      const tag = document.createElement('span');
      tag.className = 'option-mitre-reveal';
      tag.textContent = hint;
      b.appendChild(tag);
    }
    if (b.dataset.correct === 'true') b.classList.add('correct');
  });

  if (opt.correct) {
    btn.classList.add('correct');
    secureNode(state._activeModalNode);
    dom.modalFeedback.innerHTML = `<strong>✓ CORRECT MITIGATION</strong><br><br>${node.feedback.correct}`;
    dom.modalFeedback.className = 'modal-feedback show correct-fb';
  } else {
    btn.classList.add('wrong');
    compromiseNode(state._activeModalNode);
    dom.modalFeedback.innerHTML = `<strong>✗ INEFFECTIVE RESPONSE</strong><br><br>${node.feedback.wrong}`;
    dom.modalFeedback.className = 'modal-feedback show wrong-fb';
  }

  dom.modalMitre.innerHTML = `<span class="mitre-label">MITRE ATT&CK MAPPING</span> ${node.mitreId} · ${node.mitreName}`;
  dom.modalMitre.className = 'modal-mitre-tag show';
  dom.modalContinue.className = 'modal-continue-btn show';
}

function closeModal() {
  dom.modalOverlay.classList.remove('active');
  state.modalOpen = false;
  state._activeModalNode = null;
  if (state.health > 0) scheduleNextAttack();
}

// ── SECURE NODE ──────────────────────────────────────────────

function secureNode(nodeId) {
  setNodeState(nodeId, 'secured');
  state.secured++;
  state.currentAttackNode = null;
  const node = NODE_DATA.find(n => n.id === nodeId);
  addLog(`DEFENDED: ${node.label} [${node.mitreId}]`, 'defend');
  updateHUD();
  drawConnections();
  positionSprite(50, 50, true);

  const all = NODE_DATA.length;
  const done = NODE_DATA.filter(n => state.nodeStates[n.id] === 'secured' || state.nodeStates[n.id] === 'compromised').length;
  if (done === all) setTimeout(() => triggerVictory(), 800);
}

// ── HUD ──────────────────────────────────────────────────────

function updateHUD() {
  dom.securedVal.textContent    = state.secured;
  dom.compromisedVal.textContent = state.compromised;
  dom.healthVal.textContent     = state.health;
  const pct = (state.health / state.maxHealth) * 100;
  dom.healthFill.style.width = pct + '%';
  if (pct <= 40) {
    dom.healthFill.style.background = 'linear-gradient(90deg,#ff2244,#ff5566)';
    dom.healthFill.style.boxShadow  = '0 0 8px #ff2244';
  } else {
    dom.healthFill.style.background = 'linear-gradient(90deg,#ffaa00,#ffcc44)';
    dom.healthFill.style.boxShadow  = '0 0 8px #ffaa00';
  }
}

// ── END STATES ───────────────────────────────────────────────

function triggerGameOver() {
  state.running = false;
  clearTimeout(state._nextAttackTimer);
  setTimeout(() => {
    dom.endTitle.textContent    = 'SYSTEM BREACH';
    dom.endTitle.className      = 'lose';
    dom.endSubtitle.textContent = 'Critical system health failure. The threat actor has achieved persistent access across your infrastructure. Incident response required.';
    dom.endScore.textContent    = `Secured: ${state.secured}  ·  Compromised: ${state.compromised}`;
    dom.endScreen.classList.add('show');
    addLog('CRITICAL FAILURE — GAME OVER', 'breach');
  }, 600);
}

function triggerVictory() {
  state.running = false;
  clearTimeout(state._nextAttackTimer);
  setTimeout(() => {
    dom.endTitle.textContent    = 'NETWORK SECURED';
    dom.endTitle.className      = 'win';
    dom.endSubtitle.textContent = 'All attack vectors have been addressed. The threat actor has been repelled. Your security posture is significantly improved.';
    dom.endScore.textContent    = `Secured: ${state.secured}  ·  Compromised: ${state.compromised}  ·  Health: ${state.health}/${state.maxHealth}`;
    dom.endScreen.classList.add('show');
    addLog('MISSION COMPLETE — ALL NODES ASSESSED', 'defend');
  }, 600);
}

// ── GAME INIT ────────────────────────────────────────────────

function initGame() {
  state.health = state.maxHealth;
  state.secured = state.compromised = 0;
  state.currentAttackNode = state._activeModalNode = null;
  state.modalOpen = state.answered = state.running = false;
  state.nodeStates = {};
  document.querySelectorAll('.node').forEach(el => el.remove());
  dom.svg.innerHTML = '';
  dom.logEntries.innerHTML = '';
  dom.endScreen.classList.remove('show');
  positionSprite(50, 50, false);
  createNodeElements();
  drawConnections();
  updateHUD();
  addLog('SYSTEM ONLINE — NETWORK MONITORING ACTIVE', '');
  addLog('THREAT ACTOR DETECTED ON NETWORK PERIMETER', 'attack');
}

function startGame() {
  state.running = true;
  scheduleNextAttack();
}

// ── RESIZE ───────────────────────────────────────────────────

let _resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(() => {
    drawConnections();
    if (state.spriteTargetPos) positionSprite(state.spriteTargetPos.x, state.spriteTargetPos.y, false);
  }, 100);
});

// ── EVENTS ───────────────────────────────────────────────────

dom.startBtn.addEventListener('click', () => {
  dom.intro.classList.add('hidden');
  setTimeout(() => { dom.intro.style.display = 'none'; startGame(); }, 600);
});
dom.restartBtn.addEventListener('click', () => {
  dom.endScreen.classList.remove('show');
  initGame();
  setTimeout(startGame, 300);
});
dom.modalContinue.addEventListener('click', closeModal);

// ── BOOT ─────────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', initGame);
