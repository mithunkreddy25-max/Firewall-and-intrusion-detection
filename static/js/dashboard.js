// ==========================================================================
// CAMPUS SECURE: SOC Dashboard Telemetry, Topology & Interactive Charts
// ==========================================================================

let network = null;
let trafficChart = null;
let attackChart = null;
let autoSimInterval = null;
let edgeOriginalColors = {};
let allEventsCache = [];

const eventsTableBody = document.querySelector('#events-table tbody');
const networkContainer = document.getElementById('network-graph');
const dossierModal = document.getElementById('dossier-modal');

// ---------------- LIVE TELEMETRY & STATS ----------------

async function fetchStats() {
    try {
        const resp = await fetch('/api/stats');
        const stats = await resp.json();

        // Update Metric Cards
        const totalElem = document.getElementById('stat-total-traffic');
        if (totalElem) totalElem.textContent = stats.total_traffic.toLocaleString();

        const allowedElem = document.getElementById('stat-allowed-count');
        if (allowedElem) allowedElem.textContent = stats.allowed_count.toLocaleString();

        const allowedPct = document.getElementById('stat-allowed-pct');
        if (allowedPct) allowedPct.textContent = `${stats.allowed_pct}%`;

        const blockedElem = document.getElementById('stat-blocked-count');
        if (blockedElem) blockedElem.textContent = stats.blocked_count.toLocaleString();

        const blockedPct = document.getElementById('stat-blocked-pct');
        if (blockedPct) blockedPct.textContent = `${stats.blocked_pct}%`;

        const alertsElem = document.getElementById('stat-alerts-count');
        if (alertsElem) alertsElem.textContent = stats.alerts_count.toLocaleString();

        // Threat Level Beacon
        const threatElem = document.getElementById('threat-level-badge');
        if (threatElem) {
            threatElem.className = `threat-indicator ${stats.threat_class}`;
            threatElem.innerHTML = `<span class="beacon"></span> Threat Level: <strong>${stats.threat_level}</strong>`;
        }

        const activeRulesElem = document.getElementById('stat-active-rules');
        if (activeRulesElem) activeRulesElem.textContent = stats.active_rules_count;

        // Update Charts
        updateCharts(stats);

    } catch (err) {
        console.error("Error updating stats:", err);
    }
}

// ---------------- CHART.JS VISUALIZATIONS ----------------

function initCharts() {
    const trafficCtx = document.getElementById('trafficTimelineChart');
    if (trafficCtx) {
        trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Allowed Packets',
                        data: [],
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3
                    },
                    {
                        label: 'Blocked Packets',
                        data: [],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        pointRadius: 3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } } },
                    tooltip: { backgroundColor: '#111827', titleColor: '#38bdf8', borderColor: '#334155', borderWidth: 1 }
                },
                scales: {
                    x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
                    y: { beginAtZero: true, ticks: { color: '#64748b', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.04)' } }
                }
            }
        });
    }

    const attackCtx = document.getElementById('attackDistributionChart');
    if (attackCtx) {
        attackChart = new Chart(attackCtx, {
            type: 'doughnut',
            data: {
                labels: ['Port Scan', 'SSH Brute Force', 'Web Attacks', 'DMZ Lateral', 'Admin Breach', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: ['#38bdf8', '#f59e0b', '#10b981', '#ef4444', '#a855f7', '#64748b'],
                    borderWidth: 1,
                    borderColor: '#111827'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Inter', size: 10 }, boxWidth: 12 } },
                    tooltip: { backgroundColor: '#111827', titleColor: '#fff', borderColor: '#334155', borderWidth: 1 }
                },
                cutout: '68%'
            }
        });
    }
}

function updateCharts(stats) {
    if (trafficChart && stats.timeline) {
        const labels = stats.timeline.map(t => t.time);
        // Compute running allowed/blocked counts
        let allowedRun = 0, blockedRun = 0;
        const allowedPoints = [];
        const blockedPoints = [];

        stats.timeline.forEach(t => {
            const isAllow = (t.decision || '').toLowerCase() === 'allow';
            if (isAllow) allowedRun++;
            else blockedRun++;
            allowedPoints.push(allowedRun);
            blockedPoints.push(blockedRun);
        });

        trafficChart.data.labels = labels;
        trafficChart.data.datasets[0].data = allowedPoints;
        trafficChart.data.datasets[1].data = blockedPoints;
        trafficChart.update('none');
    }

    if (attackChart && stats.attack_distribution) {
        const dist = stats.attack_distribution;
        const labels = Object.keys(dist);
        const data = Object.values(dist);

        if (labels.length > 0) {
            attackChart.data.labels = labels;
            attackChart.data.datasets[0].data = data;
        } else {
            attackChart.data.labels = ['No Active Attacks'];
            attackChart.data.datasets[0].data = [1];
        }
        attackChart.update('none');
    }
}

// ---------------- EVENTS TABLE & SEARCH/FILTER ----------------

async function loadEvents() {
    try {
        const resp = await fetch('/api/events?limit=100');
        const events = await resp.json();
        allEventsCache = events;
        renderFilteredEvents();
    } catch (e) {
        console.error('Error loading events:', e);
    }
}

function renderFilteredEvents() {
    const searchVal = (document.getElementById('event-search-input')?.value || '').toLowerCase().trim();
    const severityVal = (document.getElementById('severity-filter-select')?.value || 'ALL').toUpperCase();
    const decisionVal = (document.getElementById('decision-filter-select')?.value || 'ALL').toUpperCase();

    const filtered = allEventsCache.filter(ev => {
        // Search filter
        if (searchVal) {
            const matchStr = `${ev.source} ${ev.destination} ${ev.port} ${ev.protocol} ${ev.decision} ${ev.reason || ''} ${(ev.alerts || []).join(' ')}`.toLowerCase();
            if (!matchStr.includes(searchVal)) return false;
        }
        // Severity filter
        if (severityVal !== 'ALL') {
            if ((ev.severity || 'LOW').toUpperCase() !== severityVal) return false;
        }
        // Decision filter
        if (decisionVal !== 'ALL') {
            const isAllowed = (ev.decision || '').toLowerCase() === 'allow' || (ev.decision || '').toLowerCase() === 'allowed';
            if (decisionVal === 'ALLOWED' && !isAllowed) return false;
            if (decisionVal === 'BLOCKED' && isAllowed) return false;
        }
        return true;
    });

    eventsTableBody.innerHTML = '';

    if (filtered.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="8" style="text-align: center; color: #64748b; padding: 2rem;">No security events match your filter criteria.</td>`;
        eventsTableBody.appendChild(tr);
        return;
    }

    filtered.forEach(ev => {
        const tr = document.createElement('tr');
        const isAllowed = (ev.decision || '').toLowerCase() === 'allow' || (ev.decision || '').toLowerCase() === 'allowed';
        const decisionClass = isAllowed ? 'badge-allowed' : 'badge-blocked';
        const decisionLabel = isAllowed ? 'ALLOWED' : 'BLOCKED';

        // Severity badge
        const sev = (ev.severity || 'LOW').toUpperCase();
        let sevClass = 'badge-low';
        if (sev === 'CRITICAL') sevClass = 'badge-critical';
        else if (sev === 'HIGH') sevClass = 'badge-high';
        else if (sev === 'MEDIUM') sevClass = 'badge-med';
        else if (sev === 'SAFE') sevClass = 'badge-safe';

        const alertsHtml = ev.alerts && ev.alerts.length
            ? ev.alerts.map(a => `<span class="badge-alert">${a}</span>`).join(' ')
            : '<span style="color:#64748b;">—</span>';

        const timeStr = ev.timestamp ? (ev.timestamp.includes('T') ? ev.timestamp.replace('T', ' ').substring(0, 19) : ev.timestamp) : '—';

        tr.innerHTML = `
            <td class="mono" style="color:#94a3b8; font-size: 0.78rem;">${timeStr}</td>
            <td><span class="zone-tag">${ev.source}</span></td>
            <td><span class="zone-tag">${ev.destination}</span></td>
            <td class="mono" style="color:#38bdf8;">${ev.port}</td>
            <td class="mono" style="font-weight:700;">${(ev.protocol || '').toUpperCase()}</td>
            <td><span class="${decisionClass}">${decisionLabel}</span></td>
            <td><span class="${sevClass}">${sev}</span></td>
            <td>${alertsHtml}</td>
        `;

        // Click row to open Event Dossier Modal
        tr.addEventListener('click', () => openEventDossier(ev));
        eventsTableBody.appendChild(tr);
    });
}

// ---------------- EVENT DOSSIER MODAL ----------------

function openEventDossier(ev) {
    if (!dossierModal) return;

    const isAllowed = (ev.decision || '').toLowerCase() === 'allow' || (ev.decision || '').toLowerCase() === 'allowed';

    document.getElementById('modal-event-id').textContent = ev.id || 'N/A';
    document.getElementById('modal-timestamp').textContent = ev.timestamp || 'N/A';
    document.getElementById('modal-source').textContent = `${ev.source} (${getZoneSubnet(ev.source)})`;
    document.getElementById('modal-destination').textContent = `${ev.destination} (${getZoneSubnet(ev.destination)})`;
    document.getElementById('modal-port-proto').textContent = `Port ${ev.port} / ${(ev.protocol || 'TCP').toUpperCase()}`;

    const decSpan = document.getElementById('modal-decision');
    decSpan.textContent = isAllowed ? 'ALLOWED' : 'BLOCKED';
    decSpan.className = isAllowed ? 'badge-allowed' : 'badge-blocked';

    document.getElementById('modal-rule-reason').textContent = ev.reason || 'Standard Firewall Policy Enforcement';

    const sevSpan = document.getElementById('modal-severity');
    const sev = (ev.severity || 'LOW').toUpperCase();
    sevSpan.textContent = sev;
    sevSpan.className = sev === 'CRITICAL' ? 'badge-critical' : (sev === 'HIGH' ? 'badge-high' : (sev === 'MEDIUM' ? 'badge-med' : 'badge-low'));

    const alertsBox = document.getElementById('modal-alerts');
    if (ev.alerts && ev.alerts.length > 0) {
        alertsBox.innerHTML = ev.alerts.map(a => `<div class="badge-alert" style="margin-bottom: 4px; display:inline-block;">${a}</div>`).join(' ');
    } else {
        alertsBox.innerHTML = '<span style="color:#94a3b8;">No IDS security anomaly triggered for this event.</span>';
    }

    // Recommendation Advice
    const recBox = document.getElementById('modal-recommendation');
    recBox.textContent = getSOCRecommendation(ev);

    dossierModal.classList.add('active');
}

function closeDossier() {
    if (dossierModal) dossierModal.classList.remove('active');
}

function getZoneSubnet(zone) {
    const subnets = {
        "Student Lab": "10.10.10.0/24",
        "Faculty": "10.10.20.0/24",
        "Administration": "10.10.30.0/24",
        "Public Web Server / DMZ": "10.10.40.0/24"
    };
    return subnets[zone] || "Subnet Unknown";
}

function getSOCRecommendation(ev) {
    const alerts = (ev.alerts || []).join(' ');
    if (alerts.includes('DMZ to Internal')) {
        return "CRITICAL: Potential DMZ compromise or lateral movement. Immediately isolate the public DMZ web instance, inspect reverse shell processes, and audit host credentials.";
    }
    if (alerts.includes('Restricted Administration Zone')) {
        return "HIGH: Unauthorized student access attempt to administrative systems. Verify physical student station, check for network segmentation bypass or ARP poisoning.";
    }
    if (alerts.includes('SSH Scan') || alerts.includes('RDP Brute Force')) {
        return "ELEVATED: Repeated brute-force authentication attempts detected. Enforce multi-factor authentication (MFA), trigger fail2ban rate limiting, or restrict management ports to dedicated VPN.";
    }
    if (alerts.includes('Port Scan')) {
        return "ELEVATED: Active host reconnaissance detected. Block source IP at the perimeter and inspect host for automated vulnerability scanning tools (e.g. Nmap).";
    }
    if (alerts.includes('Web Application Exploit')) {
        return "HIGH: Malicious payload targeting web application. Inspect WAF logs, review input validation on web endpoints, and patch exposed CMS/API vulnerabilities.";
    }
    if ((ev.decision || '').toLowerCase() === 'deny') {
        return "NORMAL: Traffic was correctly blocked by Zero-Trust inter-zone firewall policy. No immediate analyst intervention required.";
    }
    return "SAFE: Traffic matched authorized college network security policy. Connection allowed through normal inspection.";
}

// ---------------- VIS.JS NETWORK TOPOLOGY ----------------

async function initTopology() {
    try {
        const resp = await fetch('/api/topology');
        const payload = await resp.json();
        const zones = payload.zones || payload;

        const nodes = [];
        const edges = [];
        let id = 1;
        const zoneIds = {};

        // Color definitions per zone
        const zoneColors = {
            "Student Lab": { bg: '#1e3a8a', border: '#3b82f6' },
            "Faculty": { bg: '#3b0764', border: '#a855f7' },
            "Administration": { bg: '#4c0519', border: '#f43f5e' },
            "Public Web Server / DMZ": { bg: '#064e3b', border: '#10b981' }
        };

        for (const [name, subnet] of Object.entries(zones)) {
            zoneIds[name] = id;
            const c = zoneColors[name] || { bg: '#1e293b', border: '#64b5f6' };
            nodes.push({
                id,
                label: `🛡️ ${name}\n${subnet}`,
                shape: 'box',
                margin: 10,
                color: { background: c.bg, border: c.border },
                font: { color: '#f8fafc', face: 'Inter', size: 12, bold: true },
                shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 6 }
            });
            id++;
        }

        // Firewall node
        const fwId = id;
        nodes.push({
            id: fwId,
            label: '🔥 Campus Firewall & IDS\nInspection Core',
            shape: 'diamond',
            size: 32,
            color: { background: '#78350f', border: '#f59e0b' },
            font: { color: '#fef3c7', face: 'Inter', size: 12, bold: true },
            shadow: { enabled: true, color: 'rgba(245, 158, 11, 0.4)', size: 12 }
        });

        // Edges connecting zones to firewall
        let edgeId = 100;
        for (const [zName, zid] of Object.entries(zoneIds)) {
            const edgeKey = `edge-${zid}-${fwId}`;
            edges.push({
                id: edgeId,
                from: zid,
                to: fwId,
                label: '1 Gbps Trunk',
                color: { color: '#334155', highlight: '#38bdf8' },
                font: { color: '#64748b', size: 9, align: 'top' },
                width: 2,
                dashes: false
            });
            edgeOriginalColors[edgeId] = '#334155';
            edgeId++;
        }

        const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
        const options = {
            layout: { hierarchical: false },
            physics: {
                barnesHut: { gravitationalConstant: -3500, centralGravity: 0.3, springLength: 120 },
                stabilization: { iterations: 100 }
            },
            interaction: { hover: true, tooltipDelay: 200 }
        };

        network = new vis.Network(networkContainer, data, options);

    } catch (e) {
        console.error("Error initializing topology:", e);
    }
}

// Visual pulse animation on topology when traffic occurs
function pulseTopologyConnection(isBlocked, isAlert) {
    if (!network) return;
    const edgeData = network.body.data.edges;
    if (!edgeData) return;

    const allEdgeIds = edgeData.getIds();
    const randomEdge = allEdgeIds[Math.floor(Math.random() * allEdgeIds.length)];

    const pulseColor = isAlert ? '#f59e0b' : (isBlocked ? '#ef4444' : '#10b981');
    edgeData.update({
        id: randomEdge,
        color: { color: pulseColor, highlight: pulseColor },
        width: 4
    });

    setTimeout(() => {
        edgeData.update({
            id: randomEdge,
            color: { color: edgeOriginalColors[randomEdge] || '#334155' },
            width: 2
        });
    }, 1200);
}

// ---------------- LIVE AUTO SIMULATOR ----------------

function toggleAutoSimulation(enable) {
    if (enable) {
        if (autoSimInterval) clearInterval(autoSimInterval);
        autoSimInterval = setInterval(async () => {
            // 70% safe traffic, 30% suspicious traffic burst
            if (Math.random() < 0.65) {
                await fetch('/api/generate_safe', { method: 'POST' });
                pulseTopologyConnection(false, false);
            } else {
                await fetch('/api/generate_suspicious', { method: 'POST' });
                pulseTopologyConnection(true, true);
            }
            await loadEvents();
            await fetchStats();
        }, 3200);
    } else {
        if (autoSimInterval) {
            clearInterval(autoSimInterval);
            autoSimInterval = null;
        }
    }
}

// ---------------- LIVE POLLING & INITIALIZATION ----------------

function startPolling() {
    loadEvents();
    fetchStats();
    setInterval(() => {
        loadEvents();
        fetchStats();
    }, 3000);
}

function updateLiveClock() {
    const clock = document.getElementById('live-utc-clock');
    if (clock) {
        const now = new Date();
        clock.textContent = `${now.toISOString().replace('T', ' ').substring(0, 19)} UTC`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initTopology();
    initCharts();
    startPolling();
    setInterval(updateLiveClock, 1000);
    updateLiveClock();

    // Button Listeners
    const genSafeBtn = document.getElementById('gen-safe-btn');
    const genSuspiciousBtn = document.getElementById('gen-suspicious-btn');
    const genBurstBtn = document.getElementById('gen-burst-btn');
    const clearLogsBtn = document.getElementById('clear-logs-btn');
    const exportCsvBtn = document.getElementById('export-csv-btn');
    const autoSimToggle = document.getElementById('auto-sim-toggle');

    // Search and Filter Listeners
    const searchInput = document.getElementById('event-search-input');
    const severitySelect = document.getElementById('severity-filter-select');
    const decisionSelect = document.getElementById('decision-filter-select');

    if (searchInput) searchInput.addEventListener('input', renderFilteredEvents);
    if (severitySelect) severitySelect.addEventListener('change', renderFilteredEvents);
    if (decisionSelect) decisionSelect.addEventListener('change', renderFilteredEvents);

    if (genSafeBtn) {
        genSafeBtn.addEventListener('click', async () => {
            genSafeBtn.disabled = true;
            try {
                await fetch('/api/generate_safe', { method: 'POST' });
                pulseTopologyConnection(false, false);
                await loadEvents();
                await fetchStats();
            } catch (e) {
                console.error(e);
            } finally {
                genSafeBtn.disabled = false;
            }
        });
    }

    if (genSuspiciousBtn) {
        genSuspiciousBtn.addEventListener('click', async () => {
            genSuspiciousBtn.disabled = true;
            try {
                await fetch('/api/generate_suspicious', { method: 'POST' });
                pulseTopologyConnection(true, true);
                await loadEvents();
                await fetchStats();
            } catch (e) {
                console.error(e);
            } finally {
                genSuspiciousBtn.disabled = false;
            }
        });
    }

    if (genBurstBtn) {
        genBurstBtn.addEventListener('click', async () => {
            genBurstBtn.disabled = true;
            try {
                await fetch('/api/generate_traffic_stream', { method: 'POST' });
                pulseTopologyConnection(false, true);
                await loadEvents();
                await fetchStats();
            } catch (e) {
                console.error(e);
            } finally {
                genBurstBtn.disabled = false;
            }
        });
    }

    if (clearLogsBtn) {
        clearLogsBtn.addEventListener('click', async () => {
            if (!confirm("Are you sure you want to reset simulation counters and purge all security logs?")) return;
            clearLogsBtn.disabled = true;
            try {
                await fetch('/api/clear_logs', { method: 'POST' });
                await loadEvents();
                await fetchStats();
            } catch (e) {
                console.error(e);
            } finally {
                clearLogsBtn.disabled = false;
            }
        });
    }

    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
            window.location.href = '/api/export_csv';
        });
    }

    if (autoSimToggle) {
        autoSimToggle.addEventListener('change', (e) => {
            toggleAutoSimulation(e.target.checked);
        });
    }

    // Modal close listeners
    const modalClose = document.getElementById('modal-close-btn');
    if (modalClose) modalClose.addEventListener('click', closeDossier);

    if (dossierModal) {
        dossierModal.addEventListener('click', (e) => {
            if (e.target === dossierModal) closeDossier();
        });
    }
});
