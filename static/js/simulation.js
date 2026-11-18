// ==========================================================================
// CAMPUS SECURE: Interactive Traffic Simulation Controller
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    const sourceSelect = document.getElementById('source');
    const destSelect = document.getElementById('destination');
    const protocolSelect = document.getElementById('protocol');
    const portInput = document.getElementById('port');
    const resultDiv = document.getElementById('result');
    const form = document.getElementById('sim-form');
    const resetBtn = document.getElementById('reset-btn');

    // Populate zone selects from topology
    fetch('/api/topology')
        .then(r => r.json())
        .then(payload => {
            const zones = payload.zones || payload;
            Object.keys(zones).forEach(zone => {
                const opt1 = document.createElement('option');
                opt1.value = zone;
                opt1.textContent = `${zone} (${zones[zone]})`;
                sourceSelect.appendChild(opt1);

                const opt2 = document.createElement('option');
                opt2.value = zone;
                opt2.textContent = `${zone} (${zones[zone]})`;
                destSelect.appendChild(opt2);
            });
            // Defaults
            if (sourceSelect.options.length > 0) sourceSelect.selectedIndex = 0;
            if (destSelect.options.length > 3) destSelect.selectedIndex = 3; // DMZ
        })
        .catch(err => console.error("Error loading topology zones:", err));

    form.addEventListener('submit', async e => {
        e.preventDefault();
        const payload = {
            source: sourceSelect.value,
            destination: destSelect.value,
            protocol: protocolSelect.value.toLowerCase(),
            port: portInput.value
        };

        resultDiv.innerHTML = '<div style="color: #38bdf8; padding: 1rem;">⏳ Inspecting simulated packet against active firewall rules and IDS engine...</div>';

        try {
            const resp = await fetch('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await resp.json();

            if (data.error) {
                resultDiv.innerHTML = `<div class="remediation-box" style="border-color:#ef4444; color:#f87171;">⚠️ ${data.error}</div>`;
                return;
            }

            const decision = data.decision || 'deny';
            const isAllowed = decision.toLowerCase() === 'allow' || decision.toLowerCase() === 'allowed';
            const decisionLabel = isAllowed ? 'ALLOWED' : 'BLOCKED';
            const decisionClass = isAllowed ? 'badge-allowed' : 'badge-blocked';
            const reason = data.reason || 'Standard Firewall Rule Evaluation';
            const severity = (data.severity || 'LOW').toUpperCase();

            let sevClass = 'badge-low';
            if (severity === 'CRITICAL') sevClass = 'badge-critical';
            else if (severity === 'HIGH') sevClass = 'badge-high';
            else if (severity === 'MEDIUM') sevClass = 'badge-med';
            else if (severity === 'SAFE') sevClass = 'badge-safe';

            const alerts = data.alerts || [];
            let alertsHtml = '';
            if (alerts.length > 0) {
                alertsHtml = alerts.map(a => `<div class="badge-alert" style="margin-right:6px; margin-bottom:4px; display:inline-block;">⚠️ ${a}</div>`).join(' ');
            } else {
                alertsHtml = '<span style="color:#94a3b8; font-size:0.84rem;">No IDS signature anomalies detected for this packet.</span>';
            }

            resultDiv.innerHTML = `
                <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 1.25rem;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 0.75rem;">
                        <div style="display:flex; align-items:center; gap: 0.75rem;">
                            <span class="${decisionClass}" style="font-size: 0.95rem; padding: 0.35rem 0.85rem;">${decisionLabel}</span>
                            <span class="${sevClass}" style="font-size: 0.85rem; padding: 0.3rem 0.65rem;">SEVERITY: ${severity}</span>
                        </div>
                        <div class="mono" style="font-size: 0.82rem; color: #94a3b8;">
                            ${payload.source} &rarr; ${payload.destination} : ${payload.port}/${payload.protocol.toUpperCase()}
                        </div>
                    </div>

                    <div style="margin-bottom: 0.85rem;">
                        <span style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:700;">Matched Firewall Policy:</span>
                        <div style="font-size:0.92rem; font-weight:600; color:#38bdf8; margin-top:2px;">${reason}</div>
                    </div>

                    <div>
                        <span style="font-size:0.75rem; color:#94a3b8; text-transform:uppercase; font-weight:700;">Intrusion Detection Telemetry:</span>
                        <div style="margin-top:0.4rem;">${alertsHtml}</div>
                    </div>
                </div>
            `;
        } catch (err) {
            console.error(err);
            resultDiv.innerHTML = '<div style="color: #f87171; padding: 1rem;">❌ Error communicating with simulation backend.</div>';
        }
    });

    resetBtn.addEventListener('click', async () => {
        try {
            await fetch('/api/reset');
            resultDiv.innerHTML = '<div style="color: #10b981; padding: 0.5rem 0; font-size:0.85rem;">🔄 In-memory IDS heuristic state and SQLite logs cleared.</div>';
        } catch (err) {
            console.error(err);
        }
    });
});
