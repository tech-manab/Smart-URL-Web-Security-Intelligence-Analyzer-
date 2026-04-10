/**
 * ============================================================
 * WAZUH SOC DASHBOARD - Smart URL Checker Integration
 * ============================================================
 */

const SOC_CONFIG = {
    alertRefreshInterval: 8000,
    monitoringRefreshInterval: 5000,
    chartUpdateInterval: 10000,
    maxAlerts: 20,
    maxScans: 50
};

const RISK_COLORS = {
    CRITICAL: { bg: 'rgba(255, 77, 77, 0.12)', border: 'rgba(255, 77, 77, 0.5)', text: '#ff4d4d', icon: '🔴' },
    HIGH:     { bg: 'rgba(255, 153, 0, 0.12)', border: 'rgba(255, 153, 0, 0.5)',  text: '#ff9900', icon: '🟠' },
    MEDIUM:   { bg: 'rgba(255, 204, 0, 0.12)', border: 'rgba(255, 204, 0, 0.5)',  text: '#ffcc00', icon: '🟡' },
    LOW:      { bg: 'rgba(0, 255, 156, 0.12)', border: 'rgba(0, 255, 156, 0.5)', text: '#00ff9c', icon: '🟢' },
    INFO:     { bg: 'rgba(0, 234, 255, 0.12)', border: 'rgba(0, 234, 255, 0.5)', text: '#00eaff', icon: '🔵' }
};

const SEVERITY_LEVELS = {
    Critical: { priority: 5, color: '#ff4d4d', icon: '🚨' },
    High:     { priority: 4, color: '#ff9900', icon: '⚠️' },
    Medium:   { priority: 3, color: '#ffcc00', icon: '⚡' },
    Warning:  { priority: 2, color: '#ffa500', icon: '⚠️' },
    Low:      { priority: 1, color: '#00ff9c', icon: 'ℹ️' },
    Info:     { priority: 0, color: '#00eaff', icon: 'ℹ️' }
};

// Chart data accumulators (updated on each API scan result)
let chartScanData  = Array(12).fill(0);
let chartAlertData = Array(12).fill(0);
let activityChart  = null;

// ── Initialize ─────────────────────────────────────────────
function initWazuhDashboard() {
    initActivityChart();
    startAlertMonitoring();
    startLiveMonitoring();
    startDashboardUpdate();

    // When a new scan happens, push a point to the chart
    window.addEventListener('urlScanComplete', (e) => {
        const data = e.detail;
        chartScanData.shift();
        chartScanData.push(1);
        if (data && data.wazuh_alerts && data.wazuh_alerts.length > 0) {
            chartAlertData.shift();
            chartAlertData.push(data.wazuh_alerts.length);
        } else {
            chartAlertData.shift();
            chartAlertData.push(0);
        }
        if (activityChart) {
            activityChart.data.datasets[0].data = [...chartScanData];
            activityChart.data.datasets[1].data = [...chartAlertData];
            activityChart.update('active');
        }
        // Refresh alerts feed immediately after scan
        fetchAndDisplayAlerts();
        updateAlertBadges();
    });
}

// ── Alert Monitoring Loop ───────────────────────────────────
async function startAlertMonitoring() {
    await fetchAndDisplayAlerts();
    await updateAlertBadges();
    setInterval(async () => {
        await fetchAndDisplayAlerts();
        await updateAlertBadges();
    }, SOC_CONFIG.alertRefreshInterval);
}

async function fetchAndDisplayAlerts() {
    try {
        const res = await fetch(`/api/wazuh/alerts?limit=${SOC_CONFIG.maxAlerts}`);
        if (!res.ok) return;
        const alerts = await res.json();
        updateAlertsFeed(alerts);
    } catch (err) {
        console.warn('[SOC] Alert fetch error:', err);
    }
}

// ── Alerts Feed Render ──────────────────────────────────────
function updateAlertsFeed(alerts) {
    const container = document.getElementById('wazuh-alerts-container');
    if (!container) return;

    if (!alerts || alerts.length === 0) {
        container.innerHTML = `
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;min-height:180px;gap:10px;opacity:0.6;">
                <div style="font-size:2rem;">🛡️</div>
                <div style="color:var(--neon-green);font-family:var(--font-heading);font-size:0.8rem;letter-spacing:1px;">ALL SYSTEMS NOMINAL</div>
                <div style="color:var(--text-muted);font-size:0.72rem;text-align:center;">No active threats detected.<br>Scan a URL to begin monitoring.</div>
            </div>`;
        return;
    }

    const sorted = [...alerts].sort((a, b) => {
        return (SEVERITY_LEVELS[b.level]?.priority || 0) - (SEVERITY_LEVELS[a.level]?.priority || 0);
    });

    container.innerHTML = sorted.slice(0, 10).map(alert => {
        const sev = SEVERITY_LEVELS[alert.level] || { color: '#00eaff', icon: 'ℹ️', priority: 0 };
        const rk  = RISK_COLORS[alert.risk_level] || RISK_COLORS.INFO;
        const ts  = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '--:--';
        const shortUrl = (alert.url || 'N/A').replace(/^https?:\/\//, '').split('/')[0];

        return `
        <div class="soc-alert-item" style="
            background: ${rk.bg};
            border-left: 3px solid ${sev.color};
            border-radius: 0 6px 6px 0;
            padding: 8px 10px;
            display:flex; justify-content:space-between; align-items:center; gap:8px;
            animation: slideInRight 0.3s ease;
        ">
            <div style="flex:1;min-width:0;">
                <div style="color:${sev.color};font-weight:700;font-size:0.72rem;font-family:var(--font-heading);">
                    ${sev.icon} ${(alert.level || '').toUpperCase()}
                </div>
                <div style="color:#e2e8f0;font-size:0.75rem;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${alert.url || ''}">
                    ${alert.rule_name || 'Alert'} — ${shortUrl}
                </div>
                <div style="color:rgba(255,255,255,0.35);font-size:0.65rem;margin-top:2px;">${ts}</div>
            </div>
            <div style="text-align:right;flex-shrink:0;">
                <div style="color:${sev.color};font-weight:900;font-size:0.9rem;font-family:var(--font-heading);">${alert.security_score ?? '—'}</div>
                <div style="font-size:0.6rem;color:var(--text-muted);">score</div>
            </div>
        </div>`;
    }).join('');
}

// ── Badge Update ────────────────────────────────────────────
async function updateAlertBadges() {
    try {
        const res = await fetch('/api/wazuh/alerts/stats');
        if (!res.ok) return;
        const stats = await res.json();

        const critBadge = document.getElementById('wazuh-critical-count');
        const warnBadge = document.getElementById('wazuh-warning-count');
        if (critBadge) critBadge.textContent = `${stats.critical_alerts || 0} CRITICAL`;
        if (warnBadge) warnBadge.textContent  = `${(stats.warning_alerts || 0) + (stats.medium_alerts || 0)} WARNINGS`;
    } catch (e) { /* silent */ }
}

// ── Live Monitoring ─────────────────────────────────────────
async function startLiveMonitoring() {
    const fetchLive = async () => {
        try {
            const res = await fetch('/api/monitoring/live?limit=10');
            if (res.ok) {
                const data = await res.json();
                // Push real scan count delta to chart
                if (data.recent_scans && data.recent_scans.length > 0) {
                    updateChartWithHistory(data.recent_scans.length);
                }
            }
        } catch (e) { /* silent */ }
    };
    fetchLive();
    setInterval(fetchLive, SOC_CONFIG.monitoringRefreshInterval);
}

function updateChartWithHistory(count) {
    // Only gently hint the chart when no manual scan triggered it
    if (!activityChart) return;
    // do nothing (chart is updated by urlScanComplete event for real scans)
}

// ── Dashboard Stats ─────────────────────────────────────────
async function startDashboardUpdate() {
    const update = async () => {
        try {
            const res = await fetch('/api/security/dashboard');
            if (res.ok) {
                const data = await res.json();
                renderSOCDashboard(data);
            }
        } catch (e) { /* silent */ }
    };
    update();
    setInterval(update, 15000);
}

function renderSOCDashboard(dashboard) {
    const vulnContainer = document.getElementById('wazuh-vulnerable-urls');
    if (vulnContainer && dashboard.vulnerable_urls) {
        if (dashboard.vulnerable_urls.length === 0) {
            vulnContainer.innerHTML = `<div style="color:var(--text-muted);font-size:0.8rem;text-align:center;padding:10px;">No vulnerable URLs detected yet.</div>`;
            return;
        }
        vulnContainer.innerHTML = dashboard.vulnerable_urls.slice(0, 5).map(u => `
            <div style="padding:8px;background:rgba(255,77,77,0.08);border-left:3px solid #ff4d4d;border-radius:0 4px 4px 0;margin-bottom:6px;">
                <div style="color:#ffa;font-size:0.78rem;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${u.url}</div>
                <div style="color:var(--text-muted);font-size:0.68rem;">Alerts: ${u.alert_count} | Avg Score: ${u.avg_score ? Math.round(u.avg_score) : 'N/A'}</div>
            </div>`).join('');
    }
}

// ── Chart.js Activity Chart ─────────────────────────────────
function initActivityChart() {
    const canvas = document.getElementById('wazuhActivityChart');
    if (!canvas) return;

    // Wait for Chart.js to be available
    if (typeof Chart === 'undefined') {
        setTimeout(initActivityChart, 500);
        return;
    }

    // Destroy existing chart if any
    if (activityChart) { activityChart.destroy(); activityChart = null; }

    const ctx = canvas.getContext('2d');
    const labels = generateTimeLabels(12);

    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Scans',
                    data: [...chartScanData],
                    borderColor: '#00eaff',
                    backgroundColor: 'rgba(0, 234, 255, 0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointBackgroundColor: '#00eaff',
                    pointBorderColor: 'transparent',
                    pointHoverRadius: 5
                },
                {
                    label: 'Alerts',
                    data: [...chartAlertData],
                    borderColor: '#ff4d4d',
                    backgroundColor: 'rgba(255, 77, 77, 0.08)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointBackgroundColor: '#ff4d4d',
                    pointBorderColor: 'transparent',
                    pointHoverRadius: 5
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: '#a0aec0',
                        font: { family: 'monospace', size: 11 },
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(11, 18, 33, 0.95)',
                    borderColor: 'rgba(0, 234, 255, 0.3)',
                    borderWidth: 1,
                    titleColor: '#00eaff',
                    bodyColor: '#e2e8f0',
                    padding: 10
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#a0aec0', font: { size: 10 }, stepSize: 1 },
                    border: { display: false }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#a0aec0', font: { size: 10 }, maxRotation: 0 },
                    border: { display: false }
                }
            },
            animation: { duration: 600, easing: 'easeInOutQuart' }
        }
    });

    // Gently animate chart every interval to show it's "live"
    setInterval(() => {
        if (!activityChart) return;
        activityChart.data.labels = generateTimeLabels(12);
        activityChart.update('none');
    }, SOC_CONFIG.chartUpdateInterval);
}

// ── Helpers ─────────────────────────────────────────────────
function generateTimeLabels(count) {
    const labels = [];
    for (let i = count - 1; i >= 0; i--) {
        const t = new Date();
        t.setSeconds(t.getSeconds() - i * 15);
        labels.push(t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    }
    return labels;
}

// ── Risk Modal ──────────────────────────────────────────────
function showRiskClassification(url) {
    const modal = document.createElement('div');
    modal.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);display:flex;justify-content:center;align-items:center;z-index:10000;animation:fadeIn 0.3s ease-out;backdrop-filter:blur(4px);';

    modal.innerHTML = `
        <div style="background:linear-gradient(135deg,rgba(16,24,43,0.98),rgba(11,18,33,0.98));border:1px solid rgba(0,234,255,0.25);border-radius:14px;padding:28px;max-width:520px;width:92%;max-height:82vh;overflow-y:auto;color:#e2e8f0;box-shadow:0 20px 60px rgba(0,234,255,0.15);">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;border-bottom:1px solid rgba(0,234,255,0.15);padding-bottom:14px;">
                <h2 style="margin:0;font-family:'Orbitron',sans-serif;color:#00eaff;font-size:1rem;">🔍 RISK ANALYSIS</h2>
                <button onclick="this.closest('div[style*=fixed]').remove()" style="background:rgba(255,77,77,0.1);border:1px solid #ff4d4d;color:#ff4d4d;padding:5px 12px;border-radius:6px;cursor:pointer;font-size:0.8rem;">✕ CLOSE</button>
            </div>
            <div id="risk-modal-content" style="font-size:0.85rem;">
                <div style="display:flex;align-items:center;gap:10px;color:var(--neon-cyan);">
                    <i class="fa-solid fa-spinner fa-spin"></i> Loading analysis...
                </div>
            </div>
        </div>`;

    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });

    fetch(`/api/security/score/${encodeURIComponent(url)}`)
        .then(r => r.json())
        .then(data => {
            const content = document.getElementById('risk-modal-content');
            if (!content) return;
            if (!data.latest_scan && data.alerts.length === 0) {
                content.innerHTML = `<div style="color:var(--text-muted);text-align:center;padding:20px;">No scan data found for this URL yet.</div>`;
                return;
            }
            const scan = data.latest_scan || {};
            content.innerHTML = `
                <div style="margin-bottom:16px;word-break:break-all;font-family:monospace;font-size:0.8rem;color:#a0aec0;background:rgba(0,0,0,0.3);padding:8px 12px;border-radius:6px;">${data.url}</div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px;">
                    <div style="background:rgba(0,0,0,0.3);padding:12px;border-radius:8px;text-align:center;">
                        <div style="color:#a0aec0;font-size:0.72rem;margin-bottom:4px;">HTTP STATUS</div>
                        <div style="font-size:1.6rem;font-weight:900;color:${scan.status_code===200?'#00ff9c':'#ff4d4d'};">${scan.status_code||'N/A'}</div>
                    </div>
                    <div style="background:rgba(0,0,0,0.3);padding:12px;border-radius:8px;text-align:center;">
                        <div style="color:#a0aec0;font-size:0.72rem;margin-bottom:4px;">RESPONSE TIME</div>
                        <div style="font-size:1.6rem;font-weight:900;color:#00eaff;">${scan.response_ms||'—'}ms</div>
                    </div>
                    <div style="background:rgba(0,0,0,0.3);padding:12px;border-radius:8px;text-align:center;">
                        <div style="color:#a0aec0;font-size:0.72rem;margin-bottom:4px;">ENCRYPTION</div>
                        <div style="font-size:1.4rem;font-weight:900;color:${scan.secure?'#00ff9c':'#ff4d4d'};">${scan.secure?'🔒 HTTPS':'🔓 HTTP'}</div>
                    </div>
                    <div style="background:rgba(0,0,0,0.3);padding:12px;border-radius:8px;text-align:center;">
                        <div style="color:#a0aec0;font-size:0.72rem;margin-bottom:4px;">AVAILABILITY</div>
                        <div style="font-size:1rem;font-weight:700;color:#ffcc00;">${scan.availability||'—'}</div>
                    </div>
                </div>
                <div>
                    <div style="color:#ff4d4d;font-weight:700;margin-bottom:8px;font-family:'Orbitron',sans-serif;font-size:0.8rem;">⚡ ACTIVE ALERTS (${data.alerts.length})</div>
                    <div style="display:flex;flex-direction:column;gap:6px;max-height:180px;overflow-y:auto;">
                        ${data.alerts.length > 0 ? data.alerts.map(a => `
                            <div style="background:rgba(255,77,77,0.08);border-left:3px solid #ff4d4d;padding:8px 10px;border-radius:0 6px 6px 0;font-size:0.78rem;">
                                <div style="color:#ff4d4d;font-weight:700;">${a.rule_name}</div>
                                <div style="color:#a0aec0;margin-top:2px;">${a.message}</div>
                            </div>`).join('') : '<div style="color:#a0aec0;text-align:center;padding:10px;">No active alerts for this URL.</div>'}
                    </div>
                </div>`;
        })
        .catch(() => {
            const c = document.getElementById('risk-modal-content');
            if (c) c.innerHTML = '<div style="color:#ff4d4d;">Error loading risk data.</div>';
        });
}

// ── Boot ────────────────────────────────────────────────────
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initWazuhDashboard);
} else {
    initWazuhDashboard();
}
