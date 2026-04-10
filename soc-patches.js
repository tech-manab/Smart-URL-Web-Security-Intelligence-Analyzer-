/**
 * ============================================================
 * SOC ENHANCEMENT PATCHES
 * ============================================================
 * Applied AFTER script.js to enhance Wazuh dashboard components.
 * NOTE: fetch interceptor removed - it was breaking the API response
 * chain by consuming the response body prematurely.
 */

// ── Listen for scan completions via custom event ─────────────
// Dispatch event from script.js after successful scans
(function() {
    window.addEventListener('urlScanComplete', function(e) {
        const result = e.detail;
        if (result && result.url) {
            enhanceResultCard(result);
        }
    });
})();

// ── Toast Notification System Enhancement ─────────────────
function showSOCNotification(title, message, type, duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    const colors = {
        'success': { bg: 'rgba(0, 255, 156, 0.1)', border: '#00ff9c', icon: '✓' },
        'error': { bg: 'rgba(255, 77, 77, 0.1)', border: '#ff4d4d', icon: '✕' },
        'warning': { bg: 'rgba(255, 204, 0, 0.1)', border: '#ffcc00', icon: '⚠️' },
        'info': { bg: 'rgba(0, 234, 255, 0.1)', border: '#00eaff', icon: 'ℹ️' }
    };
    
    const style = colors[type] || colors['info'];
    
    toast.style.cssText = `
        background: ${style.bg};
        border: 1px solid ${style.border};
        border-left: 4px solid ${style.border};
        border-radius: 6px;
        padding: 15px;
        margin-bottom: 10px;
        color: #e2e8f0;
        display: flex;
        gap: 12px;
        align-items: start;
        animation: slideInRight 0.3s ease-out;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
    `;
    
    toast.innerHTML = `
        <span style="font-size: 1.2rem; flex-shrink: 0;">${style.icon}</span>
        <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 700; font-size: 0.9rem; margin-bottom: 4px;">${title}</div>
            <div style="font-size: 0.8rem; color: rgba(255,255,255,0.8); line-height: 1.4; word-break: break-word;">${message}</div>
        </div>
        <button onclick="this.parentElement.remove()" style="background: transparent; border: none; color: ${style.border}; cursor: pointer; font-size: 1.2rem; line-height: 1;">✕</button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.animation = 'fadeOut 0.3s ease-out forwards';
            setTimeout(() => toast.remove(), 300);
        }
    }, duration);
}

// ── URL Card Enhancement with Security Badge ────────────────
function enhanceResultCard(result) {
    if (!result) return;
    
    // Add security score badge to the most recently added result card
    const cards = document.querySelectorAll('.result-card');
    if (cards.length === 0) return;
    const card = cards[cards.length - 1];
    
    // Prevent double-enhancement
    if (card.dataset.enhanced) return;
    card.dataset.enhanced = '1';
    
    if (result.risk_level) {
        const riskColors = {
            'CRITICAL': '#ff4d4d',
            'HIGH': '#ff9900',
            'MEDIUM': '#ffcc00',
            'LOW': '#00ff9c',
            'INFO': '#00eaff'
        };
        const riskColor = riskColors[result.risk_level] || '#00eaff';
        const riskIcon = {
            'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'
        }[result.risk_level] || 'ℹ️';

        // Append risk panel inside card
        const riskPanel = document.createElement('div');
        riskPanel.style.cssText = `
            background: rgba(${result.risk_level === 'CRITICAL' ? '255,77,77' : result.risk_level === 'HIGH' ? '255,153,0' : '0,234,255'}, 0.08);
            border-left: 4px solid ${riskColor};
            border-radius: 0 8px 8px 0;
            padding: 10px 15px;
            margin-top: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        `;
        riskPanel.innerHTML = `
            <div>
                <span style="color: ${riskColor}; font-weight: 900; font-size: 0.85rem; font-family: var(--font-heading);">
                    ${riskIcon} WAZUH RISK: ${result.risk_level}
                </span>
                <div style="color: var(--text-muted); font-size: 0.78rem; margin-top: 4px;">
                    Security Score: <strong style="color: ${riskColor};">${result.security_score}/100</strong>
                    ${result.wazuh_alerts && result.wazuh_alerts.length > 0 ? ` &bull; ${result.wazuh_alerts.length} alert(s) detected` : ''}
                </div>
            </div>
            <button class="cyber-btn sm-btn" onclick="showRiskClassification('${result.url.replace(/'/g, "\\'")}')" style="padding: 4px 10px; font-size: 0.7rem;">
                <i class="fa-solid fa-magnifying-glass"></i> DETAILS
            </button>
        `;
        card.appendChild(riskPanel);
    }
}

// ── Statistics Update Integration ──────────────────────────
function updateSOCStatistics() {
    fetch('/api/wazuh/alerts/stats')
        .then(r => r.json())
        .then(stats => {
            // Update wazuh panel badges (handled by wazuh-dashboard.js)
            // Just ensure the DOM elements get updated if present
            const critElem = document.getElementById('wazuh-critical-count');
            const warnElem = document.getElementById('wazuh-warning-count');
            if (critElem) critElem.textContent = `${stats.critical_alerts} CRITICAL`;
            if (warnElem) warnElem.textContent = `${(stats.warning_alerts || 0) + (stats.medium_alerts || 0)} WARNINGS`;
        })
        .catch(err => console.warn('[SOC] Stats error:', err));
}

// ── Auto-update statistics every 15 seconds ───────────────
setInterval(updateSOCStatistics, 15000);
updateSOCStatistics(); // Initial call

// ── Enhanced Error Handling ─────────────────────────────────
window.addEventListener('error', (event) => {
    if (event.message && (event.message.includes('Wazuh') || event.message.includes('SOC'))) {
        console.error('[SOC] Critical Error:', event.error);
    }
});

// ── Export for external use ──────────────────────────────────
window.SOC = {
    showNotification: showSOCNotification,
    updateStats: updateSOCStatistics,
    enhanceCard: enhanceResultCard,
    triggerAnalysis: (url) => { if (typeof showRiskClassification === 'function') showRiskClassification(url); }
};

console.log('✓ SOC Enhancement Patches Loaded');
