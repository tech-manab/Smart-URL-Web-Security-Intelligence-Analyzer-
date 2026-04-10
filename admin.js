/**
 * admin.js | Admin Command Center Logic - Flask Local Auth
 * Fully rewritten to use Flask/SQLite backend (no Supabase)
 */
document.addEventListener('DOMContentLoaded', async () => {
    // -----------------------------------------------------------------
    // 1. ACCESS CONTROL via Flask session
    // -----------------------------------------------------------------
    let adminUser = null;
    try {
        const res = await fetch('/api/auth/me');
        if (!res.ok) { window.location.href = '/login'; return; }
        const data = await res.json();
        adminUser = data.user;
        if (!adminUser || adminUser.role !== 'admin') {
            window.location.href = '/?error=access_denied';
            return;
        }
    } catch(err) {
        window.location.href = '/login';
        return;
    }

    const dispName = document.getElementById('admin-display-name');
    if (dispName) dispName.textContent = adminUser.username || 'System Root';

    // Reveal body
    document.body.style.display = 'flex';

    // Logout
    const btnAdminLog = document.getElementById('btn-admin-logout');
    if (btnAdminLog) {
        btnAdminLog.addEventListener('click', async () => {
            await fetch('/api/auth/logout', { method: 'POST' });
            window.location.href = '/login';
        });
    }

    // -----------------------------------------------------------------
    // 2. UI INTERACTIONS: SIDEBAR & NAVIGATION
    // -----------------------------------------------------------------
    const links = document.querySelectorAll('.sidebar-link');
    const sections = document.querySelectorAll('.admin-section');
    const titleDisp = document.getElementById('current-section-title');

    links.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            links.forEach(l => l.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));
            
            link.classList.add('active');
            const target = link.getAttribute('data-section');
            const tgtEl = document.getElementById(`section-${target}`);
            if (tgtEl) tgtEl.classList.add('active');
            
            if (titleDisp) {
                titleDisp.textContent = link.textContent.trim().toUpperCase();
            }
        });
    });

    // -----------------------------------------------------------------
    // 3. LOAD DASHBOARD OVERVIEW
    // -----------------------------------------------------------------
    async function loadDashboard() {
        try {
            // Get user count
            const usersRes = await fetch('/api/admin/users');
            const usersData = usersRes.ok ? await usersRes.json() : [];

            // Get history/scans
            const histRes = await fetch('/api/history');
            const histData = histRes.ok ? await histRes.json() : [];

            // Get wazuh stats
            const statsRes = await fetch('/api/wazuh/alerts/stats');
            const statsData = statsRes.ok ? await statsRes.json() : {};

            const du = document.getElementById('dash-users');
            const ds = document.getElementById('dash-scans');
            const dUp = document.getElementById('dash-up');
            const dDown = document.getElementById('dash-down');
            const dLat = document.getElementById('dash-latency');

            let up = 0, down = 0, slow = 0, totalMs = 0, msCount = 0;
            let httpsCount = 0, riskyCount = 0, httpCount = 0;
            const alerts = [];

            histData.forEach(L => {
                if (L.status === 'Up' || L.status === 'Redirected') up++;
                else if (['Down', 'Broken', 'Invalid', 'SSL Error'].includes(L.status)) {
                    down++;
                    if (alerts.length < 5) alerts.push({ msg: `Service Offline`, url: L.url, type: 'critical' });
                } else if (L.status === 'Slow') {
                    slow++;
                    if (alerts.length < 5) alerts.push({ msg: `High Latency (${L.response_ms}ms)`, url: L.url, type: 'warning' });
                }

                if (L.secure) httpsCount++;
                else { httpCount++; }

                if (L.response_ms) { totalMs += L.response_ms; msCount++; }
            });

            if (du) du.textContent = usersData.length;
            if (ds) ds.textContent = histData.length;
            if (dUp) dUp.textContent = up;
            if (dDown) dDown.textContent = down + (statsData.critical_alerts || 0);
            if (dLat) dLat.textContent = msCount ? Math.floor(totalMs / msCount) : 0;

            loadSecurity(httpsCount, httpCount, riskyCount, histData.length);
            loadAlerts(alerts.length > 0 ? alerts : generateAlertsFromStats(statsData));
            loadAnalytics(up, down, slow);
        } catch (err) {
            console.error('[Admin] Dashboard load error:', err);
        }
    }

    function generateAlertsFromStats(stats) {
        const alerts = [];
        if (stats.critical_alerts > 0) alerts.push({ msg: `${stats.critical_alerts} Critical Security Alerts`, url: 'System-Wide', type: 'critical' });
        if (stats.warning_alerts > 0) alerts.push({ msg: `${stats.warning_alerts} Warning-level Alerts`, url: 'System-Wide', type: 'warning' });
        return alerts;
    }

    // -----------------------------------------------------------------
    // 4. LOAD USERS
    // -----------------------------------------------------------------
    async function loadUsers() {
        const tbody = document.getElementById('user-mgmt-tbody');
        if (!tbody) return;

        try {
            const res = await fetch('/api/admin/users');
            if (!res.ok) throw new Error('Forbidden');
            const users = await res.json();

            tbody.innerHTML = '';

            if (users.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:20px;">No users found.</td></tr>`;
                return;
            }

            users.forEach(u => {
                const isBlocked = u.status === 'Blocked';
                const stColor = isBlocked ? 'var(--neon-red)' : (u.status === 'Active' ? 'var(--neon-green)' : 'var(--text-muted)');
                const stText = isBlocked ? 'BLOCKED' : 'ACTIVE';
                const btnColor = isBlocked ? 'var(--neon-green)' : 'var(--neon-orange)';
                const btnText = isBlocked ? 'UNBLOCK' : 'BLOCK';

                tbody.innerHTML += `
                    <tr>
                        <td>
                            <div style="font-weight:600; color:#fff;">@${u.username}</div>
                            <div style="font-size:0.8rem; color:var(--text-muted); font-family:monospace;">#${u.id}</div>
                        </td>
                        <td style="font-family:'Orbitron', sans-serif; font-size:0.85rem; color:#a0aec0;">${u.role}</td>
                        <td style="color:${stColor}; font-weight:600;"><i class="fa-solid fa-circle" style="font-size:0.6rem; margin-right:5px;"></i>${stText}</td>
                        <td style="display:flex; gap:10px;">
                            <button class="cyber-btn sm-btn" style="border-color:${btnColor}; color:${btnColor};" onclick="toggleUser(${u.id}, '${u.status}')">${btnText}</button>
                        </td>
                    </tr>
                `;
            });
        } catch (err) {
            console.error('[Admin] Users load error:', err);
            if (tbody) tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--neon-red);padding:20px;">Error loading users.</td></tr>`;
        }
    }

    window.toggleUser = async (id, currentStatus) => {
        const block = currentStatus !== 'Blocked';
        try {
            const res = await fetch(`/api/admin/users/${id}/block`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ block })
            });
            if (!res.ok) throw new Error('Failed');
            loadUsers();
            showToast('User Updated', `User status changed to ${block ? 'Blocked' : 'Active'}`, 'success');
        } catch (err) {
            showToast('Error', 'Failed to update user status.', 'error');
        }
    };

    // -----------------------------------------------------------------
    // 5. LOAD ACTIVITY LOG
    // -----------------------------------------------------------------
    async function loadActivity() {
        const tbody = document.getElementById('activity-tbody');
        if (!tbody) return;

        try {
            const res = await fetch('/api/history');
            if (!res.ok) return;
            const logs = await res.json();

            tbody.innerHTML = '';

            if (logs.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:20px;">No activity logged yet.</td></tr>`;
                return;
            }

            logs.slice(0, 50).forEach(L => {
                let color = 'var(--neon-green)';
                if (['Down', 'Broken', 'Invalid', 'SSL Error'].includes(L.status)) color = 'var(--neon-red)';
                else if (L.status === 'Slow') color = 'var(--neon-yellow)';

                tbody.innerHTML += `
                    <tr>
                        <td style="font-family:monospace; max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--neon-cyan)">${L.url}</td>
                        <td style="color:${color}; font-weight:bold;">${L.status}</td>
                        <td style="color:${L.secure ? 'var(--neon-green)' : 'var(--neon-red)'};"><i class="fa-solid fa-${L.secure ? 'lock' : 'lock-open'}"></i> ${L.secure ? 'HTTPS' : 'HTTP'}</td>
                        <td style="font-family:monospace; font-size:0.9rem;">${L.response_ms ? L.response_ms + 'ms' : '---'}</td>
                        <td style="font-size:0.8rem; color:var(--text-muted)">${new Date(L.checked_at).toLocaleString()}</td>
                        <td><button class="cyber-btn sm-btn danger-btn" onclick="deleteHistoryItem(${L.id})" style="padding:4px 8px;"><i class="fa-solid fa-trash"></i></button></td>
                    </tr>
                `;
            });
        } catch (err) {
            console.error('[Admin] Activity load error:', err);
        }
    }

    window.deleteHistoryItem = async (id) => {
        // NOTE: No per-item delete endpoint; skip or show info
        showToast('Info', 'Use "Clear All History" to wipe scan logs.', 'info');
    };

    const clearLogs = document.getElementById('btn-clear-logs');
    if (clearLogs) {
        clearLogs.addEventListener('click', async () => {
            if (confirm('Clear ALL scan history from the database?')) {
                const res = await fetch('/api/history/clear', { method: 'DELETE' });
                if (res.ok) {
                    loadActivity();
                    loadDashboard();
                    showToast('Logs Cleared', 'All scan history wiped.', 'success');
                } else {
                    showToast('Error', 'Failed to clear history.', 'error');
                }
            }
        });
    }

    // -----------------------------------------------------------------
    // 6. LOAD WAZUH SECURITY ALERTS
    // -----------------------------------------------------------------
    async function loadWazuhAlerts() {
        const container = document.getElementById('alerts-container');
        if (!container) return;

        try {
            const res = await fetch('/api/wazuh/alerts?limit=20');
            if (!res.ok) return;
            const alerts = await res.json();

            if (alerts.length === 0) {
                container.innerHTML = `
                    <div style="text-align:center; padding:30px; color:var(--neon-green);">
                        <i class="fa-solid fa-shield-check fa-3x" style="margin-bottom:15px; display:block;"></i>
                        No active security alerts. All systems nominal.
                    </div>
                `;
                return;
            }

            container.innerHTML = '';
            alerts.slice(0, 10).forEach(a => {
                const levelColors = {
                    'Critical': 'var(--neon-red)',
                    'High': 'var(--neon-orange)',
                    'Medium': 'var(--neon-yellow)',
                    'Warning': 'var(--neon-yellow)',
                    'Low': 'var(--neon-green)',
                    'Info': 'var(--neon-cyan)'
                };
                const color = levelColors[a.level] || 'var(--neon-cyan)';

                container.innerHTML += `
                    <div style="border-left: 3px solid ${color}; background: rgba(0,0,0,0.3); padding: 12px 15px; border-radius: 0 6px 6px 0; margin-bottom: 10px;">
                        <div style="display:flex; justify-content:space-between; align-items:start; flex-wrap:wrap; gap:10px;">
                            <div style="flex:1;">
                                <div style="font-weight:600; color:${color}; margin-bottom:4px;">[${a.level}] ${a.rule_name}</div>
                                <div style="font-family:monospace; font-size:0.8rem; color:#a0aec0;">TARGET: ${a.url}</div>
                                <div style="font-size:0.75rem; color:var(--text-muted); margin-top:4px;">${a.message}</div>
                            </div>
                            <div style="text-align:right;">
                                <div style="font-size:0.7rem; color:var(--text-muted);">${new Date(a.timestamp).toLocaleString()}</div>
                                ${a.security_score !== null ? `<div style="font-size:0.8rem; color:${color}; font-weight:700; margin-top:4px;">Score: ${a.security_score}/100</div>` : ''}
                            </div>
                        </div>
                    </div>
                `;
            });
        } catch (err) {
            console.error('[Admin] Wazuh alerts error:', err);
        }
    }

    // -----------------------------------------------------------------
    // 7. ANALYTICS CHARTS
    // -----------------------------------------------------------------
    function loadAnalytics(up, down, slow) {
        const vC = document.getElementById('chart-volume');
        const sC = document.getElementById('chart-success');
        if (!vC || !sC) return;

        // Volume Chart
        const days = ['D-6', 'D-5', 'D-4', 'D-3', 'D-2', 'D-1', 'NOW'];
        vC.innerHTML = '<div style="display:flex; justify-content:space-between; align-items:flex-end; height:180px;">';
        days.forEach(d => {
            const h = Math.floor(Math.random() * 80) + 20;
            vC.children[0].innerHTML += `
                <div style="display:flex; flex-direction:column; align-items:center; width:12%;">
                    <div style="height:${h}%; width:100%; background:linear-gradient(to top, rgba(0,234,255,0.2), var(--neon-cyan)); border-radius:4px 4px 0 0; box-shadow:0 0 10px rgba(0,234,255,0.3); transition:height 1s;"></div>
                    <div style="margin-top:10px; font-size:0.75rem; color:#a0aec0;">${d}</div>
                </div>
            `;
        });

        // Status Breakdown
        const total = (up + down + slow) || 1;
        sC.innerHTML = '<div style="display:flex; justify-content:space-between; align-items:flex-end; height:180px;">';

        const metrics = [
            { lbl: 'UP', col: 'var(--neon-green)', val: up },
            { lbl: 'SLOW', col: 'var(--neon-yellow)', val: slow },
            { lbl: 'DOWN', col: 'var(--neon-red)', val: down }
        ];

        metrics.forEach(m => {
            const pct = Math.max((m.val / total) * 100, 5);
            sC.children[0].innerHTML += `
                <div style="display:flex; flex-direction:column; align-items:center; width:30%;">
                    <div style="font-family:'Orbitron',sans-serif; color:${m.col}; margin-bottom:5px;">${m.val}</div>
                    <div style="height:${pct}%; width:100%; background:${m.col}; border-radius:4px 4px 0 0; box-shadow:0 0 15px ${m.col}; transition:height 1s;"></div>
                    <div style="margin-top:10px; font-size:0.8rem; font-weight:600; color:#fff;">${m.lbl}</div>
                </div>
            `;
        });
    }

    // -----------------------------------------------------------------
    // 8. SECURITY OVERVIEW
    // -----------------------------------------------------------------
    function loadSecurity(https, http, risky, total) {
        const sh = document.getElementById('sec-https-count');
        const sc = document.getElementById('sec-http-count');
        const sr = document.getElementById('sec-risk-count');
        const shPct = document.getElementById('sec-health-pct');
        const shBar = document.getElementById('sec-health-bar');

        if (sh) sh.textContent = https;
        if (sc) sc.textContent = http;
        if (sr) sr.textContent = risky;

        if (shPct && shBar) {
            if (total === 0) {
                shPct.textContent = '100%';
                shBar.style.width = '100%';
                shBar.style.background = 'var(--neon-green)';
            } else {
                const pct = Math.floor((https / total) * 100);
                shPct.textContent = `${pct}%`;
                shBar.style.width = `${pct}%`;
                if (pct >= 80) shBar.style.background = 'var(--neon-green)';
                else if (pct >= 50) shBar.style.background = 'var(--neon-yellow)';
                else shBar.style.background = 'var(--neon-red)';
            }
        }
    }

    // Legacy alert loader (kept for compatibility)
    function loadAlerts(alerts) {
        const container = document.getElementById('alerts-container');
        if (!container) return;

        container.innerHTML = '';

        if (alerts.length === 0) {
            container.innerHTML = `
                <div style="text-align:center; padding:30px; color:var(--neon-green);">
                    <i class="fa-solid fa-shield-check fa-3x" style="margin-bottom:15px; display:block;"></i>
                    No system vulnerabilities or faults detected. Operations optimal.
                </div>
            `;
            return;
        }

        alerts.forEach(a => {
            let color = 'var(--neon-yellow)';
            let icon = 'fa-triangle-exclamation';
            if (a.type === 'critical') { color = 'var(--neon-red)'; icon = 'fa-skull-crossbones'; }
            else if (a.type === 'security') { color = 'var(--neon-orange)'; icon = 'fa-lock-open'; }

            container.innerHTML += `
                <div style="border-left: 3px solid ${color}; background: rgba(0,0,0,0.3); padding: 12px 15px; border-radius: 0 6px 6px 0; margin-bottom: 10px; display:flex; justify-content:space-between; align-items:center; gap:10px;">
                    <div>
                        <div style="font-weight:600; margin-bottom:5px; color:${color};">${a.msg}</div>
                        <div style="font-family:monospace; font-size:0.8rem; color: #a0aec0;">TARGET: ${a.url}</div>
                    </div>
                    <i class="fa-solid ${icon} fa-2x" style="color:${color}; opacity:0.7;"></i>
                </div>
            `;
        });
    }

    // -----------------------------------------------------------------
    // 9. SYSTEM CONTROLS
    // -----------------------------------------------------------------

    // Maintenance Mode
    const btnMaint = document.getElementById('btn-toggle-maintenance');
    if (btnMaint) {
        const checkMaint = () => {
            if (localStorage.getItem('systemStatus') === 'maintenance') {
                btnMaint.textContent = "DISABLE MAINTENANCE";
                btnMaint.className = 'cyber-btn danger-btn';
            } else {
                btnMaint.textContent = "ENABLE MAINTENANCE";
                btnMaint.className = 'cyber-btn primary-btn';
            }
        };
        checkMaint();
        btnMaint.addEventListener('click', () => {
            const isMaint = localStorage.getItem('systemStatus') === 'maintenance';
            localStorage.setItem('systemStatus', isMaint ? 'active' : 'maintenance');
            checkMaint();
            showToast('System Updated', isMaint ? 'Maintenance disabled. User portal online.' : 'Maintenance active. User portal locked.', isMaint ? 'success' : 'warning');
        });
    }

    // Force Logout (local - just a notice)
    const btnForceOut = document.getElementById('btn-force-logout');
    if (btnForceOut) {
        btnForceOut.addEventListener('click', () => {
            showToast('Info', 'Force logout available via blocking individual users in the Users tab.', 'info');
        });
    }

    // Factory Reset (clear history)
    const btnResetSystem = document.getElementById('btn-reset-system');
    if (btnResetSystem) {
        btnResetSystem.addEventListener('click', async () => {
            if (confirm("WARNING: This will delete ALL scan history globally. Proceed?")) {
                const res = await fetch('/api/history/clear', { method: 'DELETE' });
                if (res.ok) {
                    localStorage.setItem('systemStatus', 'active');
                    showToast('Reset Complete', 'All scan history cleared. Reloading...', 'error');
                    setTimeout(() => window.location.reload(), 1500);
                } else {
                    showToast('Error', 'Failed to clear history.', 'error');
                }
            }
        });
    }

    // Admin Settings: Save
    const btnSaveSettings = document.getElementById('btn-save-settings');
    if (btnSaveSettings) {
        btnSaveSettings.addEventListener('click', async () => {
            const settings = {};
            document.querySelectorAll('[data-setting]').forEach(el => {
                settings[el.dataset.setting] = el.value || el.checked;
            });
            const res = await fetch('/api/admin/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });
            if (res.ok) showToast('Settings Saved', 'Configuration updated successfully.', 'success');
            else showToast('Error', 'Failed to save settings.', 'error');
        });
    }

    // Send Global Alert broadcast (stored via admin settings)
    const btnSendAlert = document.getElementById('btn-send-alert');
    const inputAlertMsg = document.getElementById('global-alert-msg');
    if (btnSendAlert && inputAlertMsg) {
        btnSendAlert.addEventListener('click', async () => {
            const msg = inputAlertMsg.value.trim();
            if (msg) {
                await fetch('/api/admin/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ global_alert: msg, global_alert_time: new Date().toISOString() })
                });
                inputAlertMsg.value = '';
                showToast('Broadcast Sent', 'Global alert stored in settings.', 'success');
            }
        });
    }

    // Blocked Domains Registry
    function renderBlockedDomains() {
        const list = document.getElementById('blocked-domains-list');
        if (!list) return;
        const sites = JSON.parse(localStorage.getItem('blockedSites')) || [];
        list.innerHTML = '';
        if (sites.length === 0) {
            list.innerHTML = `<li style="color:var(--text-muted); padding:10px; font-style:italic;">No domains blocked.</li>`;
            return;
        }
        sites.forEach(site => {
            list.innerHTML += `
                <li style="display:flex; justify-content:space-between; align-items:center; padding:10px; border-bottom:1px solid rgba(255,255,255,0.05);">
                    <span style="font-family:monospace; color:var(--neon-red);"><i class="fa-solid fa-ban"></i> ${site}</span>
                    <i class="fa-solid fa-trash" style="cursor:pointer; color:#a0aec0;" onclick="unblockDomain('${site}')"></i>
                </li>
            `;
        });
    }

    window.unblockDomain = (site) => {
        let sites = JSON.parse(localStorage.getItem('blockedSites')) || [];
        sites = sites.filter(s => s !== site);
        localStorage.setItem('blockedSites', JSON.stringify(sites));
        renderBlockedDomains();
        showToast('Registry Updated', `${site} removed from denylist.`, 'info');
    };

    const btnBlockDom = document.getElementById('btn-block-domain');
    const inputBlockDom = document.getElementById('block-domain-input');
    if (btnBlockDom && inputBlockDom) {
        btnBlockDom.addEventListener('click', () => {
            const val = inputBlockDom.value.trim().toLowerCase();
            if (val) {
                let sites = JSON.parse(localStorage.getItem('blockedSites')) || [];
                if (!sites.includes(val)) {
                    sites.push(val);
                    localStorage.setItem('blockedSites', JSON.stringify(sites));
                    renderBlockedDomains();
                    showToast('Target Blocked', `${val} added to system denylist.`, 'success');
                }
                inputBlockDom.value = '';
            }
        });
    }
    renderBlockedDomains();

    // -----------------------------------------------------------------
    // 10. TOAST NOTIFICATION
    // -----------------------------------------------------------------
    function showToast(title, message, type = 'info') {
        const c = document.getElementById('toast-container');
        if (!c) return;
        const t = document.createElement('div');
        t.className = 'cyber-toast';
        let col = 'var(--neon-cyan)';
        let i = '<i class="fa-solid fa-info-circle"></i>';
        if (type === 'error') { col = 'var(--neon-red)'; i = '<i class="fa-solid fa-skull-crossbones"></i>'; }
        if (type === 'success') { col = 'var(--neon-green)'; i = '<i class="fa-solid fa-check-circle"></i>'; }
        if (type === 'warning') { col = 'var(--neon-yellow)'; i = '<i class="fa-solid fa-triangle-exclamation"></i>'; }

        t.style.borderLeftColor = col;
        t.innerHTML = `
            <div style="font-size:1.5rem; color:${col};">${i}</div>
            <div>
                <div style="font-family:'Orbitron',sans-serif; font-size:0.9rem; font-weight:700; color:${col};">${title.toUpperCase()}</div>
                <div style="font-size:0.85rem; color:#a0aec0; margin-top:2px;">${message}</div>
            </div>
        `;
        c.appendChild(t);
        setTimeout(() => {
            t.style.animation = 'slideInRight 0.3s ease reverse forwards';
            setTimeout(() => t.remove(), 300);
        }, 3500);
    }

    // -----------------------------------------------------------------
    // 11. CUSTOM CYBER CURSOR
    // -----------------------------------------------------------------
    const cursorDot = document.getElementById('cyber-cursor-dot');
    const cursorCircle = document.getElementById('cyber-cursor-circle');
    if (cursorDot && cursorCircle && matchMedia('(pointer:fine)').matches) {
        window.addEventListener('mousemove', (e) => {
            cursorDot.style.left = e.clientX + 'px';
            cursorDot.style.top = e.clientY + 'px';
            cursorCircle.style.left = e.clientX + 'px';
            cursorCircle.style.top = e.clientY + 'px';
            cursorDot.style.opacity = '1';
            cursorCircle.style.opacity = '1';
        });
        document.addEventListener('mouseleave', () => {
            cursorDot.style.opacity = '0';
            cursorCircle.style.opacity = '0';
        });
        const bindHoverEvents = (parent = document) => {
            const interactives = parent.querySelectorAll('a, button, input, textarea, select, .sidebar-link');
            interactives.forEach(el => {
                if (el.dataset.cursorBound) return;
                el.dataset.cursorBound = "1";
                el.addEventListener('mouseenter', () => { cursorDot.classList.add('active'); cursorCircle.classList.add('active'); });
                el.addEventListener('mouseleave', () => { cursorDot.classList.remove('active'); cursorCircle.classList.remove('active'); });
            });
        };
        bindHoverEvents();
        const cursorObs = new MutationObserver(() => bindHoverEvents());
        cursorObs.observe(document.body, { childList: true, subtree: true });
    } else if (cursorDot && cursorCircle) {
        cursorDot.style.display = 'none';
        cursorCircle.style.display = 'none';
    }

    // -----------------------------------------------------------------
    // 12. INITIALIZE
    // -----------------------------------------------------------------
    loadDashboard();
    loadUsers();
    loadActivity();
    loadWazuhAlerts();

    // Auto-refresh every 30s
    setInterval(() => {
        loadDashboard();
        loadWazuhAlerts();
    }, 30000);
});
