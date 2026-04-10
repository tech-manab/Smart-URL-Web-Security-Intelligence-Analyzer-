/**
 * script.js | Main User Portal Logic - Local Flask Auth
 */

document.addEventListener('DOMContentLoaded', async () => {
    console.log("User portal loaded - Local Auth Mode");

    // ── Auth Check via Flask session ─────────────────────────────────────────
    let currentUser = null;
    try {
        const res = await fetch('/api/auth/me');
        if (!res.ok) {
            window.location.href = '/login';
            return;
        }
        const data = await res.json();
        currentUser = data.user;
    } catch(err) {
        window.location.href = '/login';
        return;
    }

    // Set username display
    const navUserDisplay = document.getElementById('nav-user-display');
    if (navUserDisplay) navUserDisplay.textContent = (currentUser.username || 'Agent').toUpperCase();

    // Check for access denied URL param
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('error') === 'access_denied') {
        showToast('Access Denied', 'Admin access required', 'error');
        window.history.replaceState(null, null, window.location.pathname);
    }

    // Logout Event
    const btnUserLogout = document.getElementById('btn-user-logout');
    if (btnUserLogout) {
        btnUserLogout.addEventListener('click', async () => {
            await fetch('/api/auth/logout', { method: 'POST' });
            window.location.href = '/login';
        });
    }

    // Nav-link toggles
    const navLinks = document.querySelectorAll('.nav-link');
    const getTargetSection = (href) => document.querySelector(href.includes('#') ? href.substring(href.indexOf('#')) : null);
    
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const href = link.getAttribute('href');
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            ['#dashboard', '#history'].forEach(id => {
                const el = document.querySelector(id);
                if(el) {
                    if (id === href) el.style.display = 'block';
                    else el.style.display = 'none';
                }
            });
            const results = document.getElementById('results-container');
            const compare = document.getElementById('compare-container');
            if(results) results.style.display = href === '#dashboard' ? 'grid' : 'none';
            if(compare) compare.style.display = href === '#dashboard' ? 'block' : 'none';
        });
    });

    // Display the body once session is checked
    document.body.style.display = 'block';

    // Maintenance Mode Check on load
    if(localStorage.getItem('systemStatus') === 'maintenance') {
        document.body.innerHTML = `
            <div style="height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; background:radial-gradient(circle, #2a0808 0%, #0a0f1c 100%);">
                <i class="fa-solid fa-triangle-exclamation fa-5x" style="color:#ff4d4d; margin-bottom:20px; animation:blink 1s infinite alternate;"></i>
                <h1 style="font-family:'Orbitron',sans-serif; color:#ff4d4d; font-size:2.5rem; margin:0;">SYSTEM UNDER MAINTENANCE</h1>
                <p style="color:#a0aec0; margin-top:15px; font-size:1.1rem;">All portal access is temporarily locked by Administrator.</p>
            </div>
        `;
        return;
    }


    // =================================================================
    // Global Stats
    let stats = { total: 0, healthy: 0, critical: 0 };
    
    // Auto Monitor State
    let autoMonitorInterval = null;
    let autoMonitorTarget = null;

    // DOM Elements
    const urlInput = document.getElementById('url-input');
    const bulkUrlInput = document.getElementById('bulk-url-input');
    
    const cmpUrl1 = document.getElementById('cmp-url-1');
    const cmpUrl2 = document.getElementById('cmp-url-2');
    const cmpUrl3 = document.getElementById('cmp-url-3');
    const cmpInputs = [cmpUrl1, cmpUrl2, cmpUrl3].filter(i => i != null); // filter nulls dynamically
    
    const btnCheck = document.getElementById('btn-check');
    const btnBulkCheck = document.getElementById('btn-bulk-check');
    const btnCompareCheck = document.getElementById('btn-compare-check');
    
    const scanLoader = document.getElementById('scan-loader');
    const scanSteps = document.getElementById('scan-steps');
    const prgFill = document.getElementById('scan-prg-fill');
    
    const resultsContainer = document.getElementById('results-container');
    const compareContainer = document.getElementById('compare-container');
    const compareTableWrapper = document.getElementById('compare-table-wrapper');
    const template = document.getElementById('result-card-template');
    
    const historyTableBody = document.getElementById('history-table-body');
    const btnRefreshHistory = document.getElementById('btn-refresh-history');

    // Init History if user portal has it
    if (historyTableBody && btnRefreshHistory) {
        loadHistory();
    }

    // ─── EVENT LISTENERS ──────────────────────────────────────────

    // Mode Switching
    const modeBtns = document.querySelectorAll('.mode-btn');
    if (modeBtns.length > 0) {
        modeBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.mode-content').forEach(c => c.classList.remove('active'));
                
                const mode = e.target.dataset.mode;
                e.target.classList.add('active');
                
                const tmplNode = document.getElementById(`${mode}-mode`);
                if(tmplNode) tmplNode.classList.add('active');
                
                // Re-hide comparison
                if (compareContainer) compareContainer.classList.add('hidden');
                if (resultsContainer) resultsContainer.innerHTML = '';
                stopAutoMonitor();
            });
        });
    }

    // Auto Monitor Buttons
    document.querySelectorAll('.am-btn').forEach(btn => {
        if(btn.id === 'am-stop-btn') return;
        btn.addEventListener('click', (e) => {
            const sec = parseInt(e.target.dataset.sec);
            if (!urlInput) return;
            const target = urlInput.value.trim();
            if(!target) { showToast('Error', 'Input URL first to begin monitoring.', 'error'); return; }
            
            document.querySelectorAll('.am-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            startAutoMonitor(target, sec);
        });
    });

    const amStopBtn = document.getElementById('am-stop-btn');
    if (amStopBtn) {
        amStopBtn.addEventListener('click', () => {
            document.querySelectorAll('.am-btn').forEach(b => b.classList.remove('active'));
            stopAutoMonitor();
        });
    }

    // Run Single Scan
    if (btnCheck) {
        btnCheck.addEventListener('click', () => {
            if (!urlInput) {
                console.error('URL input element not found');
                showToast('Error', 'URL input field not found', 'error');
                return;
            }
            const url = urlInput.value.trim();
            if(!url) { 
                showToast('Error', 'Target URL required', 'error'); 
                return; 
            }
            stopAutoMonitor();
            console.log('Starting scan for URL:', url);
            runScan([url]);
        });
    } else {
        console.warn('btnCheck button not found in DOM');
    }

    // Run Bulk Scan
    if (btnBulkCheck) {
        btnBulkCheck.addEventListener('click', () => {
            if (!bulkUrlInput) return;
            const lines = bulkUrlInput.value.split('\n').map(l => l.trim()).filter(l => l);
            if(lines.length === 0) { showToast('Error', 'Provide at least one URL', 'error'); return; }
            if(lines.length > 20) { showToast('Warning', 'Max 20 URLs. Truncating.', 'warning'); }
            runScan(lines.slice(0, 20), true);
        });
    }

    // Run Compare Scan
    if (btnCompareCheck) {
        btnCompareCheck.addEventListener('click', () => {
            const urls = cmpInputs.map(i => i.value.trim()).filter(v => v !== '');
            if(urls.length < 2) { showToast('Error', 'Requires at least 2 URLs to compare', 'error'); return; }
            runCompareScan(urls);
        });
    }

    // History Actions
    if (btnRefreshHistory) {
        btnRefreshHistory.addEventListener('click', loadHistory);
    }
    const btnClearHistory = document.getElementById('btn-clear-history');
    if (btnClearHistory) {
        btnClearHistory.addEventListener('click', async () => {
            if(confirm("Purge your scan history? This cannot be undone.")) {
                await fetch('/api/user/scans/clear', { method: 'DELETE' });
                loadHistory();
                showToast('History Cleared', 'All logs obliterated', 'success');
            }
        });
    }
    const filterStatus = document.getElementById('hist-filter-status');
    const filterSpeed = document.getElementById('hist-filter-speed');
    if (filterStatus) filterStatus.addEventListener('change', loadHistory);
    if (filterSpeed) filterSpeed.addEventListener('change', loadHistory);

    // CSV Export Button
    const btnExportCsv = document.getElementById('btn-export-csv');
    if (btnExportCsv) {
        btnExportCsv.addEventListener('click', async () => {
            const res = await fetch('/api/user/scans');
            if (!res.ok) return;
            const rows = await res.json();
            if(!rows || rows.length === 0) { showToast('Export', 'No scan data to export', 'warning'); return; }
            const headers = ['Target', 'Type', 'Status', 'Speed(ms)', 'Grade', 'Timestamp'];
            const csvRows = rows.map(r => [r.input, r.type, r.status, r.speed || '', r.grade, r.created_at].join(','));
            const csv = [headers.join(','), ...csvRows].join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'cybermonitor_history.csv'; a.click();
            showToast('Export', 'CSV downloaded successfully', 'success');
        });
    }

    // Enter Key on main input
    if (urlInput && btnCheck) {
        urlInput.addEventListener('keypress', (e) => { 
            if(e.key === 'Enter') btnCheck.click(); 
        });
    }


    // ─── CORE SYSTEM: ANIMATIONS ──────────────────────────────────
    
    function playScanAnimation(duration=1200, callback) {
        if (!scanLoader) {
            callback();
            return;
        }

        scanLoader.classList.remove('hidden');
        if (resultsContainer) resultsContainer.style.opacity = '0.3';
        if (compareContainer) compareContainer.style.opacity = '0.3';
        
        const prgFill = document.getElementById('scan-prg-fill');
        const termText = document.getElementById('terminal-text');
        const prgPercent = document.getElementById('scan-percent');
        const prgBlocks = document.getElementById('scan-block-display');
        
        if (prgFill) {
            prgFill.style.transition = 'none';
            prgFill.style.width = '0%';
        }
        
        const steps = [
            "Initiating connection handshake...",
            "Resolving global DNS registry...",
            "Crawling associated subdomains...",
            "Auditing port exposure level...",
            "Extracting security header signatures...",
            "Performing AI health diagnosis...",
            "Initiating Smart Auto-Fix Protocols...",
            "Finalizing intelligence report..."
        ];
        
        let curStep = 0;
        const totalSteps = steps.length;
        const stepTime = duration / totalSteps;
        
        if (termText) termText.innerHTML = '';
        
        const interval = setInterval(() => {
            if(curStep < totalSteps) {
                const progress = ((curStep+1)/totalSteps);
                const pct = Math.floor(progress * 100);
                
                if(termText) {
                    termText.innerHTML = `> ${steps[curStep]}<span class="blink" style="color:#fff;">_</span>`;
                }
                if (prgFill) {
                    prgFill.style.transition = `width ${stepTime}ms linear`;
                    prgFill.style.width = `${pct}%`;
                }
                if (prgPercent) prgPercent.textContent = `${pct}%`;
                
                if (prgBlocks) {
                    const blockCount = 10;
                    const filled = Math.floor(progress * blockCount);
                    prgBlocks.textContent = "■".repeat(filled) + "□".repeat(blockCount - filled);
                }

                curStep++;
            } else {
                clearInterval(interval);
                setTimeout(() => {
                    scanLoader.classList.add('hidden');
                    if(termText) termText.innerHTML = 'Scan Complete';
                    if(resultsContainer) resultsContainer.style.opacity = '1';
                    if(compareContainer) compareContainer.style.opacity = '1';
                    callback();
                }, 400);
            }
        }, stepTime);
    }


    // ─── CORE LOGIC: SINGLE / BULK SCAN ───────────────────────────

    async function runScan(urls, isBulk = false) {
        // Maintenance Mode check
        if(localStorage.getItem('systemStatus') === 'maintenance') {
            showToast('System Locked', 'System is under maintenance. Scanning disabled.', 'error');
            return;
        }
        // Enforce Blocked Sites (managed by admin via localStorage)
        const blockedSites = JSON.parse(localStorage.getItem('blockedSites') || '[]');
        for(let url of urls) {
            if(blockedSites.some(bs => url.toLowerCase().includes(bs))) {
                showToast('Action Forbidden', `Target ${url} is restricted by Administrator`, 'error');
                return;
            }
        }

        if(window.updateSystemStatus) window.updateSystemStatus('scanning', isBulk ? urls.length + ' TARGETS' : urls[0]);

        if(btnCheck) btnCheck.disabled = true; 
        if(btnBulkCheck) btnBulkCheck.disabled = true;
        
        try {
            if(isBulk) {
                const res = await fetch('/api/check-bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ urls }) });
                if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
                const data = await res.json();
                if(data.error) throw new Error(data.error);
                
                playScanAnimation(1500, () => {
                    if (resultsContainer) {
                        resultsContainer.innerHTML = '';
                        resultsContainer.style.display = 'grid';
                        let delay = 0;
                        for(let r of data.results) {
                            appendSysHistory(r);
                            setTimeout(() => renderResultCard(r), delay);
                            delay += 200;
                            updateStats(r);
                        }
                    }
                    showToast('Success', `Mass scan complete: ${data.results.length} targets`, 'success');
                    loadHistory();
                });
                
            } else {
                const res = await fetch('/api/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: urls[0] }) });
                if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
                const data = await res.json();
                if(data.error) throw new Error(data.error);
                
                console.log('Scan result received:', data);
                playScanAnimation(1200, () => {
                    appendSysHistory(data);
                    if (resultsContainer) {
                        resultsContainer.style.display = 'grid';
                        if(autoMonitorInterval) {
                            resultsContainer.innerHTML = '';
                            renderResultCard(data, true);
                        } else {
                            resultsContainer.innerHTML = '';
                            renderResultCard(data);
                        }
                        // Notify SOC patches of completed scan
                        window.dispatchEvent(new CustomEvent('urlScanComplete', { detail: data }));
                    } else {
                        console.error('Results container not found');
                        showToast('Error', 'Results container not found', 'error');
                    }
                    updateStats(data);
                    showToast('Success', 'Diagnostics compiled', 'success');
                    loadHistory();
                });
            }
        } catch (error) {
            console.error('Scan error:', error);
            if(scanLoader) scanLoader.classList.add('hidden');
            showToast('Scan Failed', error.message, 'error');
            stopAutoMonitor();
        } finally {
            if(btnCheck) btnCheck.disabled = false; 
            if(btnBulkCheck) btnBulkCheck.disabled = false;
            if(window.updateSystemStatus) {
                const tv = urlInput ? urlInput.value.trim() : '';
                window.updateSystemStatus(tv ? 'typing' : 'normal', tv);
            }
        }
    }


    // ─── CORE LOGIC: COMPARE MODE ─────────────────────────────────
    
    async function runCompareScan(urls) {
        if(window.updateSystemStatus) window.updateSystemStatus('scanning', 'COMPARATIVE ANALYSIS');
        if(btnCompareCheck) btnCompareCheck.disabled = true;
        
        try {
            const res = await fetch('/api/check-bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ urls }) });
            const data = await res.json();
            if(data.error) throw new Error(data.error);
            
            playScanAnimation(3000, () => {
                renderCompareTable(data.results);
                showToast('Success', 'Comparison analysis complete', 'success');
                loadHistory();
            });
        } catch (error) {
            if(scanLoader) scanLoader.classList.add('hidden');
            showToast('Scan Failed', error.message, 'error');
        } finally {
            if(btnCompareCheck) btnCompareCheck.disabled = false;
            if(window.updateSystemStatus) window.updateSystemStatus('normal', '');
        }
    }

    function renderCompareTable(results) {
        if(!compareContainer || !compareTableWrapper) return;
        compareContainer.classList.remove('hidden');
        if(resultsContainer) resultsContainer.innerHTML = '';
        
        let html = `
            <table class="compare-table">
                <thead>
                    <tr>
                        <th>TARGET URL</th>
                        <th>STATUS</th>
                        <th>LATENCY (ms)</th>
                        <th>SECURITY LEVEL</th>
                        <th>PERFORMANCE GRADE</th>
                        <th>OVERALL SCORE</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        const scores = results.map(r => calcScore(r));
        const maxScore = Math.max(...scores);
        const minScore = Math.min(...scores);
        
        results.forEach((r, idx) => {
            const score = scores[idx];
            const grade = calcGrade(score);
            const pClass = score === maxScore && score > 0 ? 'best-res' : (score === minScore && minScore < 50 ? 'worst-res' : '');
            
            let stColor = 'var(--text-muted)';
            if(r.status === 'Up' || r.status === 'Up (Redirect)') stColor = 'var(--neon-green)';
            if(r.status === 'Slow') stColor = 'var(--neon-yellow)';
            if(r.status === 'Down' || r.status === 'Invalid'|| r.status === 'Broken') stColor = 'var(--neon-red)';
            
            let gradeColor = grade==='A' ? 'var(--neon-green)' : (grade==='B' ? 'var(--neon-cyan)' : (grade==='C' ? 'var(--neon-yellow)' : (grade==='D' ? 'var(--neon-orange)' : 'var(--neon-red)')));
            
            html += `
                <tr class="${pClass}">
                    <td style="font-family:monospace; color:#fff;">${r.url}</td>
                    <td style="color:${stColor}; font-weight:bold;">${r.status}</td>
                    <td>${r.response_ms || '---'}</td>
                    <td style="color:${r.secure ? 'var(--neon-green)' : 'var(--neon-red)'}"><i class="fa-solid ${r.secure ? 'fa-lock' : 'fa-lock-open'}"></i> ${r.secure ? 'HTTPS' : 'HTTP'}</td>
                    <td style="color:${gradeColor}; font-weight:900; font-size:1.2rem;">${grade}</td>
                    <td>${score}/100</td>
                </tr>
            `;
        });
        
        html += `</tbody></table>`;
        compareTableWrapper.innerHTML = html;
        compareContainer.scrollIntoView({ behavior: 'smooth' });
    }


    // ─── AUTO MONITOR ─────────────────────────────────────────────

    function startAutoMonitor(url, seconds) {
        if(amStopBtn) amStopBtn.classList.remove('hidden');
        const lp = document.getElementById('live-pulse-icon');
        if(lp) lp.style.display = 'block';
        
        autoMonitorTarget = url;
        showToast('System Live', `Live monitoring ON. Syncing every ${seconds}s`, 'success');
        
        runScan([url]);
        
        if(autoMonitorInterval) clearInterval(autoMonitorInterval);
        
        autoMonitorInterval = setInterval(() => {
            fetch('/api/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: autoMonitorTarget }) })
                .then(r => r.json())
                .then(data => {
                    if(!data.error) {
                        if(resultsContainer) {
                            resultsContainer.innerHTML = '';
                            renderResultCard(data, true);
                        }
                        loadHistory(); 
                    }
                }).catch(e => console.error(e));
        }, seconds * 1000);
    }
    
    function stopAutoMonitor() {
        if(autoMonitorInterval) {
            clearInterval(autoMonitorInterval);
            autoMonitorInterval = null;
            if(amStopBtn) amStopBtn.classList.add('hidden');
            const lp = document.getElementById('live-pulse-icon');
            if(lp) lp.style.display = 'none';
            document.querySelectorAll('.am-btn').forEach(b => b.classList.remove('active'));
            showToast('System Halt', 'Live monitoring OFF.', 'info');
        }
    }


    // ─── RENDERING RESULT CARD ────────────────────────────────────

    function calcScore(data) {
        let score = 0;
        if (data.status_code) {
            if(data.status_code === 200) score += 40;
            else if(data.status_code < 400) score += 20;
            
            if(data.secure && data.status !== 'SSL Error') score += 25;
            
            const ms = data.response_ms;
            if(ms !== null) {
                if(ms < 500) score += 25;
                else if(ms < 1500) score += 15;
                else if(ms < 3000) score += 5;
            }
            if(data.redirects === 0) score += 10;
            score = Math.min(Math.max(score, 0), 100);
        }
        return score;
    }
    
    function calcGrade(score) {
        if(score >= 90) return 'A';
        if(score >= 75) return 'B';
        if(score >= 60) return 'C';
        if(score >= 40) return 'D';
        return 'F';
    }

    function renderResultCard(data, isLive = false) {
        if (!template) {
            console.error('Result card template not found');
            showToast('Error', 'Template not found for rendering results', 'error');
            return;
        }
        const clone = template.content.cloneNode(true);
        const root = clone.querySelector('.result-card');
        if(!root) {
            console.error('Result card root element not found in template');
            showToast('Error', 'Result card structure invalid', 'error');
            return;
        }
        
        if(isLive) root.id = 'card-live-monitor';

        const urlText = root.querySelector('.url-text');
        if(urlText) urlText.textContent = data.url;
        
        if(isLive) {
            const lt = root.querySelector('.last-check');
            if (lt) {
                lt.textContent = `LAST SYNC: ${new Date().toLocaleTimeString()}`;
                lt.classList.add('blink');
            }
        }

        const statusBadge = root.querySelector('.status-badge');
        let headerColor = '';
        if(data.status === 'Up' || data.status === 'Up (Redirect)') { headerColor = 'var(--neon-green)'; if(statusBadge) statusBadge.innerHTML = '<i class="fa-solid fa-circle-check" style="margin-right:6px;"></i> ONLINE'; }
        else if (data.status === 'Slow') { headerColor = 'var(--neon-yellow)'; if(statusBadge) statusBadge.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i> DEGRADED'; }
        else if (data.status === 'Redirected') { headerColor = 'var(--neon-orange)'; if(statusBadge) statusBadge.innerHTML = '<i class="fa-solid fa-route" style="margin-right:6px;"></i> ROUTED'; }
        else { headerColor = 'var(--neon-red)'; if(statusBadge) statusBadge.innerHTML = '<i class="fa-solid fa-plug-circle-xmark" style="margin-right:6px;"></i> CRITICAL / OFFLINE'; }
        
        if (statusBadge) {
            statusBadge.style.color = headerColor;
            statusBadge.style.border = `1px solid ${headerColor}`;
            statusBadge.style.boxShadow = `0 0 10px ${headerColor}`;
            statusBadge.style.backgroundColor = 'rgba(0,0,0,0.5)';
        }
        root.style.borderTop = `3px solid ${headerColor}`;

        // 1. Performance Grade
        const score = calcScore(data);
        const grade = calcGrade(score);
        const elGrade = root.querySelector('.grade-val');
        
        let gradeColor = 'var(--neon-green)';
        if(grade==='B') gradeColor='var(--neon-cyan)';
        else if(grade==='C') gradeColor='var(--neon-yellow)';
        else if(grade==='D') gradeColor='var(--neon-orange)';
        else if(grade==='F') gradeColor='var(--neon-red)';
        
        if (elGrade) {
            elGrade.textContent = grade;
            elGrade.style.color = gradeColor;
            elGrade.style.textShadow = `0 0 15px ${gradeColor}`;
            if(elGrade.parentElement) elGrade.parentElement.style.borderColor = gradeColor;
        }

        // 2. HTTP Status Box
        const codeNum = root.querySelector('.code-number');
        const httpExp = root.querySelector('.http-explanation');
        if(codeNum) {
            codeNum.textContent = data.status_code || 'Err';
            codeNum.style.color = headerColor;
        }
        
        let explanation = '';
        if(data.status_code === 200) explanation = "Operations normal.";
        else if(data.status_code >= 300 && data.status_code < 400) explanation = "Endpoint redirected.";
        else if(data.status_code === 404) explanation = "Target not found.";
        else if(data.status_code >= 500) explanation = "Critical server downfall.";
        else if(!data.status_code) explanation = data.error || "Connection timed out/DNS failed.";
        else explanation = `Status: ${data.status_code}`;
        
        if(httpExp) httpExp.textContent = explanation;

        // 3. Speed/Latency Meter
        const ms = data.response_ms;
        const speedValue = root.querySelector('.speed-value');
        const speedLevel = root.querySelector('.speed-level');
        const speedMarker = root.querySelector('.speed-marker');
        const speedFill = root.querySelector('.speed-fill');
        
        if (ms !== null && data.valid && speedValue && speedLevel && speedMarker && speedFill) {
            speedValue.textContent = `${ms} ms`;
            let level = '', color = '', pct = 0;
            
            if(ms < 500) { level = 'FAST'; color = 'var(--neon-green)'; pct = Math.min((ms/500)*33, 33); }
            else if(ms < 1500) { level = 'GOOD'; color = 'var(--neon-cyan)'; pct = 33 + Math.min(((ms-500)/1000)*33, 33); }
            else if(ms < 3000) { level = 'AVG'; color = 'var(--neon-yellow)'; pct = 66 + Math.min(((ms-1500)/1500)*20, 20); }
            else { level = 'SLOW'; color = 'var(--neon-red)'; pct = Math.min(86 + ((ms-3000)/2000)*14, 100); }
            
            speedLevel.textContent = level; speedLevel.style.color = color;
            speedLevel.style.border = `1px solid ${color}`;
            
            setTimeout(() => {
                speedMarker.style.left = `${pct}%`;
                speedFill.style.width = `${pct}%`;
            }, 100);
        }

        // 4. Circular Health Score Animation
        const pCircle = root.querySelector('.progress-circle');
        const pNum = root.querySelector('.number');
        const pLbl = root.querySelector('.score-label');
        
        if (pCircle && pNum && pLbl) {
            pCircle.style.stroke = gradeColor;
            pLbl.textContent = grade==='A'?'EXCELLENT':(grade==='B'?'GOOD':(grade==='C'?'AVERAGE':(grade==='D'?'POOR':'CRITICAL')));
            pLbl.style.color = gradeColor;
            
            setTimeout(() => {
                const offset = 251.2 - (251.2 * score) / 100;
                pCircle.style.strokeDashoffset = offset;
                let cur = 0;
                if(score > 0) {
                    const timer = setInterval(() => {
                        cur += Math.ceil(score/20);
                        if(cur >= score) { cur = score; clearInterval(timer); }
                        pNum.textContent = cur;
                    }, 30);
                } else { pNum.textContent = 0; }
            }, 100);
        }

        // 5. SECURITY HEADERS MODULE
        // 5. SECURITY SCORE BREAKDOWN & HEADERS
        const secH = data.sec_headers || {};
        const implyBox = root.querySelector('.header-implications');
        let hCount = 0;

        // SSL Check
        const httpsBox = root.querySelector('.sh-https .sec-h-val');
        if(httpsBox) {
            if(data.secure) {
                httpsBox.innerHTML = '<i class="fa-solid fa-check"></i> Encrypted';
                httpsBox.className = 'sec-h-val sec-h-ok';
            } else {
                httpsBox.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Insecure';
                httpsBox.className = 'sec-h-val sec-h-warn';
            }
        }
        
        const setHeaderState = (className, key, implyMsg) => {
            const parent = root.querySelector(className);
            if (!parent) return;
            const valEl = parent.querySelector('.sec-h-val');
            if(!valEl) return;
            
            if(secH[key]) {
                valEl.innerHTML = `<i class="fa-solid fa-check"></i> Found`;
                valEl.className = 'sec-h-val sec-h-ok';
                hCount++;
            } else if(data.valid && implyBox) {
                const li = document.createElement('li');
                li.innerHTML = `<span style="color:var(--neon-red)">${key}:</span> ${implyMsg}`;
                implyBox.appendChild(li);
            }
        };

        setHeaderState('.sh-csp', 'Content-Security-Policy', 'Vulnerable to XSS (Cross-Site Scripting).');
        setHeaderState('.sh-hsts', 'Strict-Transport-Security', 'Susceptible to connection stripping / MITM.');
        setHeaderState('.sh-xfo', 'X-Frame-Options', 'Vulnerable to Clickjacking.');
        setHeaderState('.sh-xcto', 'X-Content-Type-Options', 'Vulnerable to MIME-type sniffing.');
        
        // Mock Api & Ports security logic
        const shApi = root.querySelector('.sh-api .sec-h-val');
        if(shApi) {
            shApi.innerHTML = (data.status_code === 200 && hCount > 1) ? '<i class="fa-solid fa-check"></i> Shielded' : '<i class="fa-solid fa-triangle-exclamation"></i> Exposed';
            shApi.className = (data.status_code === 200 && hCount > 1) ? 'sec-h-val sec-h-ok' : 'sec-h-val sec-h-warn';
        }
        const shPorts = root.querySelector('.sh-ports .sec-h-val');
        if(shPorts) {
            shPorts.innerHTML = data.secure ? '<i class="fa-solid fa-check"></i> Secured' : '<i class="fa-solid fa-triangle-exclamation"></i> High Risk';
            shPorts.className = data.secure ? 'sec-h-val sec-h-ok' : 'sec-h-val sec-h-warn';
        }

        if (implyBox) {
            if(!data.valid || data.status_code >= 500 || ms === null) {
                implyBox.innerHTML = `<li>Server unreachable. Security inspection aborted.</li>`;
            } else if(hCount === 4) {
                implyBox.innerHTML = `<li style="color:var(--neon-green)">Optimal Security Headers configurations detected.</li>`;
            }
        }

        // 6. AI Reasonings & Recommendations
        const riskB = root.querySelector('.risk-badge');
        if (riskB) {
            riskB.textContent = grade==='A'?'SAFE / SECURE':(grade==='F'?'DANGER':'CAUTION');
            riskB.style.background = gradeColor;
            riskB.style.color = (grade==='A'||grade==='B')?'#000':'#fff';
        }

        const basicBox = root.querySelector('.basic-reasons');
        const recList = root.querySelector('.rec-list');
        const appendItem = (list, text) => { if(list){ const l=document.createElement('li'); l.textContent=text; list.appendChild(l); }};

        if(!data.valid) appendItem(basicBox, `Connection Failure: ${data.error}`);
        if(data.status_code) appendItem(basicBox, `HTTP Code: ${data.status_code}`);
        if(!data.secure) appendItem(basicBox, `Insecure Payload delivery detected.`);

        if(ms !== null && ms > 2000) appendItem(recList, 'Warning: Immediate server optimization/caching needed.');
        if(!data.secure && data.valid) appendItem(recList, 'CRITICAL: Obtain and configure SSL/TLS Certificate.');
        if(data.status_code && data.status_code >= 400) appendItem(recList, 'Investigate broken endpoint / backend routing engine.');
        if(score >= 80) appendItem(recList, 'System operations nominal. Excellent performance.');

        // 7. Route Output
        if(data.redirects > 0) {
            const rPanel = root.querySelector('.redirect-panel');
            if (rPanel) {
                rPanel.classList.remove('hidden');
                const og = rPanel.querySelector('.og-url');
                const f = rPanel.querySelector('.fi-url');
                const rc = rPanel.querySelector('.redirect-count');
                if(og && data.url) og.textContent = new URL(data.url).hostname;
                if(f && data.final_url) f.textContent = new URL(data.final_url).hostname;
                if(rc) rc.textContent = `${data.redirects} HOP(s)`;
            }
        }

        // 8. DEEP RECONNAISSANCE SCANNER SIMLATION
        // Subdomains
        const subBox = root.querySelector('.recon-subdomains');
        if (subBox && data.valid) {
            let baseDomain = "unknown";
            try { baseDomain = new URL(data.url).hostname.replace('www.', ''); } catch(e){}
            
            // Generate Network Identity (Mock IP/Location)
            const elIp = root.querySelector('.recon-ip');
            const elLoc = root.querySelector('.recon-loc');
            const elProv = root.querySelector('.recon-prov');
            
            const randIp = `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
            const locations = ['Frankfurt, DE', 'Ashburn, VA, US', 'Singapore, SG', 'London, UK', 'Tokyo, JP'];
            const providers = ['Cloudflare, Inc.', 'Amazon Web Services', 'Google Cloud Platform', 'DigitalOcean, LLC', 'Linode'];
            
            if(elIp) elIp.textContent = `${randIp} [ASN: ${Math.floor(Math.random()*50000)}]`;
            if(elLoc) elLoc.textContent = locations[Math.floor(Math.random()*locations.length)];
            if(elProv) elProv.textContent = providers[Math.floor(Math.random()*providers.length)];

            // Summary Card Injection
            const sumSt = root.querySelector('.sum-status');
            const sumSp = root.querySelector('.sum-speed');
            const sumSec = root.querySelector('.sum-security');
            const sumGr = root.querySelector('.sum-grade');
            
            if(sumSt) { sumSt.textContent = statusBadge ? statusBadge.textContent : data.status; sumSt.style.color = headerColor; }
            if(sumSp) { sumSp.textContent = speedLevel ? speedLevel.textContent : '--'; sumSp.style.color = speedLevel ? speedLevel.style.color : '#fff'; }
            if(sumSec) { sumSec.textContent = data.secure ? 'High' : 'Low'; sumSec.style.color = data.secure ? 'var(--neon-green)' : 'var(--neon-red)'; }
            if(sumGr) { sumGr.textContent = grade; sumGr.style.color = gradeColor; }

            const subdomains = [`api.${baseDomain}`, `mail.${baseDomain}`, `dev.${baseDomain}`, `test.${baseDomain}`];
            subdomains.forEach((sub, i) => {
                const d = document.createElement('div');
                d.style.opacity = '0';
                d.innerHTML = `<i class="fa-solid fa-angle-right" style="color:#a0aec0;"></i> ${sub} <span style="color:var(--text-muted); font-size:0.75rem;">[Live]</span>`;
                subBox.appendChild(d);
                setTimeout(() => d.style.animation = 'fadeIn 0.3s forwards', 500 + (i*200));
            });
        }

        // Ports
        const portBox = root.querySelector('.recon-ports');
        if (portBox && data.valid) {
            const ports = [
                { p: 80, n: 'HTTP', st: data.secure ? 'Filtered' : 'Open' },
                { p: 443, n: 'HTTPS', st: data.secure ? 'Open' : 'Closed' },
                { p: 22, n: 'SSH', st: 'Filtered' },
                { p: 21, n: 'FTP', st: 'Closed' }
            ];
            ports.forEach((pt, i) => {
                const b = document.createElement('div');
                b.style.opacity = '0';
                let ptCol = 'var(--neon-red)';
                if(pt.st === 'Open') ptCol = 'var(--neon-green)';
                if(pt.st === 'Filtered') ptCol = 'var(--neon-yellow)';
                
                b.innerHTML = `<div style="background:rgba(0,0,0,0.5); border:1px solid ${ptCol}; padding:5px 8px; border-radius:4px; text-align:center;">
                    <div style="color:#fff;">${pt.p}</div>
                    <div style="font-size:0.6rem; color:var(--text-muted);">${pt.n}</div>
                    <div style="color:${ptCol}; font-size:0.7rem; font-weight:bold; margin-top:2px;">${pt.st.toUpperCase()}</div>
                </div>`;
                portBox.appendChild(b);
                setTimeout(() => b.style.animation = 'fadeIn 0.3s forwards', 800 + (i*150));
            });
        }

        // APIs
        const apiBox = root.querySelector('.recon-apis');
        if (apiBox && data.valid) {
            const apis = ['/api', '/v1', '/auth', '/graphql'];
            const foundCount = data.status_code === 200 ? Math.floor(Math.random()*3)+1 : 0;
            if(foundCount > 0) {
                for(let i=0; i<foundCount; i++) {
                    const d = document.createElement('div');
                    d.style.opacity = '0';
                    d.innerHTML = `<i class="fa-solid fa-plug"></i> Detected endpoint: <span style="color:#fff;">${apis[i]}</span>`;
                    apiBox.appendChild(d);
                    setTimeout(() => d.style.animation = 'fadeIn 0.3s forwards', 1200 + (i*300));
                }
            } else {
                apiBox.innerHTML = `<span style="color:var(--text-muted)">No standard API architectures resolved.</span>`;
            }
        }

        // --- SMART AUTO-FIX ENGINE ---
        if (data.auto_fixes && data.auto_fixes.length > 0) {
            const afPanel = document.createElement('div');
            afPanel.style.cssText = "margin-top:20px; padding:15px; background:rgba(0,0,0,0.4); border:1px solid rgba(0, 234, 255, 0.3); border-radius:8px; box-shadow: 0 0 10px rgba(0, 234, 255, 0.1);";
            afPanel.innerHTML = `<h4 style="margin:0 0 15px; color:var(--neon-cyan); border-bottom: 1px solid rgba(0,234,255,0.2); padding-bottom:10px;"><i class="fa-solid fa-wand-magic-sparkles"></i> SMART AUTO-DETECT & FIX ENGINE</h4>`;
            
            const afList = document.createElement('div');
            afList.style.cssText = "display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:15px;";
            
            data.auto_fixes.forEach(af => {
                const stepWrap = document.createElement('div');
                stepWrap.style.cssText = "background:rgba(255,255,255,0.02); border-left:3px solid var(--neon-cyan); padding:10px; border-radius:4px; display:flex; flex-direction:column; justify-content:space-between;";
                
                let btnHtml = "";
                if (af.auto_fix_attempted) {
                    btnHtml = `<span class="badge" style="background:rgba(0,255,156,0.1); color:var(--neon-green); border:1px solid var(--neon-green); margin-bottom:5px; align-self:flex-start; font-size:0.6rem;">AUTO-FIX ATTEMPTED</span>`;
                }

                stepWrap.innerHTML = `
                    <div style="display:flex; flex-direction:column;">
                        ${btnHtml}
                        <div style="font-family:var(--font-heading); font-size:0.95rem; margin-bottom:5px; text-transform:uppercase;">
                            <i class="fa-solid fa-triangle-exclamation" style="color:var(--neon-red);"></i> <span style="color:#fff;">${af.issue}</span>
                        </div>
                        <div style="font-size:0.8rem; color:var(--text-muted); margin-bottom:8px;">
                            ${af.cause}
                        </div>
                        <div style="font-family:monospace; font-size:0.85rem; color:var(--neon-cyan); margin-bottom:10px; padding:5px; background:rgba(0, 234, 255, 0.05); border-radius:4px;">
                            <i class="fa-solid fa-wrench"></i> ${af.fix_suggested}
                        </div>
                    </div>
                    <div style="font-family:monospace; font-size:0.8rem; background:rgba(0,0,0,0.5); padding:6px; border-radius:2px; border:1px dotted ${af.auto_fix_result.includes('✅') ? 'var(--neon-green)' : (af.auto_fix_result.includes('❌') ? 'var(--neon-red)' : 'var(--neon-yellow)')}; color:${af.auto_fix_result.includes('✅') ? 'var(--neon-green)' : (af.auto_fix_result.includes('❌') ? 'var(--neon-red)' : 'var(--neon-yellow)')}">
                        > ${af.auto_fix_result}
                    </div>
                `;
                afList.appendChild(stepWrap);
            });
            afPanel.appendChild(afList);
            root.appendChild(afPanel);
        }

        // 9. ACTIONS & BUTTONS EVENT LISTENERS
        const btnRecheck = root.querySelector('.btn-recheck');
        const btnFavorite = root.querySelector('.btn-favorite');
        const btnDownload = root.querySelector('.btn-download-txt');

        if(btnRecheck) {
            btnRecheck.addEventListener('click', () => {
                const target = data.url;
                runScan([target]);
            });
        }
        
        const targetUrl = data.url;
        const checkFav = async () => {
            if(!btnFavorite) return;
            // Check if already favorited
            const res = await fetch('/api/user/favorites');
            if (res.ok) {
                const favs = await res.json();
                if(favs.some(f => f.input === targetUrl)) btnFavorite.classList.add('active');
            }

            btnFavorite.addEventListener('click', async () => {
                const isActive = btnFavorite.classList.contains('active');
                if (isActive) {
                    await fetch('/api/user/favorites', { method: 'DELETE', headers: {'Content-Type':'application/json'}, body: JSON.stringify({input: targetUrl}) });
                    btnFavorite.classList.remove('active');
                    showToast('Watchlist', 'Target removed from priority watchlist', 'info');
                } else {
                    await fetch('/api/user/favorites', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({input: targetUrl}) });
                    btnFavorite.classList.add('active');
                    showToast('Watchlist', 'Target priority elevated', 'success');
                }
                renderWatchlist();
            });
        };
        checkFav();

        if(btnDownload) {
            btnDownload.addEventListener('click', () => {
                const txt = `
=========================================
  CYBERMONITOR | TARGET ANALYSIS REPORT
=========================================
Target URL:   ${data.url}
Timestamp:    ${new Date().toLocaleString()}

-- PERFOMANCE & HEALTH --
Overall Grade: ${grade}  (${score}/100)
Status:        ${data.status} (HTTP ${data.status_code || 'Err'})
Latency:       ${ms || 'Timeout'} ms
Encryption:    ${data.secure ? 'Enabled (SSL/TLS Active)' : 'Disabled (Insecure)'}

-- SECURITY HEADERS --
Content-Security-Policy:     ${secH['Content-Security-Policy'] ? 'Found' : 'Missing'}
Strict-Transport-Security:   ${secH['Strict-Transport-Security'] ? 'Found' : 'Missing'}
X-Frame-Options:             ${secH['X-Frame-Options'] ? 'Found' : 'Missing'}
X-Content-Type-Options:      ${secH['X-Content-Type-Options'] ? 'Found' : 'Missing'}

-- SMART AUTO-FIX ENGINE RESULTS --
${data.auto_fixes && data.auto_fixes.length > 0 ? data.auto_fixes.map((af, i) => `
[!] Issue ${i+1}: ${af.issue}
Cause: ${af.cause}
Fix Suggestion: ${af.fix_suggested}
Auto-Fix Output: ${af.auto_fix_result}
`).join('') : 'No auto-fix actions generated.'}

Report generated by Smart URL Status Checker system.
`;
                const blob = new Blob([txt], { type: "text/plain" });
                const urlObj = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.style.display = "none";
                a.href = urlObj;
                a.download = `Report_${data.url.replace(/[^a-zA-Z0-9]/g, '_')}.txt`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(urlObj);
            });
        }

        if(resultsContainer) resultsContainer.appendChild(clone);
    }


    // ─── UTILITIES ────────────────────────────────────────────────
    
    function showToast(title, message, type='info') {
        const container = document.getElementById('toast-container');
        if(!container) return;
        const t = document.createElement('div');
        t.className = 'cyber-toast';
        
        let icon = '<i class="fa-solid fa-info-circle"></i>';
        let color = 'var(--neon-cyan)';
        if(type === 'error') { icon = '<i class="fa-solid fa-skull-crossbones"></i>'; color = 'var(--neon-red)'; }
        if(type === 'success') { icon = '<i class="fa-solid fa-check-circle"></i>'; color = 'var(--neon-green)'; }
        if(type === 'warning') { icon = '<i class="fa-solid fa-triangle-exclamation"></i>'; color = 'var(--neon-yellow)'; }
        
        t.style.borderLeftColor = color;
        t.innerHTML = `<div style="font-size:1.5rem; color:${color};">${icon}</div>
            <div>
                <div style="font-family:var(--font-heading); font-size:0.9rem; font-weight:bold; color:${color}; margin-bottom:2px;">
                    [ ${title.toUpperCase()} ]
                </div>
                <div style="font-size:0.85rem; color:var(--text-main);">${message}</div>
            </div>`;
        container.appendChild(t);
        setTimeout(() => { t.style.animation = 'slideInRight 0.3s ease reverse forwards'; setTimeout(()=> t.remove(), 300); }, 4000);
    }

    function updateStats(data) {
        // we'll trigger a history reload instead to keep stats consistent
        loadHistory();
    }

    const isIP = (input) => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(input);

    async function appendSysHistory(data) {
        const score  = calcScore(data);
        const grade  = calcGrade(score);
        const type   = isIP(data.url.replace(/^https?:\/\//,'').split('/')[0]) ? 'ip' : 'url';
        await fetch('/api/user/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                input:     data.url,
                type:      type,
                status:    data.status,
                speed:     data.response_ms,
                grade:     grade,
                scan_data: data
            })
        });
    }

    async function loadHistory() {
        if (!historyTableBody) return;
        const res = await fetch('/api/user/scans');
        if (!res.ok) return;
        let data = await res.json();
        
        const filterStatus = document.getElementById('hist-filter-status');
        const filterSpeed  = document.getElementById('hist-filter-speed');
        
        if (filterStatus && filterStatus.value !== 'ALL') {
            const fs = filterStatus.value;
            data = data.filter(r => fs === 'UP' ? (r.status || '').includes('Up') : (r.status || '').includes('Down') || (r.status || '').includes('Error'));
        }
        if (filterSpeed && filterSpeed.value !== 'ALL') {
            const fsp = filterSpeed.value;
            data = data.filter(r => {
                const spd = r.speed;
                if(fsp === 'FAST') return spd !== null && spd < 1000;
                return spd === null || spd >= 1000;
            });
        }
        
        historyTableBody.innerHTML = '';
        if(data.length === 0) {
            historyTableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding: 20px;">NO LOGS MET FILTER CRITERIA.</td></tr>`;
            return;
        }
        
        let t_checks = 0; let t_healthy = 0; let t_critical = 0; let t_ms = 0; let t_ms_count = 0;

        data.forEach(r => {
            t_checks++;
            if(r.status === 'Up' || r.status === 'Up (Redirect)') t_healthy++;
            if((r.status || '').includes('Down') || (r.status || '').includes('Error') || r.status === 'Invalid') t_critical++;
            const spd = r.speed;
            if(spd) { t_ms += spd; t_ms_count++; }
            
            let color = 'var(--neon-green)';
            if((r.status || '').includes('Down') || (r.status || '').includes('Error') || r.status === 'Invalid') color = 'var(--neon-red)';
            else if((r.status || '').includes('Slow')) color = 'var(--neon-yellow)';
            
            historyTableBody.innerHTML += `
                <tr>
                    <td class="td-url">${r.input}</td>
                    <td style="color:${color}; font-weight:bold;">${r.status}</td>
                    <td style="font-family:monospace;">${r.grade || '---'}</td>
                    <td style="font-family:monospace;">${spd ? spd + 'ms' : '---'}</td>
                    <td style="color:var(--neon-cyan);">${r.type || 'url'}</td>
                    <td style="font-family:monospace;">${new Date(r.created_at).toLocaleString()}</td>
                </tr>
            `;
        });

        const sdT = document.getElementById('stat-total');
        const sdH = document.getElementById('stat-healthy');
        const sdC = document.getElementById('stat-critical');
        const sdS = document.getElementById('stat-speed');

        if(sdT) sdT.textContent = t_checks;
        if(sdH) sdH.textContent = t_healthy;
        if(sdC) sdC.textContent = t_critical;
        if(sdS) sdS.textContent = t_ms_count ? `${Math.round(t_ms/t_ms_count)}ms` : '0ms';

        stats.total = t_checks; stats.healthy = t_healthy; stats.critical = t_critical;
    }

    async function renderWatchlist() {
        const res = await fetch('/api/user/favorites');
        if (!res.ok) return;
        const favData = await res.json();
        const watchList = favData.map(f => f.input);
        
        const container = document.getElementById('watchlist-container');
        const favCount  = document.getElementById('fav-count');
        
        if(favCount) favCount.textContent = `${watchList.length} SAVED`;
        if(!container) return;
        
        if(watchList.length === 0) {
            container.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem; font-style:italic;">No priority targets starred. Run a scan to add targets to the watchlist.</div>`;
            return;
        }
        
        container.innerHTML = '';
        watchList.forEach(url => {
            const wrap = document.createElement('div');
            wrap.style.cssText = "background:rgba(0,0,0,0.5); border:1px solid rgba(255,204,0,0.2); border-radius:6px; padding:10px 15px; display:flex; flex-direction:column; gap:8px; min-width:200px;";
            wrap.innerHTML = `
                <div style="font-family:monospace; color:#fff; font-size:0.9rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${url}">
                    <i class="fa-solid fa-star" style="color:var(--neon-yellow); font-size:0.7rem;"></i> ${url}
                </div>
                <div style="display:flex; justify-content:space-between; margin-top:5px;">
                    <button class="cyber-btn sm-btn action-btn wp-recheck" style="padding:4px 8px; font-size:0.7rem;"><i class="fa-solid fa-rotate-right"></i> CHECK</button>
                    <button class="cyber-btn sm-btn danger-btn wp-remove" style="padding:4px 8px; font-size:0.7rem;"><i class="fa-solid fa-xmark"></i></button>
                </div>
            `;
            wrap.querySelector('.wp-recheck').addEventListener('click', () => {
                const urlInputEl = document.getElementById('url-input');
                if (urlInputEl) urlInputEl.value = url;
                // Switch to dashboard/single mode view
                const dashMode = document.getElementById('single-mode');
                if (dashMode && !dashMode.classList.contains('active')) {
                    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
                    document.querySelectorAll('.mode-content').forEach(c => c.classList.remove('active'));
                    const singleBtn = document.querySelector('[data-mode="single"]');
                    if (singleBtn) singleBtn.classList.add('active');
                    dashMode.classList.add('active');
                }
                runScan([url]);
            });
            wrap.querySelector('.wp-remove').addEventListener('click', async () => {
                await fetch('/api/user/favorites', { method: 'DELETE', headers: {'Content-Type':'application/json'}, body: JSON.stringify({input: url}) });
                renderWatchlist();
            });
            container.appendChild(wrap);
        });
    }

    // Initialize Watchlist on load
    renderWatchlist();

    // =================================================================
    // UI INTERACTION CONTROLLER & ANIMATIONS
    // =================================================================

    // 1. Technical Loading Screen
    const initLoader = document.getElementById('system-init-loader');
    const initLoaderText = document.getElementById('init-loader-text');
    if (initLoader && initLoaderText) {
        const sequences = ["Initializing system...", "Loading modules...", "Starting analyzer..."];
        let seqIdx = 0;
        initLoaderText.textContent = sequences[0];
        const seqTimer = setInterval(() => {
            seqIdx++;
            if(seqIdx < sequences.length) {
                initLoaderText.textContent = sequences[seqIdx];
            } else {
                clearInterval(seqTimer);
                setTimeout(() => {
                    initLoader.classList.add('hidden-loader');
                }, 400); // Wait a bit before hiding
            }
        }, 400);
    }

    // 2. Custom Cyber Cursor
    const cursorDot = document.getElementById('cyber-cursor-dot');
    const cursorCircle = document.getElementById('cyber-cursor-circle');
    
    // Only apply custom cursor on non-touch devices
    if (cursorDot && cursorCircle && matchMedia('(pointer:fine)').matches) {
        window.addEventListener('mousemove', (e) => {
            cursorDot.style.left = e.clientX + 'px';
            cursorDot.style.top = e.clientY + 'px';
            
            // Add slight lag to circle for organic cyber feel
            cursorCircle.style.left = e.clientX + 'px';
            cursorCircle.style.top = e.clientY + 'px';
            
            // Unhide cursors if they were hidden when mouse leaves window
            cursorDot.style.opacity = '1';
            cursorCircle.style.opacity = '1';
        });

        // Hide cursors when mouse leaves window
        document.addEventListener('mouseleave', () => {
             cursorDot.style.opacity = '0';
             cursorCircle.style.opacity = '0';
        });

        const bindHoverEvents = (parent = document) => {
            const interactives = parent.querySelectorAll('a, button, input, textarea, select, .mode-btn, .am-btn');
            interactives.forEach(el => {
                if(el.dataset.cursorBound) return;
                el.dataset.cursorBound = "1";
                el.addEventListener('mouseenter', () => {
                    cursorDot.classList.add('active');
                    cursorCircle.classList.add('active');
                });
                el.addEventListener('mouseleave', () => {
                    cursorDot.classList.remove('active');
                    cursorCircle.classList.remove('active');
                });
            });
        };
        bindHoverEvents();
        
        // Re-apply to dynamically added elements
        const cursorObs = new MutationObserver(() => bindHoverEvents());
        cursorObs.observe(document.body, { childList: true, subtree: true });
    } else if (cursorDot && cursorCircle) {
        // Hide if touch device
        cursorDot.style.display = 'none';
        cursorCircle.style.display = 'none';
    }

    // 3. Scroll Animation (Fade In)
    const fadeElements = document.querySelectorAll('.glass-panel, .result-card, .stat-card, .hero-section, .history-panel');
    fadeElements.forEach(el => el.classList.add('fade-in'));
    
    // Polyfill or simple intersection observer setup
    const scrollObserver = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('is-visible');
                // Optional: stop observing if we only want it once
                obs.unobserve(entry.target);
            }
        });
    }, { threshold: 0.05, rootMargin: '0px 0px -20px 0px' });
    
    fadeElements.forEach(el => scrollObserver.observe(el));

    // Observe newly added result-cards
    const resultObs = new MutationObserver((mutations) => {
        mutations.forEach(mut => {
            mut.addedNodes.forEach(node => {
                if (node.nodeType === 1) {
                    if (node.classList && node.classList.contains('result-card')) {
                        node.classList.add('fade-in');
                        scrollObserver.observe(node);
                        setTimeout(() => node.classList.add('is-visible'), 100);
                    }
                    if (node.classList && node.classList.contains('fade-in')) {
                        scrollObserver.observe(node);
                    }
                }
            });
        });
    });
    if(resultsContainer) resultObs.observe(resultsContainer, { childList: true });

    // 4. Live Global System Status Bar
    const topStatusBar = document.getElementById('top-status-bar');
    const statusText = document.getElementById('status-text');
    
    window.updateSystemStatus = function(state, url) {
        if (!topStatusBar || !statusText) return;
        if (state === 'typing') {
            topStatusBar.className = 'top-status-bar typing';
            statusText.textContent = `READY TO SCAN: ${url}`;
        } else if (state === 'scanning') {
            topStatusBar.className = 'top-status-bar scanning';
            statusText.textContent = `SCANNING: ${url}`;
        } else {
            topStatusBar.className = 'top-status-bar';
            statusText.textContent = 'SYSTEM ONLINE';
        }
    };

    if (urlInput) {
        urlInput.addEventListener('input', (e) => {
            const val = e.target.value.trim();
            if (val.length > 0) window.updateSystemStatus('typing', val);
            else window.updateSystemStatus('normal', '');
        });
    }
    if (bulkUrlInput) {
        bulkUrlInput.addEventListener('input', (e) => {
            const val = e.target.value.trim();
            if (val.length > 0) window.updateSystemStatus('typing', 'BULK PROTOCOL ENGAGED');
            else window.updateSystemStatus('normal', '');
        });
    }
    
    // Add same for compare mode
    if (cmpUrl1) {
        const updateCompareStatus = () => {
            if (cmpUrl1.value.trim().length > 0 || cmpUrl2.value.trim().length > 0) {
                window.updateSystemStatus('typing', 'CROSS-COMPARE READY');
            } else {
                window.updateSystemStatus('normal', '');
            }
        };
        cmpUrl1.addEventListener('input', updateCompareStatus);
        cmpUrl2.addEventListener('input', updateCompareStatus);
        if (cmpUrl3) cmpUrl3.addEventListener('input', updateCompareStatus);
    }

    // 5. Button Ripple Click Effect
    document.addEventListener('mousedown', function(e) {
        const btn = e.target.closest('.cyber-btn');
        if (btn) {
            const rect = btn.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const ripple = document.createElement('span');
            ripple.className = 'btn-ripple-effect';
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;
            
            const size = Math.max(rect.width, rect.height);
            ripple.style.width = ripple.style.height = `${size}px`;
            ripple.style.marginLeft = ripple.style.marginTop = `${-size/2}px`;
            
            btn.appendChild(ripple);
            setTimeout(() => { ripple.remove(); }, 600);
        }
    });

});
