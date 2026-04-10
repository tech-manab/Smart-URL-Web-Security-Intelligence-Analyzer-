/**
 * login.js | Local Flask Auth - No Supabase
 */
document.addEventListener('DOMContentLoaded', async () => {
    console.log("Login page loaded - Local Auth Mode");

    // ── Check if already logged in ───────────────────────────────────────────
    try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
            const data = await res.json();
            if (data.user) {
                window.location.href = data.user.role === 'admin' ? '/admin' : '/';
                return;
            }
        }
    } catch(e) {
        // Not logged in - show login form normally
    }

    const loginForm  = document.getElementById('user-login-form');
    const signupForm = document.getElementById('user-signup-form');
    const errBox     = document.getElementById('login-error');
    const errTxt     = document.getElementById('auth-err-text');
    const panel      = document.getElementById('login-box');

    function showError(msg) {
        if (!errBox || !errTxt) return;
        errTxt.innerHTML = msg;
        errBox.classList.remove('hidden');
        // Shake animation
        if (panel) {
            panel.classList.remove('shake');
            void panel.offsetWidth;
            panel.classList.add('shake');
        }
    }

    function clearError() {
        if (errBox) errBox.classList.add('hidden');
    }

    // ── Toggle between Login / Signup forms ──────────────────────────────────
    const goSignupBtn = document.getElementById('go-signup');
    if (goSignupBtn) {
        goSignupBtn.addEventListener('click', (e) => {
            e.preventDefault();
            clearError();
            if (loginForm) loginForm.classList.add('hidden');
            if (signupForm) signupForm.classList.remove('hidden');
        });
    }

    const goLoginBtn = document.getElementById('go-login');
    if (goLoginBtn) {
        goLoginBtn.addEventListener('click', (e) => {
            e.preventDefault();
            clearError();
            if (signupForm) signupForm.classList.add('hidden');
            if (loginForm) loginForm.classList.remove('hidden');
        });
    }

    // ── SIGNUP ───────────────────────────────────────────────────────────────
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const u = document.getElementById('user-signup-name').value.trim();
            const p = document.getElementById('user-signup-pass').value;
            if (!u || !p) return;

            const btn = signupForm.querySelector('button[type="submit"]');
            if (btn) { btn.disabled = true; btn.textContent = 'Creating...'; }

            try {
                const res  = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p })
                });
                const data = await res.json();

                if (!res.ok) {
                    showError(data.error || 'Signup failed');
                } else {
                    window.location.href = '/';
                }
            } catch (err) {
                showError('Server connection failed. Is Flask running?');
            } finally {
                if (btn) { btn.disabled = false; btn.textContent = 'CREATE PROFILE'; }
            }
        });
    }

    // ── LOGIN ────────────────────────────────────────────────────────────────
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const u = document.getElementById('user-login-name').value.trim();
            const p = document.getElementById('user-login-pass').value;
            if (!u || !p) return;

            const btn = loginForm.querySelector('button[type="submit"]');
            if (btn) { btn.disabled = true; btn.textContent = 'Connecting...'; }

            try {
                const res  = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p })
                });
                const data = await res.json();

                if (!res.ok) {
                    showError(data.error || 'Access Denied');
                } else {
                    // Redirect based on role
                    window.location.href = data.user.role === 'admin' ? '/admin' : '/';
                }
            } catch (err) {
                showError('Server connection failed. Is Flask running?');
            } finally {
                if (btn) { btn.disabled = false; btn.textContent = 'CONNECT'; }
            }
        });
    }

    // ── Custom Cyber Cursor ──────────────────────────────────────────────────
    const cursorDot    = document.getElementById('cyber-cursor-dot');
    const cursorCircle = document.getElementById('cyber-cursor-circle');

    if (cursorDot && cursorCircle && matchMedia('(pointer:fine)').matches) {
        window.addEventListener('mousemove', (e) => {
            cursorDot.style.left    = e.clientX + 'px';
            cursorDot.style.top     = e.clientY + 'px';
            cursorCircle.style.left = e.clientX + 'px';
            cursorCircle.style.top  = e.clientY + 'px';
            cursorDot.style.opacity    = '1';
            cursorCircle.style.opacity = '1';
        });
        document.addEventListener('mouseleave', () => {
            cursorDot.style.opacity    = '0';
            cursorCircle.style.opacity = '0';
        });
        const interactives = document.querySelectorAll('a, button, input');
        interactives.forEach(el => {
            el.addEventListener('mouseenter', () => {
                cursorDot.classList.add('active');
                cursorCircle.classList.add('active');
            });
            el.addEventListener('mouseleave', () => {
                cursorDot.classList.remove('active');
                cursorCircle.classList.remove('active');
            });
        });
    } else if (cursorDot && cursorCircle) {
        cursorDot.style.display    = 'none';
        cursorCircle.style.display = 'none';
    }
});
