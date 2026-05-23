// 认证相关功能

// 全局状态
let turnstileWidgetId = null;

// 初始化登录页面
function initLoginPage(config) {
    const form = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');

    // 初始化 CAPTCHA
    if (config.captchaProvider === 'cloudflare' && typeof turnstile !== 'undefined') {
        turnstileWidgetId = turnstile.render('#login-turnstile', {
            sitekey: config.turnstileSiteKey,
            callback: function(token) {
                document.getElementById('cf-token-hidden').value = token;
            }
        });
    } else if (config.captchaProvider === 'altcha') {
        initAltcha('login-altcha-widget', 'altcha-payload');
    }

    // 表单提交
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        let captchaResponse = '';

        // 获取 CAPTCHA 响应
        if (config.captchaProvider === 'cloudflare') {
            captchaResponse = document.getElementById('cf-token-hidden').value;
        } else if (config.captchaProvider === 'cha') {
            captchaResponse = document.getElementById('cha-answer').value;
        } else if (config.captchaProvider === 'altcha') {
            captchaResponse = document.getElementById('altcha-payload').value;
        }

        if (!email || !password) {
            showError('请填写所有必填项');
            return;
        }

        if (!captchaResponse) {
            showError('请完成人机验证');
            return;
        }

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    cf_token: captchaResponse
                })
            });

            const data = await response.json();

            if (data.success) {
                // 登录成功，跳转首页
                window.location.href = '/';
            } else {
                showError(data.error || '登录失败');
            }
        } catch (error) {
            console.error('登录错误:', error);
            showError('网络错误，请稍后重试');
        }
    });

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
        setTimeout(() => {
            errorMessage.style.display = 'none';
        }, 5000);
    }
}

// 初始化注册页面
function initRegisterPage(config) {
    const form = document.getElementById('register-form');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const passwordInput = document.getElementById('password');
    const passwordStrength = document.getElementById('password-strength');

    // 密码强度检测
    passwordInput.addEventListener('input', (e) => {
        const password = e.target.value;
        let strength = 0;

        if (password.length >= 6) strength++;
        if (password.length >= 10) strength++;
        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^a-zA-Z0-9]/.test(password)) strength++;

        const strengthText = ['很弱', '弱', '中等', '强', '很强'];
        const strengthColor = ['#ff4444', '#ff8800', '#ffcc00', '#88cc00', '#00cc88'];

        if (password.length > 0) {
            passwordStrength.textContent = '密码强度: ' + strengthText[strength - 1] || '很弱';
            passwordStrength.style.color = strengthColor[strength - 1] || '#ff4444';
        } else {
            passwordStrength.textContent = '';
        }
    });

    // 初始化 CAPTCHA
    if (config.captchaProvider === 'cloudflare' && typeof turnstile !== 'undefined') {
        turnstileWidgetId = turnstile.render('#register-turnstile', {
            sitekey: config.turnstileSiteKey,
            callback: function(token) {
                document.getElementById('cf-token-hidden').value = token;
            }
        });
    } else if (config.captchaProvider === 'altcha') {
        initAltcha('register-altcha-widget', 'altcha-payload');
    }

    // 表单提交
    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const email = document.getElementById('email').value.trim().toLowerCase();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        let captchaResponse = '';

        // 获取 CAPTCHA 响应
        if (config.captchaProvider === 'cloudflare') {
            captchaResponse = document.getElementById('cf-token-hidden').value;
        } else if (config.captchaProvider === 'cha') {
            captchaResponse = document.getElementById('cha-answer').value;
        } else if (config.captchaProvider === 'altcha') {
            captchaResponse = document.getElementById('altcha-payload').value;
        }

        // 验证
        if (!email || !password || !confirmPassword) {
            showError('请填写所有必填项');
            return;
        }

        if (password !== confirmPassword) {
            showError('两次输入的密码不一致');
            return;
        }

        if (password.length < 6) {
            showError('密码长度至少6位');
            return;
        }

        if (!captchaResponse) {
            showError('请完成人机验证');
            return;
        }

        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    username: username,
                    cf_token: captchaResponse
                })
            });

            const data = await response.json();

            if (data.success) {
                showSuccess(data.message + '，即将跳转到登录页面...');
                setTimeout(() => {
                    window.location.href = '/auth/login';
                }, 3000);
            } else {
                showError(data.error || '注册失败');
            }
        } catch (error) {
            console.error('注册错误:', error);
            showError('网络错误，请稍后重试');
        }
    });

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
        successMessage.style.display = 'none';
    }

    function showSuccess(message) {
        successMessage.textContent = message;
        successMessage.style.display = 'block';
        errorMessage.style.display = 'none';
    }
}

// Altcha 初始化（加载并求解挑战）
function initAltcha(widgetId, payloadInputId) {
    // 加载 Altcha 挑战并自动求解，填入隐藏输入框
    // widgetId: the div where the challenge UI will be rendered
    // payloadInputId: the hidden input to store the solved payload JSON
    fetch('/api/altcha/challenge')
        .then(r => r.json())
        .then(data => {
            const widget = document.getElementById(widgetId);
            if (!widget) return;
            widget.innerHTML = `
                <div class="altcha-info">
                    <p>🔐 人机验证</p>
                    <p style="font-size: 12px; color: #666;">正在计算工作量证明...</p>
                    <div class="altcha-progress"><div id="${widgetId}-progress" style="width: 0%;"></div></div>
                    <p id="${widgetId}-status" style="font-size: 12px; color: #666;">初始化中...</p>
                </div>`;
            // 开始求解挑战
            solveAltchaChallenge(data.challenge, data.salt, data.signature, data.target_prefix, data.max_number, widgetId, payloadInputId);
        })
        .catch(err => {
            console.error('加载 Altcha 挑战失败', err);
        });
}

// 求解 Altcha 挑战的通用实现（从 verify.js 中抽取）
function solveAltchaChallenge(challenge, salt, signature, targetPrefix, maxNumber, widgetId, payloadInputId) {
    const startTime = Date.now();
    const progressEl = document.getElementById(`${widgetId}-progress`);
    const statusEl = document.getElementById(`${widgetId}-status`);
    const chunkSize = 10000;
    const simpleSha256 = async (msg) => {
        const msgBuffer = new TextEncoder().encode(msg);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    };
    const loop = async (i) => {
        if (i >= maxNumber) {
            statusEl.textContent = '验证失败，请刷新页面重试';
            progressEl.style.background = '#f44336';
            return;
        }
        const testString = challenge + i;
        const hash = await simpleSha256(testString);
        if (i % chunkSize === 0) {
            const progress = Math.min((i / maxNumber) * 100, 100);
            progressEl.style.width = progress + '%';
            statusEl.textContent = `计算中... ${Math.floor(progress)}%`;
            await new Promise(r => setTimeout(r, 0));
        }
        if (hash.startsWith(targetPrefix)) {
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
            const widget = document.getElementById(widgetId);
            widget.innerHTML = `<div class="altcha-success">✓ 验证完成 (${elapsed}s)</div>`;
            const payload = JSON.stringify({
                challenge: challenge,
                number: i,
                salt: salt,
                signature: signature,
                hash_result: hash
            });
            const payloadInput = document.getElementById(payloadInputId);
            if (payloadInput) payloadInput.value = payload;
            return;
        }
        // continue next iteration
        if (i % 1000 === 0) {
            // allow UI to update
            setTimeout(() => loop(i + 1), 0);
        } else {
            loop(i + 1);
        }
    };
    loop(0);
}

// 检查登录状态
async function checkLoginStatus() {
    try {
        const response = await fetch('/api/user/profile');
        if (response.ok) {
            const data = await response.json();
            return data.user;
        }
    } catch (error) {
        console.error('检查登录状态失败:', error);
    }
    return null;
}

// 登出
async function logout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
        window.location.href = '/';
    } catch (error) {
        console.error('登出失败:', error);
    }
}
