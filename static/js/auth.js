// 认证相关功能

// 全局状态
let turnstileWidgetId = null;

// 显示警告信息
function showWarning(message) {
    console.log('showWarning 被调用');
    // 创建或获取警告元素
    let warningElement = document.getElementById('warning-message');
    if (!warningElement) {
        warningElement = document.createElement('div');
        warningElement.id = 'warning-message';
        warningElement.style.cssText = 'background-color: #fff3cd; border: 1px solid #ffc107; color: #856404; padding: 15px; border-radius: 5px; margin: 15px 0; white-space: pre-wrap; font-size: 12px;';
        // 插入到错误消息之后
        const errorElement = document.getElementById('error-message');
        if (errorElement && errorElement.parentNode) {
            errorElement.parentNode.insertBefore(warningElement, errorElement.nextSibling);
        } else {
            // 如果找不到错误消息元素，添加到表单前面
            const form = document.getElementById('login-form') || document.getElementById('register-form');
            if (form) {
                form.parentNode.insertBefore(warningElement, form);
            }
        }
    }
    warningElement.textContent = message;
    warningElement.style.display = 'block';
}

// 检测是否为移动设备
function isMobileDevice() {
    return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

// 初始化登录页面
function initLoginPage(config) {
    console.log('initLoginPage 被调用, config:', config);

    const form = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');

    if (!form) {
        console.error('登录表单元素未找到');
        return;
    }

    console.log('登录表单元素已找到，准备绑定事件');

    // 初始化 CAPTCHA
    try {
        if (config.captchaProvider === 'cloudflare' && typeof turnstile !== 'undefined') {
            turnstileWidgetId = turnstile.render('#login-turnstile', {
                sitekey: config.turnstileSiteKey,
                callback: function(token) {
                    document.getElementById('cf-token-hidden').value = token;
                }
            });
        } else if (config.captchaProvider === 'altcha') {
            console.log('使用 Altcha 验证，isMobileDevice:', isMobileDevice());
            // 移动端使用CHA，桌面端使用Altcha
            if (isMobileDevice()) {
                // 隐藏Altcha容器，显示CHA容器
                const altchaContainer = document.getElementById('login-altcha-container');
                const chaContainer = document.getElementById('login-cha-container');
                const chaInput = document.getElementById('cha-answer');
                if (altchaContainer) altchaContainer.style.display = 'none';
                if (chaContainer) chaContainer.style.display = 'block';
                if (chaInput) chaInput.required = true;
            } else {
                // 桌面端初始化Altcha，隐藏CHA并移除required
                const altchaContainer = document.getElementById('login-altcha-container');
                const chaContainer = document.getElementById('login-cha-container');
                const chaInput = document.getElementById('cha-answer');
                if (chaContainer) chaContainer.style.display = 'none';
                if (chaInput) chaInput.required = false;
                if (altchaContainer) altchaContainer.style.display = 'block';
                initAltcha('login-altcha-widget', 'altcha-payload');
            }
        }
    } catch (captchaError) {
        console.error('CAPTCHA 初始化失败:', captchaError);
    }

    // showError 函数定义（移到事件监听器之前）
    function showError(message) {
        console.log('showError 被调用:', message);
        if (errorMessage) {
            errorMessage.textContent = message;
            errorMessage.style.display = 'block';
            setTimeout(() => {
                errorMessage.style.display = 'none';
            }, 5000);
        }
    }

    // 表单提交
    form.addEventListener('submit', async (e) => {
        console.log('表单提交事件被触发');
        e.preventDefault();

        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        let captchaResponse = '';

        console.log('表单数据 - email:', email, 'password长度:', password?.length);

        // 获取 CAPTCHA 响应
        if (config.captchaProvider === 'cloudflare') {
            captchaResponse = document.getElementById('cf-token-hidden').value;
        } else if (config.captchaProvider === 'cha') {
            captchaResponse = document.getElementById('cha-answer').value;
        } else if (config.captchaProvider === 'altcha') {
            // Altcha模式：移动端使用CHA，桌面端使用Altcha
            if (isMobileDevice()) {
                captchaResponse = document.getElementById('cha-answer').value;
            } else {
                captchaResponse = document.getElementById('altcha-payload').value;
            }
        } else {
            // 其他情况（包括 config.captchaProvider 为空）
            captchaResponse = document.getElementById('cha-answer')?.value || '';
        }

        console.log('captchaResponse:', captchaResponse ? '有值' : '空');

        if (!email || !password) {
            showError('请填写所有必填项');
            return;
        }

        if (!captchaResponse) {
            showError('请完成人机验证');
            return;
        }

        console.log('准备发送登录请求');

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: email,
                    password: password,
                    ...(config.captchaProvider === 'cloudflare' ? { cf_token: captchaResponse } :
                        config.captchaProvider === 'cha' ? { cha_answer: captchaResponse } :
                        isMobileDevice() ? { cha_answer: captchaResponse } :
                        { altcha_payload: captchaResponse })
                })
            });

            console.log('登录请求响应状态:', response.status);
            const data = await response.json();
            console.log('登录响应数据:', data);

            if (data.success) {
                // 登录成功，跳转首页
                window.location.href = '/';
            } else {
                // 显示错误信息
                showError(data.error || '登录失败');
                // 如果有警告信息，显示警告
                if (data.warning) {
                    showWarning(data.warning);
                }
            }
        } catch (error) {
            console.error('登录错误:', error);
            showError('网络错误，请稍后重试');
        }
    });

    console.log('登录表单事件监听器已绑定');
}

// 初始化注册页面
function initRegisterPage(config) {
    console.log('initRegisterPage 被调用, config:', config);

    const form = document.getElementById('register-form');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const passwordInput = document.getElementById('password');
    const passwordStrength = document.getElementById('password-strength');

    if (!form) {
        console.error('注册表单元素未找到');
        return;
    }

    console.log('注册表单元素已找到，准备绑定事件');

    // 密码强度检测
    if (passwordInput && passwordStrength) {
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
                passwordStrength.textContent = '密码强度: ' + (strengthText[strength - 1] || '很弱');
                passwordStrength.style.color = strengthColor[strength - 1] || '#ff4444';
            } else {
                passwordStrength.textContent = '';
            }
        });
    }

    // 初始化 CAPTCHA
    try {
        if (config.captchaProvider === 'cloudflare' && typeof turnstile !== 'undefined') {
            turnstileWidgetId = turnstile.render('#register-turnstile', {
                sitekey: config.turnstileSiteKey,
                callback: function(token) {
                    document.getElementById('cf-token-hidden').value = token;
                }
            });
        } else if (config.captchaProvider === 'altcha') {
            console.log('使用 Altcha 验证，isMobileDevice:', isMobileDevice());
            // 移动端使用CHA，桌面端使用Altcha
            if (isMobileDevice()) {
                const altchaContainer = document.getElementById('register-altcha-container');
                const chaContainer = document.getElementById('register-cha-container');
                const chaInput = document.getElementById('cha-answer');
                if (altchaContainer) altchaContainer.style.display = 'none';
                if (chaContainer) chaContainer.style.display = 'block';
                if (chaInput) chaInput.required = true;
            } else {
                // 桌面端初始化Altcha，隐藏CHA并移除required
                const altchaContainer = document.getElementById('register-altcha-container');
                const chaContainer = document.getElementById('register-cha-container');
                const chaInput = document.getElementById('cha-answer');
                if (chaContainer) chaContainer.style.display = 'none';
                if (chaInput) chaInput.required = false;
                if (altchaContainer) altchaContainer.style.display = 'block';
                initAltcha('register-altcha-widget', 'altcha-payload');
            }
        }
    } catch (captchaError) {
        console.error('CAPTCHA 初始化失败:', captchaError);
    }

    // showError 和 showSuccess 函数定义（移到事件监听器之前）
    function showError(message) {
        console.log('showError 被调用:', message);
        if (errorMessage) {
            errorMessage.textContent = message;
            errorMessage.style.display = 'block';
            if (successMessage) successMessage.style.display = 'none';
        }
    }

    function showSuccess(message) {
        console.log('showSuccess 被调用:', message);
        if (successMessage) {
            successMessage.textContent = message;
            successMessage.style.display = 'block';
            if (errorMessage) errorMessage.style.display = 'none';
        }
    }

    // 表单提交
    form.addEventListener('submit', async (e) => {
        console.log('注册表单提交事件被触发');
        e.preventDefault();

        const email = document.getElementById('email').value.trim().toLowerCase();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        let captchaResponse = '';

        console.log('表单数据 - email:', email, 'username:', username, 'password长度:', password?.length);

        // 获取 CAPTCHA 响应
        if (config.captchaProvider === 'cloudflare') {
            captchaResponse = document.getElementById('cf-token-hidden').value;
        } else if (config.captchaProvider === 'cha') {
            captchaResponse = document.getElementById('cha-answer').value;
        } else if (config.captchaProvider === 'altcha') {
            // Altcha模式：移动端使用CHA，桌面端使用Altcha
            if (isMobileDevice()) {
                captchaResponse = document.getElementById('cha-answer').value;
            } else {
                captchaResponse = document.getElementById('altcha-payload').value;
            }
        } else {
            // 其他情况
            captchaResponse = document.getElementById('cha-answer')?.value || '';
        }

        console.log('captchaResponse:', captchaResponse ? '有值' : '空');

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

        console.log('准备发送注册请求');

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
                    ...(config.captchaProvider === 'cloudflare' ? { cf_token: captchaResponse } :
                        config.captchaProvider === 'cha' ? { cha_answer: captchaResponse } :
                        isMobileDevice() ? { cha_answer: captchaResponse } :
                        { altcha_payload: captchaResponse })
                })
            });

            console.log('注册请求响应状态:', response.status);
            const data = await response.json();
            console.log('注册响应数据:', data);

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

    console.log('注册表单事件监听器已绑定');
}

// Altcha 初始化（加载并求解挑战）
function initAltcha(widgetId, payloadInputId) {
    // 加载 Altcha 挑战并自动求解，填入隐藏输入框
    // widgetId: the div where the challenge UI will be rendered
    // payloadInputId: the hidden input to store the solved payload JSON
    fetch('/api/altcha/challenge')
        .then(r => {
            if (!r.ok) {
                throw new Error(`HTTP ${r.status}: ${r.statusText}`);
            }
            return r.json();
        })
        .then(data => {
            const widget = document.getElementById(widgetId);
            if (!widget) {
                console.error(`Widget element not found: ${widgetId}`);
                return;
            }
            if (!data.challenge || !data.salt || !data.signature || !data.target_prefix) {
                throw new Error('Invalid challenge data');
            }
            widget.innerHTML = `
                <div class="altcha-info">
                    <p>🔐 人机验证</p>
                    <p style="font-size: 12px; color: #666;">正在计算工作量证明...</p>
                    <div class="altcha-progress"><div id="${widgetId}-progress" style="width: 0%;"></div></div>
                    <p id="${widgetId}-status" style="font-size: 12px; color: #666;">初始化中...</p>
                </div>`;
            // 开始求解挑战
            solveAltchaChallenge(data.challenge, data.salt, data.signature, data.target_prefix, data.max_number, widgetId, payloadInputId)
                .catch(err => console.error('求解 Altcha 挑战失败:', err));
        })
        .catch(err => {
            console.error('加载 Altcha 挑战失败', err);
            const widget = document.getElementById(widgetId);
            if (widget) {
                widget.innerHTML = `<div class="altcha-error">❌ 验证加载失败，请刷新页面</div>`;
            }
        });
}

// 求解 Altcha 挑战的通用实现（从 verify.js 中抽取）
async function solveAltchaChallenge(challenge, salt, signature, targetPrefix, maxNumber, widgetId, payloadInputId) {
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

    for (let i = 0; i < maxNumber; i++) {
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
    }

    statusEl.textContent = '验证失败，请刷新页面重试';
    progressEl.style.background = '#f44336';
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
