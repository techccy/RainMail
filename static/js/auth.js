// 认证相关功能

// 全局状态
let turnstileWidgetId = null;
let emailProviders = {};

// 加载邮箱服务商映射数据
async function loadEmailProviders() {
    if (Object.keys(emailProviders).length > 0) {
        return emailProviders;
    }
    try {
        const response = await fetch('/api/email-providers');
        if (response.ok) {
            emailProviders = await response.json();
        }
    } catch (error) {
        console.error('加载邮箱服务商映射失败:', error);
    }
    return emailProviders;
}

// 根据邮箱获取邮箱服务商URL
function getEmailProviderUrl(email) {
    const domain = email.substring(email.lastIndexOf('@'));
    return emailProviders[domain.toLowerCase()] || null;
}

// 显示邮箱验证弹窗
function showEmailVerificationModal(email) {
    const emailUrl = getEmailProviderUrl(email);
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'email-verification-modal';
    modal.style.display = 'flex';
    modal.style.zIndex = '2000';

    const emailProviderName = emailUrl ? '邮箱' : '邮箱服务商';

    modal.innerHTML = `
        <div class="modal-content" style="max-width: 420px;">
            <h2 style="margin-bottom: 15px;">📨 验证邮件已发送</h2>
            <p style="margin-bottom: 10px;">请查收 <strong>${email}</strong> 中的验证邮件，并在1小时内完成验证。</p>
            <p style="font-size: 13px; color: #666; margin-bottom: 20px;">如未收到邮件，请检查垃圾箱文件夹。</p>
            <div class="modal-actions">
                ${emailUrl ? `<a href="${emailUrl}" target="_blank" class="primary-btn">前往${emailProviderName}</a>` : ''}
                <a href="/auth/login" class="secondary-btn">${emailUrl ? '稍后，' : ''}前往登录</a>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    // 点击背景关闭
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
}

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
        if (config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3') {
            // reCAPTCHA v3 - 无形验证
            const statusEl = document.getElementById('recaptcha-v3-status');
            if (typeof grecaptcha !== 'undefined') {
                grecaptcha.ready(function() {
                    grecaptcha.execute(config.recaptchaSiteKey, {action: 'login'})
                        .then(function(token) {
                            document.getElementById('recaptcha-token-hidden').value = token;
                            // 更新状态为验证完成
                            if (statusEl) {
                                statusEl.innerHTML = '<span class="status-icon">✓</span> 人机验证完成';
                                statusEl.classList.add('status-success');
                            }
                        })
                        .catch(function(error) {
                            console.error('reCAPTCHA v3 执行失败:', error);
                            if (statusEl) {
                                statusEl.innerHTML = '<span class="status-icon">⚠</span> 验证加载失败，请刷新页面';
                                statusEl.classList.add('status-error');
                            }
                        });
                });
            } else {
                if (statusEl) {
                    statusEl.innerHTML = '<span class="status-icon">⚠</span> 验证服务未加载，请检查网络';
                    statusEl.classList.add('status-error');
                }
            }
        } else if (config.captchaProvider === 'cloudflare') {
            const initTurnstile = () => {
                if (typeof turnstile !== 'undefined') {
                    console.log('Turnstile 库已加载，开始渲染登录页 widget');
                    turnstileWidgetId = turnstile.render('#login-turnstile', {
                        sitekey: config.turnstileSiteKey,
                        callback: function(token) {
                            console.log('登录页 Turnstile 验证成功');
                            document.getElementById('cf-token-hidden').value = token;
                        },
                        'error-callback': function() {
                            console.error('登录页 Turnstile 验证失败');
                        }
                    });
                } else {
                    setTimeout(initTurnstile, 100);
                }
            };
            initTurnstile();
        } else if (config.captchaProvider === 'altcha') {
            initAltcha('login-altcha-widget', 'altcha-payload');
        } else if (config.captchaProvider === 'cha') {
            // CHA 验证码 - 支持刷新
            const chaQuestionEl = document.getElementById('cha-question');
            if (chaQuestionEl) {
                const refreshBtn = document.createElement('button');
                refreshBtn.type = 'button';
                refreshBtn.className = 'refresh-captcha-btn';
                refreshBtn.textContent = '🔄 刷新验证';
                refreshBtn.onclick = async () => {
                    try {
                        const response = await fetch('/api/cha/question');
                        const data = await response.json();
                        if (response.ok && data.question) {
                            chaQuestionEl.textContent = data.question;
                        } else {
                            chaQuestionEl.textContent = '加载失败，请重试';
                        }
                    } catch (error) {
                        console.error('刷新 CHA 失败:', error);
                        chaQuestionEl.textContent = '加载失败，请重试';
                    }
                };
                chaQuestionEl.parentNode.appendChild(refreshBtn);
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

        // none 模式跳过验证
        if (config.captchaProvider !== 'none') {
            // 获取 CAPTCHA 响应
            if (config.captchaProvider === 'cloudflare') {
                captchaResponse = document.getElementById('cf-token-hidden').value;
            } else if (config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3') {
                captchaResponse = document.getElementById('recaptcha-token-hidden').value;
            } else if (config.captchaProvider === 'cha') {
                captchaResponse = document.getElementById('cha-answer').value;
            } else if (config.captchaProvider === 'altcha') {
                captchaResponse = document.getElementById('altcha-payload').value;
            } else {
                // 其他情况
                captchaResponse = document.getElementById('cha-answer')?.value || '';
            }

            console.log('captchaResponse:', captchaResponse ? '有值' : '空');

            if (!captchaResponse) {
                showError('请完成人机验证');
                return;
            }
        }

        if (!email || !password) {
            showError('请填写所有必填项');
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
                        config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3' ? { recaptcha_token: captchaResponse } :
                        config.captchaProvider === 'cha' ? { cha_answer: captchaResponse } :
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
        if (config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3') {
            // reCAPTCHA v3 - 无形验证
            const statusEl = document.getElementById('recaptcha-v3-status');
            if (typeof grecaptcha !== 'undefined') {
                grecaptcha.ready(function() {
                    grecaptcha.execute(config.recaptchaSiteKey, {action: 'register'})
                        .then(function(token) {
                            document.getElementById('recaptcha-token-hidden').value = token;
                            // 更新状态为验证完成
                            if (statusEl) {
                                statusEl.innerHTML = '<span class="status-icon">✓</span> 人机验证完成';
                                statusEl.classList.add('status-success');
                            }
                        })
                        .catch(function(error) {
                            console.error('reCAPTCHA v3 执行失败:', error);
                            if (statusEl) {
                                statusEl.innerHTML = '<span class="status-icon">⚠</span> 验证加载失败，请刷新页面';
                                statusEl.classList.add('status-error');
                            }
                        });
                });
            } else {
                if (statusEl) {
                    statusEl.innerHTML = '<span class="status-icon">⚠</span> 验证服务未加载，请检查网络';
                    statusEl.classList.add('status-error');
                }
            }
        } else if (config.captchaProvider === 'cloudflare') {
            const initTurnstile = () => {
                if (typeof turnstile !== 'undefined') {
                    console.log('Turnstile 库已加载，开始渲染注册页 widget');
                    turnstileWidgetId = turnstile.render('#register-turnstile', {
                        sitekey: config.turnstileSiteKey,
                        callback: function(token) {
                            console.log('注册页 Turnstile 验证成功');
                            document.getElementById('cf-token-hidden').value = token;
                        },
                        'error-callback': function() {
                            console.error('注册页 Turnstile 验证失败');
                        }
                    });
                } else {
                    setTimeout(initTurnstile, 100);
                }
            };
            initTurnstile();
        } else if (config.captchaProvider === 'altcha') {
            initAltcha('register-altcha-widget', 'altcha-payload');
        } else if (config.captchaProvider === 'cha') {
            // CHA 验证码 - 支持刷新
            const chaQuestionEl = document.getElementById('cha-question');
            if (chaQuestionEl) {
                const refreshBtn = document.createElement('button');
                refreshBtn.type = 'button';
                refreshBtn.className = 'refresh-captcha-btn';
                refreshBtn.textContent = '🔄 刷新验证';
                refreshBtn.onclick = async () => {
                    try {
                        const response = await fetch('/api/cha/question');
                        const data = await response.json();
                        if (response.ok && data.question) {
                            chaQuestionEl.textContent = data.question;
                        } else {
                            chaQuestionEl.textContent = '加载失败，请重试';
                        }
                    } catch (error) {
                        console.error('刷新 CHA 失败:', error);
                        chaQuestionEl.textContent = '加载失败，请重试';
                    }
                };
                chaQuestionEl.parentNode.appendChild(refreshBtn);
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

        // none 模式跳过验证
        if (config.captchaProvider !== 'none') {
            // 获取 CAPTCHA 响应
            if (config.captchaProvider === 'cloudflare') {
                captchaResponse = document.getElementById('cf-token-hidden').value;
            } else if (config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3') {
                captchaResponse = document.getElementById('recaptcha-token-hidden').value;
            } else if (config.captchaProvider === 'cha') {
                captchaResponse = document.getElementById('cha-answer').value;
            } else if (config.captchaProvider === 'altcha') {
                captchaResponse = document.getElementById('altcha-payload').value;
            } else {
                // 其他情况
                captchaResponse = document.getElementById('cha-answer')?.value || '';
            }

            console.log('captchaResponse:', captchaResponse ? '有值' : '空');

            if (!captchaResponse) {
                showError('请完成人机验证');
                return;
            }
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
                        config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3' ? { recaptcha_token: captchaResponse } :
                        config.captchaProvider === 'cha' ? { cha_answer: captchaResponse } :
                        { altcha_payload: captchaResponse })
                })
            });

            console.log('注册请求响应状态:', response.status);
            const data = await response.json();
            console.log('注册响应数据:', data);

            if (data.success) {
                // 先加载邮箱服务商映射，然后显示弹窗
                await loadEmailProviders();
                showEmailVerificationModal(email);
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
    const chunkSize = 500;
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

// 初始化管理员登录页面
function initAdminLoginPage(config) {
    console.log('initAdminLoginPage 被调用, config:', config);

    const form = document.getElementById('admin-login-form');
    const errorMessage = document.getElementById('error-message');

    if (!form) {
        console.error('管理员登录表单元素未找到');
        return;
    }

    console.log('管理员登录表单元素已找到，准备绑定事件');

    // 初始化 CAPTCHA
    try {
        if (config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3') {
            // reCAPTCHA v3 - 无形验证
            const statusEl = document.getElementById('recaptcha-v3-status');
            if (typeof grecaptcha !== 'undefined') {
                grecaptcha.ready(function() {
                    grecaptcha.execute(config.recaptchaSiteKey, {action: 'admin_login'})
                        .then(function(token) {
                            document.getElementById('recaptcha-token-hidden').value = token;
                            // 更新状态为验证完成
                            if (statusEl) {
                                statusEl.innerHTML = '<span class="status-icon">✓</span> 人机验证完成';
                                statusEl.classList.add('status-success');
                            }
                        })
                        .catch(function(error) {
                            console.error('reCAPTCHA v3 执行失败:', error);
                            if (statusEl) {
                                statusEl.innerHTML = '<span class="status-icon">⚠</span> 验证加载失败，请刷新页面';
                                statusEl.classList.add('status-error');
                            }
                        });
                });
            } else {
                if (statusEl) {
                    statusEl.innerHTML = '<span class="status-icon">⚠</span> 验证服务未加载，请检查网络';
                    statusEl.classList.add('status-error');
                }
            }
        } else if (config.captchaProvider === 'cloudflare') {
            // 使用 window.onload 确保 Turnstile 库已完全加载
            const initTurnstile = () => {
                if (typeof turnstile !== 'undefined') {
                    console.log('Turnstile 库已加载，开始渲染');
                    const container = document.getElementById('admin-turnstile');
                    if (!container) {
                        console.error('Turnstile 容器元素未找到');
                        return;
                    }
                    turnstileWidgetId = turnstile.render('#admin-turnstile', {
                        sitekey: config.turnstileSiteKey,
                        callback: function(token) {
                            console.log('Turnstile 验证成功，token 已获取');
                            document.getElementById('cf-turnstile-response').value = token;
                        },
                        'error-callback': function() {
                            console.error('Turnstile 验证失败');
                            showError('人机验证失败，请刷新页面');
                        }
                    });
                } else {
                    console.warn('Turnstile 库未加载，将延迟初始化');
                    // 延迟初始化，等待库加载
                    setTimeout(initTurnstile, 200);
                }
            };
            // 使用 window.onload 确保 script 标签加载完成
            if (document.readyState === 'complete') {
                initTurnstile();
            } else {
                window.addEventListener('load', initTurnstile);
            }
        } else if (config.captchaProvider === 'altcha') {
            initAltcha('admin-altcha-widget', 'altcha-payload');
        }
    } catch (captchaError) {
        console.error('CAPTCHA 初始化失败:', captchaError);
    }

    // showError 函数定义
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

    // 表单提交拦截 - 验证 CAPTCHA 是否完成
    form.addEventListener('submit', function(e) {
        // none 模式跳过验证检查
        if (config.captchaProvider === 'none') {
            console.log('CAPTCHA 配置为 none，跳过验证');
            return true;
        }

        let captchaResponse = '';

        // 获取 CAPTCHA 响应
        if (config.captchaProvider === 'cloudflare') {
            captchaResponse = document.getElementById('cf-turnstile-response').value;
        } else if (config.captchaProvider === 'recaptcha' || config.captchaProvider === 'recaptcha_v3') {
            captchaResponse = document.getElementById('recaptcha-token-hidden').value;
        } else if (config.captchaProvider === 'cha') {
            captchaResponse = document.getElementById('cha-answer').value;
        } else if (config.captchaProvider === 'altcha') {
            captchaResponse = document.getElementById('altcha-payload').value;
        }

        // 如果 CAPTCHA 未完成，阻止提交并显示错误
        if (!captchaResponse) {
            e.preventDefault();
            showError('请完成人机验证');
            return false;
        }

        // CAPTCHA 已完成，允许表单正常提交
        console.log('CAPTCHA 验证通过，提交表单');
    });

    console.log('管理员登录表单初始化完成');
}

// ========================================
// 自动初始化 - 页面加载时自动执行
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    // 从 body data 属性获取配置
    const body = document.body;
    const captchaProvider = body.getAttribute('data-captcha-provider');
    const turnstileSiteKey = body.getAttribute('data-turnstile-site-key');
    const recaptchaSiteKey = body.getAttribute('data-recaptcha-site-key');

    if (!captchaProvider) {
        console.warn('未找到 captcha-provider 配置');
        return;
    }

    const config = {
        captchaProvider: captchaProvider,
        turnstileSiteKey: turnstileSiteKey || '',
        recaptchaSiteKey: recaptchaSiteKey || ''
    };

    console.log('自动初始化, config:', config);

    // 根据页面元素判断是哪个页面
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const adminForm = document.getElementById('admin-login-form');

    if (loginForm && typeof initLoginPage === 'function') {
        console.log('检测到登录页面，执行 initLoginPage');
        initLoginPage(config);

        // 检查URL参数
        const urlParams = new URLSearchParams(window.location.search);
        const verified = urlParams.get('verified');
        const error = urlParams.get('error');

        if (verified === '1') {
            const successMsg = document.getElementById('success-message');
            if (successMsg) {
                successMsg.textContent = '✓ 邮箱验证成功，请登录';
                successMsg.style.display = 'block';
            }
        } else if (error) {
            const errorMsg = document.getElementById('error-message');
            if (errorMsg) {
                const errorMessages = {
                    'invalid_token': '验证链接无效或已过期',
                    'verification_failed': '验证失败，请重试'
                };
                errorMsg.textContent = errorMessages[error] || '验证失败';
                errorMsg.style.display = 'block';
            }
        }
    } else if (registerForm && typeof initRegisterPage === 'function') {
        console.log('检测到注册页面，执行 initRegisterPage');
        initRegisterPage(config);
    } else if (adminForm && typeof initAdminLoginPage === 'function') {
        console.log('检测到管理员登录页面，执行 initAdminLoginPage');
        initAdminLoginPage(config);
    }

    // 初始化登出按钮（所有页面通用）
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn && typeof logout === 'function') {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('登出按钮被点击');
            logout();
        });
        console.log('登出按钮事件监听器已绑定');
    }
});
