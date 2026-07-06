// 认证相关功能（旧 SSR 页面用，已移除验证码逻辑）

// 全局状态
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

    // 使用更亮的颜色提升可见性（亮黄色）
    const brightColor = '#ffec00';

    modal.innerHTML = `
        <div class="modal-content" style="max-width: 420px;">
            <h2 style="margin-bottom: 15px; color: ${brightColor};">📨 验证邮件已发送</h2>
            <p style="margin-bottom: 10px; color: ${brightColor};">请查收 <strong>${email}</strong> 中的验证邮件，并在1小时内完成验证。</p>
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
function initLoginPage() {
    console.log('initLoginPage 被调用');

    const form = document.getElementById('login-form');
    const errorMessage = document.getElementById('error-message');

    if (!form) {
        console.error('登录表单元素未找到');
        return;
    }

    console.log('登录表单元素已找到，准备绑定事件');

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

        console.log('表单数据 - email:', email, 'password长度:', password?.length);

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
                    password: password
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
function initRegisterPage() {
    console.log('initRegisterPage 被调用');

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

        console.log('表单数据 - email:', email, 'username:', username, 'password长度:', password?.length);

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
                    username: username
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
        // 使用全局的 fetchWithCSRF，确保请求带上 CSRF token，防止 403 错误
        await fetchWithCSRF('/api/auth/logout', { method: 'POST' });
        window.location.href = '/';
    } catch (error) {
        console.error('登出失败:', error);
    }
}

// 初始化管理员登录页面
function initAdminLoginPage() {
    console.log('initAdminLoginPage 被调用');

    const form = document.getElementById('admin-login-form');

    if (!form) {
        console.error('管理员登录表单元素未找到');
        return;
    }

    console.log('管理员登录表单元素已找到，准备绑定事件');

    console.log('管理员登录表单初始化完成');
}

// ========================================
// 自动初始化 - 页面加载时自动执行
// ========================================
document.addEventListener('DOMContentLoaded', function() {
    // 根据页面元素判断是哪个页面
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const adminForm = document.getElementById('admin-login-form');

    if (loginForm && typeof initLoginPage === 'function') {
        console.log('检测到登录页面，执行 initLoginPage');
        initLoginPage();

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
        initRegisterPage();
    } else if (adminForm && typeof initAdminLoginPage === 'function') {
        console.log('检测到管理员登录页面，执行 initAdminLoginPage');
        initAdminLoginPage();
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
