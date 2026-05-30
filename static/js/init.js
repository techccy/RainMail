// 检查用户登录状态
async function checkUserStatus() {
    try {
        const response = await fetch('/api/user/profile');
        if (response.ok) {
            const data = await response.json();
            showUserBar(data.user);
        }
    } catch (error) {
        // 未登录，忽略错误
    }
}

function showUserBar(user) {
    const userBar = document.getElementById('user-bar');
    const authEntry = document.getElementById('auth-entry');
    const body = document.body;

    if (userBar) {
        userBar.style.display = 'flex';
        document.getElementById('user-name').textContent = user.username || user.email.split('@')[0];
    }
    if (authEntry) {
        authEntry.style.display = 'none';
    }
    body.classList.add('has-user-bar');

    // 更新应用状态
    if (window.app && user.email) {
        window.app.isLoggedIn = true;
        window.app.userEmail = user.email;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // 检查用户状态
    checkUserStatus();

    // 从 data 属性读取配置
    const body = document.body;
    const captchaProvider = body.dataset.captchaProvider || '';
    const turnstileSiteKey = body.dataset.turnstileSiteKey || '';

    // 检测是否为移动设备
    function isMobileDevice() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    }

    // 根据验证提供商选择不同的处理方式
    if (captchaProvider === 'cloudflare') {
        // 检查 Turnstile 是否加载完成
        const checkTurnstile = setInterval(() => {
            if (typeof turnstile !== 'undefined') {
                clearInterval(checkTurnstile);
                renderTurnstileWidgets();
            }
        }, 100);

        function renderTurnstileWidgets() {
            // 1. 处理晴天界面的验证框
            const sunnyContainer = document.getElementById('sunny-turnstile');
            if (sunnyContainer) {
                turnstile.render('#sunny-turnstile', {
                    sitekey: turnstileSiteKey,
                    callback: function(token) {
                        document.getElementById('cf-token-hidden').value = token;
                    }
                });
            }

            // 2. 处理雨天界面的验证框
            const rainyContainer = document.getElementById('rainy-turnstile');
            if (rainyContainer) {
                turnstile.render('#rainy-turnstile', {
                    sitekey: turnstileSiteKey,
                    callback: function(token) {
                        document.getElementById('rainy-cf-token-hidden').value = token;
                    }
                });
            }
        }
    } else if (captchaProvider === 'cha') {
        // 加载 CHA 验证问题
        loadCHAPuzzle('sunny-cha-question');
        loadCHAPuzzle('rainy-cha-question');
    } else if (captchaProvider === 'altcha') {
        // 所有设备统一使用 Altcha
        loadAltchaWidget('sunny-altcha-widget', 'sunny-altcha-payload');
        loadAltchaWidget('rainy-altcha-widget', 'rainy-altcha-payload');
    }

    async function loadCHAPuzzle(questionElementId) {
        try {
            const response = await fetch('/api/cha/question');
            const data = await response.json();
            document.getElementById(questionElementId).textContent = data.question;
        } catch (error) {
            console.error('Failed to load CHA puzzle:', error);
            document.getElementById(questionElementId).textContent = '加载失败，请刷新页面';
        }
    }

    async function loadAltchaWidget(widgetId, payloadId) {
        try {
            const response = await fetch('/api/altcha/challenge');
            const data = await response.json();

            const widget = document.getElementById(widgetId);
            widget.innerHTML = `
                <div class="altcha-info">
                    <p>🔐 人机验证</p>
                    <p style="font-size: 12px; color: #666;">正在计算工作量证明...</p>
                    <div class="altcha-progress" style="width: 100%; background: #f0f0f0; border-radius: 5px; margin: 10px 0;">
                        <div id="${widgetId}-progress" style="width: 0%; height: 20px; background: #4CAF50; border-radius: 5px; transition: width 0.1s;"></div>
                    </div>
                    <p id="${widgetId}-status" style="font-size: 12px; color: #666;">初始化中...</p>
                </div>
            `;

            // 执行工作量证明
            solveAltchaChallenge(data.challenge, data.salt, data.signature, data.target_prefix, data.max_number, widgetId, payloadId);

        } catch (error) {
            console.error('Failed to load Altcha challenge:', error);
            document.getElementById(widgetId).innerHTML = '<p style="color: red;">加载失败，请刷新页面</p>';
        }
    }

    async function solveAltchaChallenge(challenge, salt, signature, targetPrefix, maxNumber, widgetId, payloadId) {
        const startTime = Date.now();
        const progressEl = document.getElementById(`${widgetId}-progress`);
        const statusEl = document.getElementById(`${widgetId}-status`);
        const payloadEl = document.getElementById(payloadId);

        // 使用服务器返回的 target_prefix（由 ALTCHA_DIFFICULTY 控制）
        const chunkSize = 500;

        for (let i = 0; i < maxNumber; i++) {
            const testString = challenge + i;
            const hash = await simpleSha256(testString);

            // 更新进度
            if (i % chunkSize === 0) {
                const progress = Math.min((i / maxNumber) * 100, 100);
                progressEl.style.width = progress + '%';
                statusEl.textContent = `计算中... ${Math.floor(progress)}%`;
                await new Promise(resolve => setTimeout(resolve, 0)); // 让 UI 有机会更新
            }

            if (hash.startsWith(targetPrefix)) {
                // 找到解决方案
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
                progressEl.style.width = '100%';
                progressEl.style.background = '#4CAF50';

                const widget = document.getElementById(widgetId);
                widget.innerHTML = `
                    <div class="altcha-success" style="text-align: center; padding: 10px; background: #e8f5e9; border-radius: 5px;">
                        <p style="color: #4CAF50; margin: 0;">✓ 验证完成 (${elapsed}s)</p>
                    </div>
                `;

                // 保存 payload
                payloadEl.value = JSON.stringify({
                    challenge: challenge,
                    number: i,
                    salt: salt,
                    signature: signature,
                    hash_result: hash
                });

                return;
            }
        }

        // 未找到解决方案
        statusEl.textContent = '验证失败，请刷新页面重试';
        progressEl.style.background = '#f44336';
    }

    // 简化的 SHA-256 实现（使用 Web Crypto API）
    async function simpleSha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }
});
