// verify.js - 独立验证页面逻辑

class VerifyPage {
    constructor() {
        this.captchaProvider = captchaProvider;
        this.pendingData = pendingData;
        this.statusEl = document.getElementById('verify-status');
        this.init();
    }

    init() {
        if (this.captchaProvider === 'cloudflare') {
            this.initTurnstile();
        } else if (this.captchaProvider === 'cha') {
            this.initCHA();
        } else if (this.captchaProvider === 'altcha') {
            this.initAltcha();
        }
    }

    showStatus(message, type) {
        this.statusEl.textContent = message;
        this.statusEl.className = `verify-status ${type}`;
    }

    // Cloudflare Turnstile
    initTurnstile() {
        const checkTurnstile = setInterval(() => {
            if (typeof turnstile !== 'undefined') {
                clearInterval(checkTurnstile);
                turnstile.render('#turnstile-widget', {
                    sitekey: document.querySelector('meta[name="turnstile-site-key"]')?.content || '',
                    callback: (token) => {
                        document.getElementById('cf-token').value = token;
                        this.verifyAndSubmit({ cf_token: token });
                    }
                });
            }
        }, 100);
    }

    // CHA 验证
    async initCHA() {
        try {
            const response = await fetch('/api/cha/question');
            const data = await response.json();
            document.getElementById('cha-question').textContent = data.question;

            document.getElementById('btn-verify').addEventListener('click', () => {
                const answer = document.getElementById('cha-answer').value.trim();
                if (!answer) {
                    this.showStatus('请输入答案', 'error');
                    return;
                }
                this.verifyAndSubmit({ cha_answer: answer });
            });
        } catch (error) {
            this.showStatus('加载验证问题失败，请刷新页面', 'error');
        }
    }

    // Altcha 验证
    async initAltcha() {
        try {
            const response = await fetch('/api/altcha/challenge');
            const data = await response.json();

            const widget = document.getElementById('altcha-widget');
            widget.innerHTML = `
                <div class="altcha-info">
                    <p>🔐 人机验证</p>
                    <p style="font-size: 12px; color: #666;">正在计算工作量证明...</p>
                    <div class="altcha-progress">
                        <div id="altcha-progress" style="width: 0%;"></div>
                    </div>
                    <p id="altcha-status" style="font-size: 12px; color: #666;">初始化中...</p>
                </div>
            `;

            await this.solveAltchaChallenge(data.challenge, data.salt, data.signature, data.target_prefix, data.max_number);

        } catch (error) {
            this.showStatus('加载验证失败，请刷新页面', 'error');
        }
    }

    async solveAltchaChallenge(challenge, salt, signature, targetPrefix, maxNumber) {
        const startTime = Date.now();
        const progressEl = document.getElementById('altcha-progress');
        const statusEl = document.getElementById('altcha-status');
        const chunkSize = 500;

        for (let i = 0; i < maxNumber; i++) {
            const testString = challenge + i;
            const hash = await this.simpleSha256(testString);

            if (i % chunkSize === 0) {
                const progress = Math.min((i / maxNumber) * 100, 100);
                progressEl.style.width = progress + '%';
                statusEl.textContent = `计算中... ${Math.floor(progress)}%`;
                await new Promise(resolve => setTimeout(resolve, 0));
            }

            // 使用服务器返回的 target_prefix 进行验证
            // 客户端无法伪造这个值，因为它是通过 HMAC 签名的
            if (hash.startsWith(targetPrefix)) {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

                const widget = document.getElementById('altcha-widget');
                widget.innerHTML = `
                    <div class="altcha-success">
                        ✓ 验证完成 (${elapsed}s)
                    </div>
                `;

                const payload = JSON.stringify({
                    challenge: challenge,
                    number: i,
                    salt: salt,
                    signature: signature,
                    hash_result: hash  // 将计算出的哈希值也发送给服务器进行验证
                });

                this.verifyAndSubmit({ altcha_payload: payload });
                return;
            }
        }

        statusEl.textContent = '验证失败，请刷新页面重试';
        progressEl.style.background = '#f44336';
    }

    async simpleSha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    // 验证并提交原始请求
    async verifyAndSubmit(captchaData) {
        this.showStatus('验证中...', 'loading');

        try {
            // 首先验证 CAPTCHA
            const verifyResponse = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(captchaData)
            });

            if (!verifyResponse.ok) {
                this.showStatus('验证失败，请重试', 'error');
                return;
            }

            const verifyResult = await verifyResponse.json();

            if (!verifyResult.success) {
                this.showStatus(verifyResult.error || '验证失败', 'error');
                return;
            }

            this.showStatus('验证成功，正在提交您的请求...', 'loading');

            // 验证成功，提交原始请求
            const submitResponse = await fetch('/api/messages', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(this.pendingData)
            });

            const submitResult = await submitResponse.json();

            if (submitResult.success) {
                this.showStatus('提交成功！正在跳转...', 'success');
                setTimeout(() => {
                    window.location.href = '/';
                }, 1500);
            } else {
                this.showStatus(submitResult.error || '提交失败', 'error');
            }

        } catch (error) {
            console.error('Verification error:', error);
            this.showStatus('网络错误，请重试', 'error');
        }
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    new VerifyPage();
});
