class RainMailApp {
    constructor() {
        this.currentWeather = 'sunny';
        this.weatherCheckInterval = null;
        this.captchaProvider = 'cloudflare'; // 默认验证提供商
        this.isLoggedIn = false;  // 用户登录状态
        this.userEmail = '';  // 用户登录邮箱
        this.init();
    }

    init() {
        this.bindEvents();
        this.updateInterface();
        this.startWeatherPolling();
        this.detectCaptchaProvider();
        this.initWeatherMeta(); // 初始化天气元信息
    }

    initWeatherMeta() {
        // 初始化天气元信息显示
        const locationElem = document.getElementById('weather-location');
        const textElem = document.getElementById('weather-text');
        const refreshElem = document.getElementById('next-refresh');

        if (locationElem && textElem && refreshElem) {
            this.fetchWeatherMeta();
            setInterval(() => this.fetchWeatherMeta(), 30000); // 每30秒更新一次，天气缓存1小时才刷新
        }
    }

    fetchWeatherMeta() {
        fetch('/api/weather/meta')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                const locationElem = document.getElementById('weather-location');
                const textElem = document.getElementById('weather-text');
                const refreshElem = document.getElementById('next-refresh');

                if (locationElem) locationElem.textContent = data.location || '未知';
                if (textElem) textElem.textContent = data.weather_text || '--';
                if (refreshElem) refreshElem.textContent = data.next_refresh_in_minutes ?? '--';

                console.log('Weather meta updated:', data);
            })
            .catch(err => {
                console.error('Failed to fetch weather meta:', err);
                const locationElem = document.getElementById('weather-location');
                if (locationElem) locationElem.textContent = '获取失败';
            });
    }

    detectCaptchaProvider() {
        // 优先从 body 的 data-captcha-provider 属性读取后端配置
        const bodyProvider = document.body.dataset.captchaProvider;
        if (bodyProvider) {
            this.captchaProvider = bodyProvider;
            console.log(`Using CAPTCHA provider from config: ${bodyProvider}`);
            return;
        }

        // 回退到 DOM 元素检测（兼容旧版本）
        const chaContainer = document.querySelector('.cha-container');
        const turnstileWidget = document.querySelector('.cf-turnstile');
        const altchaContainer = document.querySelector('.altcha-container');

        if (altchaContainer) {
            this.captchaProvider = 'altcha';
            console.log('Using Altcha PoW captcha');
        } else if (chaContainer) {
            this.captchaProvider = 'cha';
            console.log('Using CHA captcha provider');
        } else if (turnstileWidget) {
            this.captchaProvider = 'cloudflare';
            console.log('Using Cloudflare Turnstile');
        }
    }

    bindEvents() {
        // 字符计数
        document.getElementById('message-input').addEventListener('input', (e) => {
            this.updateCharCount(e.target);
        });

        document.getElementById('rainy-message-input').addEventListener('input', (e) => {
           this.updateCharCount(e.target);
        });

        // 提交按钮
        document.getElementById('submit-btn').addEventListener('click', () => {
            this.submitMessage('message-input');
        });

        document.getElementById('rainy-submit-btn').addEventListener('click', () => {
            this.submitMessage('rainy-message-input');
        });

        // 模态框按钮
        document.getElementById('close-modal-btn').addEventListener('click', () => {
            this.hideModal();
        });

        document.getElementById('save-card-btn').addEventListener('click', () => {
            this.saveShareCard();
        });

        // 投递选项切换
        this.bindDeliveryOptionsEvents();
    }

    bindDeliveryOptionsEvents() {
        // 晴天界面投递选项
        const sunnyDeliveryOptions = document.querySelectorAll('input[name="delivery-type"]');
        sunnyDeliveryOptions.forEach(radio => {
            radio.addEventListener('change', (e) => {
                const privateOptions = document.getElementById('private-options');
                if (privateOptions) {
                    privateOptions.style.display = e.target.value === 'private' ? 'block' : 'none';
                }
            });
        });

        // 雨天界面投递选项
        const rainyDeliveryOptions = document.querySelectorAll('input[name="rainy-delivery-type"]');
        rainyDeliveryOptions.forEach(radio => {
            radio.addEventListener('change', (e) => {
                const privateOptions = document.getElementById('rainy-private-options');
                if (privateOptions) {
                    privateOptions.style.display = e.target.value === 'private' ? 'block' : 'none';
                }
            });
        });

        // 邮箱通知和邮箱输入框逻辑 - 绑定所有相关元素
        this.bindEmailNotificationEvents('private-options', 'delivery-type');
        this.bindEmailNotificationEvents('rainy-private-options', 'rainy-delivery-type');
    }

    bindEmailNotificationEvents(optionsContainerId, deliveryTypeName) {
        const optionsContainer = document.getElementById(optionsContainerId);
        if (!optionsContainer) return;

        const emailCheckbox = optionsContainer.querySelector('.email-notification-checkbox');
        const emailContainer = optionsContainer.querySelector('.sender-email-container');
        const emailInput = optionsContainer.querySelector('.sender-email-input');
        const publicCheckbox = optionsContainer.querySelector('.public-after-reply-checkbox');

        if (!emailCheckbox || !emailContainer || !emailInput || !publicCheckbox) return;

        // 邮件通知勾选事件
        emailCheckbox.addEventListener('change', (e) => {
            if (e.target.checked) {
                if (this.isLoggedIn) {
                    // 已登录用户，显示登录邮箱提示
                    emailContainer.style.display = 'block';
                    emailInput.value = this.userEmail;
                    emailInput.readOnly = true;
                    emailInput.placeholder = `使用登录邮箱: ${this.userEmail}`;
                    // 取消强制公开
                    publicCheckbox.disabled = false;
                } else {
                    // 未登录用户，显示邮箱输入框
                    emailContainer.style.display = 'block';
                    emailInput.readOnly = false;
                    emailInput.placeholder = '请输入您的邮箱地址';
                    emailInput.value = '';
                    // 取消强制公开
                    publicCheckbox.disabled = false;
                }
            } else {
                // 取消勾选邮件通知
                emailContainer.style.display = 'none';
                emailInput.value = '';

                if (!this.isLoggedIn) {
                    // 未登录用户取消邮件通知，强制勾选公开
                    publicCheckbox.checked = true;
                    publicCheckbox.disabled = true;
                }
            }
        });

        // "被回复后公开"取消事件
        publicCheckbox.addEventListener('change', (e) => {
            if (!e.target.checked && !this.isLoggedIn && !emailCheckbox.checked) {
                // 未登录用户试图取消公开且未勾选邮件通知
                alert('登录或填写邮箱');
                e.target.checked = true;
            }
        });

        // 初始化：如果未登录且未勾选邮件通知，强制勾选公开
        if (!this.isLoggedIn && !emailCheckbox.checked) {
            publicCheckbox.checked = true;
            publicCheckbox.disabled = true;
        }
    }

    updateCharCount(textarea) {
        const count = textarea.value.length;
        const counter = textarea.nextElementSibling?.querySelector('.char-count') || 
                       document.getElementById('char-counter');
        if (counter) {
            counter.textContent = count;
        }
    }

    async submitMessage(inputId) {
        const textarea = document.getElementById(inputId);
        const content = textarea.value.trim();

        // 蜜罐检查 - 如果隐藏字段有值，说明是机器人
        const honeypot = document.getElementById('website-hp');
        if (honeypot && honeypot.value.trim() !== '') {
            // 机器人检测到，假装正常处理但不实际提交
            console.warn('Honeypot triggered');
            return;
        }

        if (!content) {
            alert('请先写下你的信件');
            return;
        }

        if (content.length > 500) {
            alert('内容不能超过500字');
            return;
        }

        // 获取投递选项
        const isRainy = inputId === 'rainy-message-input';
        const deliveryTypeSelector = isRainy ? 'rainy-delivery-type' : 'delivery-type';
        const privateOptionsId = isRainy ? 'rainy-private-options' : 'private-options';

        const selectedDeliveryType = document.querySelector(`input[name="${deliveryTypeSelector}"]:checked`)?.value || 'public';
        const replyNotificationCheckbox = document.querySelector(`#${privateOptionsId} input[name="${isRainy ? 'rainy-reply-notification' : 'reply-notification'}"]`);
        const publicAfterReplyCheckbox = document.querySelector(`#${privateOptionsId} .public-after-reply-checkbox`);
        const senderEmailInput = document.querySelector(`#${privateOptionsId} .sender-email-input`);

        const deliveryOptions = {
            type: selectedDeliveryType
        };

        let replyNotification = 'none';
        if (selectedDeliveryType === 'private' && replyNotificationCheckbox && replyNotificationCheckbox.checked) {
            replyNotification = 'email';
            deliveryOptions.emailNotification = true;
        }

        // 获取"被回复后公开"选项
        let publicAfterReply = false;
        if (selectedDeliveryType === 'private' && publicAfterReplyCheckbox) {
            publicAfterReply = publicAfterReplyCheckbox.checked;
        }

        // 获取发送者邮箱
        let senderEmail = '';
        if (selectedDeliveryType === 'private' && senderEmailInput && senderEmailInput.value) {
            senderEmail = senderEmailInput.value.trim();
        }

        // 如果勾选了邮件通知但未填写邮箱，提示用户
        if (replyNotification === 'email' && !senderEmail && !this.isLoggedIn) {
            alert('请输入您的邮箱地址');
            return;
        }

        // 验证邮箱格式
        if (senderEmail && !this.isValidEmail(senderEmail)) {
            alert('请输入正确的邮箱格式');
            return;
        }

        // 根据验证提供商获取验证响应
        let captchaResponse = '';

        if (this.captchaProvider === 'cloudflare') {
            const turnstileWidget = document.querySelector('.cf-turnstile iframe[src*="challenges.cloudflare.com"]');
            let cfToken = '';
            if (turnstileWidget && typeof turnstile !== 'undefined' && turnstile.getResponse) {
                cfToken = turnstile.getResponse(turnstileWidget.closest('.cf-turnstile').id);
                if (!cfToken) {
                    cfToken = turnstile.getResponse();
                }
            } else {
                const hiddenInput = document.querySelector('input[name="cf-turnstile-response"]');
                cfToken = hiddenInput ? hiddenInput.value : '';
            }
            captchaResponse = cfToken;

            if (!captchaResponse) {
                alert('请先完成人机验证');
                return;
            }
        } else if (this.captchaProvider === 'cha') {
            const chaAnswerInput = inputId === 'message-input' ?
                document.getElementById('sunny-cha-answer') :
                document.getElementById('rainy-cha-answer');
            captchaResponse = chaAnswerInput ? chaAnswerInput.value.trim() : '';

            if (!captchaResponse) {
                alert('请先完成人机验证');
                return;
            }
        } else if (this.captchaProvider === 'altcha') {
            // 使用 Altcha，无论移动端还是桌面端
            const altchaPayloadInput = inputId === 'message-input' ?
                document.getElementById('sunny-altcha-payload') :
                document.getElementById('rainy-altcha-payload');
            captchaResponse = altchaPayloadInput ? altchaPayloadInput.value : '';

            if (!captchaResponse) {
                alert('请等待人机验证完成');
                return;
            }
        } else if (this.captchaProvider === 'recaptcha' || this.captchaProvider === 'recaptcha_v3') {
            const recaptchaTokenInput = document.getElementById('recaptcha-token-hidden');
            captchaResponse = recaptchaTokenInput ? recaptchaTokenInput.value : '';

            if (!captchaResponse) {
                // 显示刷新按钮
                const refreshBtn = document.getElementById('refresh-captcha-btn');
                const statusEl = document.getElementById('recaptcha-v3-status');
                if (statusEl) {
                    statusEl.innerHTML = '<span class="status-icon">⚠</span> 验证未完成或已过期，请点击刷新';
                    statusEl.classList.add('status-error');
                }
                if (refreshBtn) refreshBtn.style.display = 'inline-block';
                alert('人机验证未完成或已过期，请点击刷新验证按钮');
                return;
            }
        } else if (this.captchaProvider === 'none') {
            // 跳过人机验证
            console.log('CAPTCHA disabled, skipping validation');
        }

        this.showProcessingOverlay();
        this.simulateProgress(8000); // 8000毫秒 = 8秒

        try {
            const requestBody = {
                content: content,
                delivery_type: selectedDeliveryType,
                delivery_options: deliveryOptions,
                reply_notification: replyNotification,
                is_anonymous: true,
                public_after_reply: publicAfterReply,
                sender_email: senderEmail
            };

            // 根据验证提供商添加不同的字段
            if (this.captchaProvider === 'cloudflare') {
                requestBody.cf_token = captchaResponse;
            } else if (this.captchaProvider === 'recaptcha' || this.captchaProvider === 'recaptcha_v3') {
                requestBody.recaptcha_token = captchaResponse;
            } else if (this.captchaProvider === 'cha') {
                requestBody.cha_answer = captchaResponse;
            } else if (this.captchaProvider === 'altcha') {
                requestBody.altcha_payload = captchaResponse;
            } else if (this.captchaProvider === 'none') {
                // 无需添加验证字段
                console.log('CAPTCHA disabled, no token needed');
            }

            const response = await fetchWithCSRF('/api/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });

            clearInterval(this.progressIntervalId);
            this.hideProcessingOverlay();
            const data = await response.json();

            if (response.ok) {
                this.showSuccessModal(data.share_data);
                textarea.value = '';
                this.updateCharCount(textarea);

                // 如果是雨天模式，重新加载消息
                if (this.currentWeather === 'rainy') {
                    this.loadMessages();
                }

                // 如果使用 CHA，重新加载验证问题
                if (this.captchaProvider === 'cha') {
                    await this.loadCHAPuzzle(inputId === 'message-input' ? 'sunny-cha-question' : 'rainy-cha-question');
                    // 清空答案输入框
                    const chaAnswerInput = inputId === 'message-input' ?
                        document.getElementById('sunny-cha-answer') :
                        document.getElementById('rainy-cha-answer');
                    if (chaAnswerInput) {
                        chaAnswerInput.value = '';
                    }
                }

                // 如果使用 Altcha，重新加载挑战
                if (this.captchaProvider === 'altcha') {
                    await this.loadAltchaChallenge(inputId === 'message-input' ? 'sunny-altcha-widget' : 'rainy-altcha-widget',
                                                     inputId === 'message-input' ? 'sunny-altcha-payload' : 'rainy-altcha-payload');
                }

                // 如果使用 reCAPTCHA v3，重新获取验证
                if (this.captchaProvider === 'recaptcha' || this.captchaProvider === 'recaptcha_v3') {
                    if (typeof window.refreshRecaptcha === 'function') {
                        await window.refreshRecaptcha();
                    }
                }
            } else {
                // 检查是否需要登录
                if (data.require_login) {
                    this.showLoginModal();
                } else {
                    alert(data.error || '提交失败');
                }
                clearInterval(this.progressIntervalId);
                this.hideProcessingOverlay();
            }
        } catch (error) {
            console.error('提交错误:', error);
            alert('网络错误，请重试');
            clearInterval(this.progressIntervalId);
            this.hideProcessingOverlay();
        }
    }

    async loadCHAPuzzle(questionElementId) {
        try {
            const response = await fetch('/api/cha/question');
            const data = await response.json();
            const questionElement = document.getElementById(questionElementId);
            if (questionElement) {
                questionElement.textContent = data.question;
            }
        } catch (error) {
            console.error('Failed to load CHA puzzle:', error);
        }
    }

    async loadAltchaChallenge(widgetId, payloadId) {
        // 触发全局的 Altcha 加载函数（定义在 index.html 中）
        if (typeof loadAltchaWidget === 'function') {
            await loadAltchaWidget(widgetId, payloadId);
        }
    }
    // --- 新增：显示处理中界面 ---
    showProcessingOverlay() {
        const overlay = document.getElementById('processing-overlay');
        overlay.style.display = 'flex'; // 或 'block'，取决于CSS布局
        document.getElementById('processing-text').textContent = '正在加密...';
        document.getElementById('processing-progress-bar').style.width = '0%';
        document.getElementById('processing-time-remaining').textContent = '预计剩余时间: 8 秒';

        // 可选：禁用提交按钮，防止重复点击
        // document.getElementById('submit-btn').disabled = true;
        // document.getElementById('rainy-submit-btn').disabled = true;
    }
    // --- END 新增 ---

    // --- 新增：隐藏处理中界面 ---
    hideProcessingOverlay() {
        const overlay = document.getElementById('processing-overlay');
        overlay.style.display = 'none';

        // 可选：启用提交按钮
        // document.getElementById('submit-btn').disabled = false;
        // document.getElementById('rainy-submit-btn').disabled = false;
    }
    // --- END 新增 ---

    // --- 新增：模拟进度条 ---
    simulateProgress(totalDurationMs) {
        const progressBar = document.getElementById('processing-progress-bar');
        const processingText = document.getElementById('processing-text');
        const timeRemainingElement = document.getElementById('processing-time-remaining');

        const steps = 100; // 进度条分为100步
        const stepDuration = totalDurationMs / steps;
        let currentStep = 0;

        const texts = [
            '正在加密...',
            '正在打包...',
            '正在上传...',
            '正在审核...'
        ];
        let textIndex = 0;
        const textChangeInterval = Math.floor(steps / texts.length); // 每隔几步换一次文字

        const startTime = Date.now();

        // 清除可能存在的旧定时器
        if (this.progressIntervalId) {
            clearInterval(this.progressIntervalId);
        }

        this.progressIntervalId = setInterval(() => {
            currentStep++;
            const progressPercent = Math.min((currentStep / steps) * 100, 100);
            progressBar.style.width = `${progressPercent}%`;

            // 更新文字
            if (currentStep % textChangeInterval === 0 && textIndex < texts.length) {
                processingText.textContent = texts[textIndex];
                textIndex++;
            }

            // 更新剩余时间 (估算)
            const elapsed = Date.now() - startTime;
            const remaining = Math.max(0, totalDurationMs - elapsed);
            timeRemainingElement.textContent = `预计剩余时间: ${(remaining / 1000).toFixed(1)} 秒`;

            if (currentStep >= steps) {
                clearInterval(this.progressIntervalId);
                // 确保进度条达到100%
                progressBar.style.width = '100%';
                processingText.textContent = '处理完成...'; // 或者显示一个完成状态
            }
        }, stepDuration);
    }
    // --- END 新增 ---

    // 显示登录弹窗
    showLoginModal() {
        // 创建登录弹窗
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.id = 'login-modal';
        modal.style.display = 'flex';
        modal.style.zIndex = '2000';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 400px;">
                <h2>需要登录</h2>
                <p>一对一投递功能需要登录后才能使用。</p>
                <p>登录后，收到回复时可在收件箱查看。</p>
                <div class="modal-actions">
                    <a href="/auth/login" class="primary-btn">前往登录</a>
                    <button class="secondary-btn" onclick="this.closest('.modal').remove()">取消</button>
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

    async loadMessages() {
        const container = document.getElementById('messages-container');
        container.innerHTML = '<div class="loading">加载中...</div>';

        try {
            const response = await fetch('/api/messages');
            const data = await response.json();

            if (response.ok) {
                this.renderMessages(data.messages);
            } else {
                container.innerHTML = `<div class="error">${data.error || '加载失败'}</div>`;
            }
        } catch (error) {
            console.error('加载消息错误:', error);
            container.innerHTML = '<div class="error">网络错误，请重试</div>';
        }
    }

    renderMessages(messages) {
        const container = document.getElementById('messages-container');

        if (!messages || messages.length === 0) {
            container.innerHTML = '<div class="empty-state">还没有信件，成为第一个分享的人吧！</div>';
            return;
        }

        container.innerHTML = messages.map(msg => `
            <div class="message-item fade-in">
                <div class="message-content">${this.escapeHtml(msg.content)}</div>
                <div class="message-meta">
                    <span>#${msg.id}</span>
                    <span>${msg.created_at}</span>
                </div>
            </div>
        `).join('');
    }

    async checkWeather() {
        try {
            const response = await fetch('/api/weather');
            const data = await response.json();

            if (this.currentWeather !== data.weather_status) {
                this.currentWeather = data.weather_status;
                this.updateInterface();

                // 如果是雨天模式，自动加载消息
                if (this.currentWeather === 'rainy') {
                    this.loadMessages();
                }
            }

            this.updateWeatherDisplay();
        } catch (error) {
            console.error('天气检查错误:', error);
        }
    }

    updateWeatherDisplay() {
        const display = document.getElementById('current-weather');
        if (display) {
            display.textContent = this.currentWeather === 'rainy' ? '🌧️ 雨天模式' : '🌤️ 晴天模式';
        }
    }

    updateInterface() {
        const sunnyInterface = document.getElementById('sunny-interface');
        const rainyInterface = document.getElementById('rainy-interface');

        // 更新body的class
        document.body.className = `${this.currentWeather}-mode`;

        if (this.currentWeather === 'sunny') {
            sunnyInterface.style.display = 'block';
            rainyInterface.style.display = 'none';
        } else {
            sunnyInterface.style.display = 'none';
            rainyInterface.style.display = 'block';
            this.loadMessages();
        }

        this.updateWeatherDisplay();
    }

    startWeatherPolling() {
        // 每5分钟检查一次天气状态
        this.weatherCheckInterval = setInterval(() => {
            this.checkWeather();
        }, 300000);

        // 立即检查一次
        this.checkWeather();
    }

    showSuccessModal(shareData) {
        document.getElementById('card-message-id').textContent = shareData.message_id;
        document.getElementById('card-created-at').textContent = shareData.created_at;
        document.getElementById('card-weather-status').textContent =
            shareData.weather_status === 'rainy' ? '雨天模式' : '晴天模式';
        document.getElementById('card-total-messages').textContent = shareData.total_messages;
        document.getElementById('card-unique-id').textContent = shareData.unique_identifier || 'N/A';

        // 设置分享链接
        const shareUrlEl = document.getElementById('card-share-url');
        if (shareUrlEl && shareData.full_share_url) {
            shareUrlEl.textContent = shareData.full_share_url;
            shareUrlEl.href = shareData.full_share_url;
        }

        // 生成二维码（使用分享链接）
        this.generateQRCode(shareData.full_share_url || shareData.unique_identifier);

        document.getElementById('success-modal').style.display = 'flex';
    }

    generateQRCode(urlOrId) {
        const qrContainer = document.getElementById('qr-code-container');
        qrContainer.innerHTML = '';

        // 如果传入的是完整URL，直接使用；否则构建旧格式URL
        const qrUrl = urlOrId.startsWith('http') ? urlOrId : `${window.location.origin}/#message-${urlOrId}`;

        // 使用QRCode.js生成二维码
        const qrcode = new QRCode(qrContainer, {
            text: qrUrl,
            width: 128,
            height: 128,
            colorDark: '#000000',
            colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.H
        });
    }

    hideModal() {
        document.getElementById('success-modal').style.display = 'none';
    }

    async saveShareCard() {
        try {
            const cardElement = document.getElementById('share-card');

            // 创建离屏元素进行截图
            const tempContainer = document.createElement('div');
            tempContainer.style.position = 'absolute';
            tempContainer.style.left = '-9999px';
            tempContainer.style.top = '-9999px';
            document.body.appendChild(tempContainer);

            // 克隆存票卡片
            const clonedCard = cardElement.cloneNode(true);
            tempContainer.appendChild(clonedCard);

            // 添加打印样式
            clonedCard.className = clonedCard.className + ' print-version';

            // 等待渲染完成
            await new Promise(resolve => setTimeout(resolve, 200));

            const canvas = await html2canvas(clonedCard, {
                backgroundColor: '#ffffff',
                scale: 2, // 适中的分辨率
                useCORS: true,
                allowTaint: false,
                logging: false,
                width: clonedCard.offsetWidth,
                height: clonedCard.offsetHeight
            });

            // 清理临时元素
            document.body.removeChild(tempContainer);

            // 创建下载链接
            const link = document.createElement('a');
            const messageId = document.getElementById('card-message-id').textContent;
            link.download = `雨天信箱存票_#${messageId}.png`;
            link.href = canvas.toDataURL('image/png');

            // 移动端兼容性处理
            if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
                // 移动端使用新窗口打开图片
                const newWindow = window.open();
                newWindow.document.write(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>保存存票</title>
                        <style>
                            body { 
                                margin: 0; 
                                padding: 20px; 
                                background: #f5f5f5; 
                                display: flex; 
                                flex-direction: column; 
                                align-items: center; 
                                justify-content: center; 
                                min-height: 100vh; 
                            }
                            img { 
                                max-width: 100%; 
                                height: auto; 
                                border-radius: 10px; 
                                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                            }
                            .instruction {
                                margin-top: 20px;
                                text-align: center;
                                color: #666;
                                font-size: 14px;
                            }
                        </style>
                    </head>
                    <body>
                        <img src="${link.href}" alt="雨天信箱存票">
                        <div class="instruction">请长按图片选择"保存图像"</div>
                    </body>
                    </html>
                `);
                newWindow.document.close();
            } else {
                // 桌面端直接下载
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                alert('存票已保存！');
            }

        } catch (error) {
            console.error('保存存票错误:', error);
            alert('保存失败，请重试: ' + error.message);
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }
}

// 页面加载完成后初始化应用
document.addEventListener('DOMContentLoaded', () => {
    window.app = new RainMailApp();
});

// 添加键盘快捷键
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.getElementById('success-modal').style.display = 'none';
    }
});
