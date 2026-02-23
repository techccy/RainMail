class RainMailApp {
    constructor() {
        this.currentWeather = 'sunny';
        this.weatherCheckInterval = null;
        this.init();
    }

    init() {
        this.bindEvents();
        this.updateInterface();
        this.startWeatherPolling();
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

        if (!content) {
            alert('请先写下你的信件');
            return;
        }

        if (content.length > 500) {
            alert('内容不能超过500字');
            return;
        }
        this.showProcessingOverlay();
        // 模拟进度条 (8秒)
        this.simulateProgress(8000); // 8000毫秒 = 8秒
        const turnstileWidget = document.querySelector('.cf-turnstile iframe[src*="challenges.cloudflare.com"]'); // 更精确地选择 Widget iframe
        let cfToken = '';
        if (turnstileWidget && typeof turnstile !== 'undefined' && turnstile.getResponse) {
            // 如果 Turnstile JS SDK 可用，使用其 API
            cfToken = turnstile.getResponse(turnstileWidget.closest('.cf-turnstile').id); // 如果 Widget 有 ID
            if (!cfToken) { // 如果没有 ID 或者没找到，尝试获取第一个 Widget 的响应
                cfToken = turnstile.getResponse(); // 获取第一个 Widget 的响应
            }
        } else {
            // 如果 SDK 不可用，尝试从隐藏的 input 获取 (这是 Cloudflare 的标准做法)
            const hiddenInput = document.querySelector('input[name="cf-turnstile-response"]');
            cfToken = hiddenInput ? hiddenInput.value : '';
        }

        if (!cfToken) {
            this.hideProcessingOverlay();
            clearInterval(this.progressIntervalId);
            alert('请先完成人机验证');
            return;
        }

        try {
            const response = await fetch('/api/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    content: content,
                    cf_token: cfToken // <-- 添加 cf_token 到 JSON body
                })
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
            } else {
                alert(data.error || '提交失败');
                clearInterval(this.progressIntervalId);
                this.hideProcessingOverlay();
            }
        } catch (error) {
            console.error('提交错误:', error);
            alert('网络错误，请重试');
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

        // 生成二维码
        this.generateQRCode(shareData.message_id);

        document.getElementById('success-modal').style.display = 'flex';
    }

    generateQRCode(messageId) {
        const qrContainer = document.getElementById('qr-code-container');
        qrContainer.innerHTML = '';

        const qrUrl = `${window.location.origin}/#message-${messageId}`;

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
                                /* 修复点：auto极狐 -> auto; */
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
}

// 页面加载完成后初始化应用
document.addEventListener('DOMContentLoaded', () => {
    new RainMailApp();
});

// 添加键盘快捷键
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.getElementById('success-modal').style.display = 'none';
    }
});
