// 信件阅读页面逻辑

let deliveryId = null;
let messageId = null;
let isUnlocked = false;
let unlockCheckInterval = null;

function initLetterView(config) {
    deliveryId = config.deliveryId;
    messageId = config.messageId;
    isUnlocked = config.isUnlocked;

    if (isUnlocked) {
        initUnlockedLetter();
    } else {
        startUnlockCheck();
    }
}

function initUnlockedLetter() {
    // 拥抱按钮
    const hugBtn = document.getElementById('hug-btn');
    if (hugBtn) {
        hugBtn.addEventListener('click', sendHug);
    }

    // 回复按钮
    const replyBtn = document.getElementById('reply-btn');
    if (replyBtn) {
        replyBtn.addEventListener('click', showReplyForm);
    }

    // 取消回复按钮
    const cancelReplyBtn = document.getElementById('cancel-reply-btn');
    if (cancelReplyBtn) {
        cancelReplyBtn.addEventListener('click', hideReplyForm);
    }

    // 发送回复按钮
    const sendReplyBtn = document.getElementById('send-reply-btn');
    if (sendReplyBtn) {
        sendReplyBtn.addEventListener('click', sendReply);
    }

    // 字符计数
    const replyContent = document.getElementById('reply-content');
    if (replyContent) {
        replyContent.addEventListener('input', function() {
            const count = this.value.length;
            const counter = document.querySelector('.reply-form .char-count');
            if (counter) {
                counter.textContent = count;
            }
        });
    }
}

function startUnlockCheck() {
    // 每30秒检查一次是否解锁
    checkUnlockStatus();
    unlockCheckInterval = setInterval(checkUnlockStatus, 30000);
}

async function checkUnlockStatus() {
    try {
        const response = await fetch(`/api/letters/${deliveryId}/unlock`);
        const data = await response.json();

        if (data.unlocked) {
            // 已解锁，刷新页面
            clearInterval(unlockCheckInterval);
            location.reload();
        }
    } catch (error) {
        console.error('检查解锁状态失败:', error);
    }
}

async function sendHug() {
    try {
        const response = await fetchWithCSRF(`/api/messages/${messageId}/hug`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            alert('🤗 拥抱已发送！');
            const hugBtn = document.getElementById('hug-btn');
            if (hugBtn) {
                hugBtn.textContent = `🤗 已拥抱 (${data.hugs_count})`;
                hugBtn.disabled = true;
            }
        }
    } catch (error) {
        console.error('发送拥抱失败:', error);
        alert('发送失败，请稍后重试');
    }
}

function showReplyForm() {
    const replyForm = document.getElementById('reply-form');
    if (replyForm) {
        const motion = window.RainMailMotion;
        if (motion && motion.slideToggle) {
            motion.slideToggle(replyForm, true);
        } else {
            replyForm.style.display = 'block';
        }
        document.getElementById('reply-content').focus();
    }
}

function hideReplyForm() {
    const replyForm = document.getElementById('reply-form');
    if (replyForm) {
        document.getElementById('reply-content').value = '';
        const counter = document.querySelector('.reply-form .char-count');
        if (counter) {
            counter.textContent = '0';
        }
        const motion = window.RainMailMotion;
        if (motion && motion.slideToggle) {
            motion.slideToggle(replyForm, false);
        } else {
            replyForm.style.display = 'none';
        }
    }
}

async function sendReply() {
    const content = document.getElementById('reply-content').value.trim();

    if (!content) {
        alert('请输入回复内容');
        return;
    }

    try {
        const response = await fetchWithCSRF(`/api/letters/${deliveryId}/reply`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                content: content,
                reply_type: 'text'
            })
        });

        const data = await response.json();

        if (data.success) {
            alert('✉️ 回复已发送！');
            hideReplyForm();
        } else {
            alert(data.error || '发送失败');
        }
    } catch (error) {
        console.error('发送回复失败:', error);
        alert('发送失败，请稍后重试');
    }
}
