
/**
 * 用户行为跟踪器
 * 用于跟踪用户在页面上的行为轨迹，防止自动化脚本攻击
 */
class UserBehaviorTracker {
    constructor() {
        this.formToken = null;
        this.pageLoadTime = null;
        this.inputFocusCount = 0;
        this.inputCharCount = 0;
        this.hasFocusedInput = false;
        this.minStayTime = 8; // 最小停留时间（秒）
        this.tracking = false;
    }

    async init() {
        this.pageLoadTime = Date.now();
        await this.fetchFormToken();
        this.bindEvents();
        this.tracking = true;
        console.log('[Behavior] Tracking initialized');
    }

    async fetchFormToken() {
        try {
            const response = await fetch('/api/form_token');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            const data = await response.json();
            this.formToken = data.form_token;
            console.log('[Behavior] Form token received');
            return data;
        } catch (error) {
            console.error('[Behavior] Failed to fetch form token:', error);
            throw error;
        }
    }

    bindEvents() {
        // 跟踪所有输入框的聚焦事件
        const inputs = document.querySelectorAll('textarea, input[type="text"], input[type="email"]');
        inputs.forEach(input => {
            // 聚焦事件
            input.addEventListener('focus', () => {
                if (!this.hasFocusedInput) {
                    this.inputFocusCount++;
                    this.hasFocusedInput = true;
                    console.log('[Behavior] Input focused, count:', this.inputFocusCount);
                }
            });

            // 输入事件
            input.addEventListener('input', () => {
                this.inputCharCount += input.value.length - (this.lastValueLength || 0);
                this.lastValueLength = input.value.length;
                console.log('[Behavior] Input changed, total chars:', this.inputCharCount);
            });
        });

        // 鼠标移动事件（可选，用于更复杂的分析）
        let mouseMoveCount = 0;
        document.addEventListener('mousemove', () => {
            mouseMoveCount++;
        });
    }

    getBehaviorData() {
        if (!this.tracking || !this.formToken) {
            return null;
        }

        const currentTime = Date.now();
        const pageStayTime = Math.floor((currentTime - this.pageLoadTime) / 1000);

        return {
            form_token: this.formToken,
            page_stay_time: pageStayTime,
            input_focus_count: this.inputFocusCount,
            input_char_count: this.inputCharCount
        };
    }

    validateBeforeSubmit() {
        const data = this.getBehaviorData();
        if (!data) {
            return {
                valid: false,
                message: '行为跟踪未初始化，请刷新页面后重试'
            };
        }

        // 验证页面停留时间
        if (data.page_stay_time < this.minStayTime) {
            return {
                valid: false,
                message: `请在页面停留至少${this.minStayTime}秒后再提交（当前：${data.page_stay_time}秒）`
            };
        }

        // 验证输入框交互
        if (data.input_focus_count < 1) {
            return {
                valid: false,
                message: '请先在输入框中输入内容'
            };
        }

        // 验证输入字符数
        if (data.input_char_count < 1) {
            return {
                valid: false,
                message: '请输入有效内容'
            };
        }

        return {
            valid: true,
            message: '验证通过',
            data: data
        };
    }

    reset() {
        this.pageLoadTime = Date.now();
        this.inputFocusCount = 0;
        this.inputCharCount = 0;
        this.hasFocusedInput = false;
        this.lastValueLength = 0;
        this.fetchFormToken();
    }
}

// 创建全局实例
const behaviorTracker = new UserBehaviorTracker();

// 页面加载时初始化
document.addEventListener('DOMContentLoaded', () => {
    behaviorTracker.init().catch(error => {
        console.error('[Behavior] Initialization failed:', error);
    });
});

// 导出为全局变量
window.behaviorTracker = behaviorTracker;

