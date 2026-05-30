// 管理员设置页面交互逻辑

let currentConfig = {};
let originalConfig = {};

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    loadConfig();
    initTabs();
    initPasswordToggle();
});

// 初始化标签页切换
function initTabs() {
    const tabs = document.querySelectorAll('.settings-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const panelId = this.getAttribute('data-panel');

            // 切换标签页状态
            tabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');

            // 切换面板显示
            document.querySelectorAll('.settings-panel').forEach(p => p.classList.remove('active'));
            document.getElementById('panel-' + panelId).classList.add('active');
        });
    });
}

// 初始化密码显示切换
function initPasswordToggle() {
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', function() {
            const input = this.previousElementSibling;
            if (input.type === 'password') {
                // 检查是否是脱敏值
                if (input.value && input.value.startsWith('****')) {
                    showToast('原值已加密，无法查看完整内容', 'error');
                    return;
                }
                input.type = 'text';
                this.textContent = '';
            } else {
                input.type = 'password';
                this.textContent = '👁';
            }
        });
    });
}

// 加载配置
async function loadConfig() {
    showLoading(true);
    try {
        const response = await fetch('/admin/api/config');
        const data = await response.json();

        if (data.success) {
            currentConfig = JSON.parse(JSON.stringify(data.config));
            originalConfig = JSON.parse(JSON.stringify(data.config));
            populateForms(data.config);
        } else {
            showToast('加载配置失败: ' + data.error, 'error');
        }
    } catch (error) {
        showToast('加载配置失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 填充表单
function populateForms(config) {
    // 处理邮件加密方式反向映射
    if (config.mail && config.mail.MAIL_USE_TLS !== undefined && config.mail.MAIL_USE_SSL !== undefined) {
        // 使用临时属性存储加密方式，供单选框使用
        config.mail.MAIL_ENCRYPTION = config.mail.MAIL_USE_SSL ? 'ssl' : (config.mail.MAIL_USE_TLS ? 'tls' : 'none');
    }

    document.querySelectorAll('[data-key]').forEach(input => {
        const key = input.getAttribute('data-key');
        const value = getNestedValue(config, key);

        if (value !== undefined && value !== null) {
            if (input.type === 'checkbox') {
                input.checked = value;
            } else if (input.type === 'radio') {
                input.checked = (input.value === value);
            } else {
                input.value = value;
            }
        }
    });

    // 更新邮件配置字段显示状态
    toggleMailConfig();
}

// 获取嵌套对象的值
function getNestedValue(obj, path) {
    const keys = path.split('.');
    let current = obj;
    for (const key of keys) {
        if (current && current[key] !== undefined) {
            current = current[key];
        } else {
            return undefined;
        }
    }
    return current;
}

// 收集表单数据
function collectFormData() {
    const data = {
        weather: {},
        captcha: {},
        location: {},
        admin: {},
        mail: {},
        ai_moderation: {},
        delivery: {}
    };

    let mailEncryption = null;

    document.querySelectorAll('[data-key]').forEach(input => {
        const key = input.getAttribute('data-key');
        const [category, field] = key.split('.');

        let value;
        if (input.type === 'checkbox') {
            value = input.checked;
        } else if (input.type === 'radio') {
            if (input.checked) {
                value = input.value;
            } else {
                return; // 跳过未选中的radio
            }
        } else if (input.type === 'number') {
            value = input.value ? parseInt(input.value) : '';
        } else {
            value = input.value;
        }

        if (data[category] !== undefined) {
            // 处理嵌套字段 (如 ai_moderation.API_KEY)
            if (category === 'ai_moderation') {
                const subField = field.split('.')[1] || field;
                data[category][subField] = value;
            } else if (field === 'MAIL_ENCRYPTION') {
                mailEncryption = value;
            } else {
                data[category][field] = value;
            }
        }
    });

    // 处理加密方式转换为 MAIL_USE_TLS 和 MAIL_USE_SSL
    if (mailEncryption) {
        if (mailEncryption === 'tls') {
            data.mail.MAIL_USE_TLS = true;
            data.mail.MAIL_USE_SSL = false;
            // 建议端口587
            if (!data.mail.MAIL_PORT || data.mail.MAIL_PORT === 465) {
                data.mail.MAIL_PORT = 587;
            }
        } else if (mailEncryption === 'ssl') {
            data.mail.MAIL_USE_TLS = false;
            data.mail.MAIL_USE_SSL = true;
            // 建议端口465
            if (!data.mail.MAIL_PORT || data.mail.MAIL_PORT === 587) {
                data.mail.MAIL_PORT = 465;
            }
        } else {
            data.mail.MAIL_USE_TLS = false;
            data.mail.MAIL_USE_SSL = false;
        }
    }

    return data;
}

// 保存配置
async function saveConfig() {
    showLoading(true);
    const formData = collectFormData();

    try {
        const response = await fetchWithCSRF('/admin/api/config', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ config: formData })
        });

        const data = await response.json();

        if (data.success) {
            showToast(data.message || '配置已保存', 'success');
            // 重新加载配置
            await loadConfig();
        } else {
            showToast('保存失败: ' + data.error, 'error');
        }
    } catch (error) {
        showToast('保存失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 重置配置
function resetConfig() {
    if (confirm('确定要重置所有未保存的更改吗？')) {
        populateForms(originalConfig);
        currentConfig = JSON.parse(JSON.stringify(originalConfig));
        showToast('已重置为上次保存的配置', 'success');
    }
}

// 导出配置
async function exportConfig() {
    showLoading(true);
    try {
        const response = await fetch('/admin/api/config/export');

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `rainmail_config_${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            showToast('配置已导出', 'success');
        } else {
            showToast('导出失败', 'error');
        }
    } catch (error) {
        showToast('导出失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 导入配置
async function importConfig() {
    const fileInput = document.getElementById('import-file');
    const file = fileInput.files[0];

    if (!file) return;

    showLoading(true);

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetchWithCSRF('/admin/api/config/import', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            showToast(data.message || '配置已导入', 'success');
            // 重新加载配置
            await loadConfig();
        } else {
            showToast('导入失败: ' + data.error, 'error');
        }
    } catch (error) {
        showToast('导入失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
        fileInput.value = '';
    }
}

// 测试邮件
async function testEmail() {
    const testEmail = document.getElementById('test_email').value;

    if (!testEmail) {
        showToast('请输入测试邮箱地址', 'error');
        return;
    }

    showLoading(true);

    try {
        const response = await fetchWithCSRF('/admin/api/config/test-email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ test_email: testEmail })
        });

        const data = await response.json();

        if (data.success) {
            showToast(data.message || '测试邮件已发送', 'success');
        } else {
            showToast('发送失败: ' + data.error, 'error');
        }
    } catch (error) {
        showToast('发送失败: ' + error.message, 'error');
    } finally {
        showLoading(false);
    }
}

// 显示加载状态
function showLoading(show) {
    const loading = document.getElementById('loading');
    if (show) {
        loading.classList.add('show');
    } else {
        loading.classList.remove('show');
    }
}

// 显示提示消息
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// 切换邮件配置显示
function toggleMailConfig() {
    const mailEnabled = document.getElementById('mail_enabled');
    const mailConfigFields = document.getElementById('mail-config-fields');
    if (mailConfigFields) {
        mailConfigFields.style.display = mailEnabled.checked ? 'block' : 'none';
    }
}
