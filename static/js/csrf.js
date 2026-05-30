// CSRF 保护 - 全局配置
let csrfToken = null;

async function fetchCsrfToken() {
    try {
        const response = await fetch('/api/csrf_token');
        const data = await response.json();
        csrfToken = data.csrf_token;
        return csrfToken;
    } catch (error) {
        console.error('获取 CSRF token 失败:', error);
        return null;
    }
}

async function fetchWithCSRF(url, options = {}) {
    if (!csrfToken) {
        csrfToken = await fetchCsrfToken();
    }

    const headers = options.headers || {};
    if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
    }
    options.headers = headers;

    const response = await fetch(url, options);

    if (response.status === 403) {
        const data = await response.json();
        if (data.error && data.error.includes('CSRF')) {
            csrfToken = await fetchCsrfToken();
            headers['X-CSRF-Token'] = csrfToken;
            return fetch(url, options);
        }
    }

    return response;
}

document.addEventListener('DOMContentLoaded', async () => {
    await fetchCsrfToken();
});

window.fetchWithCSRF = fetchWithCSRF;
window.getCsrfToken = () => csrfToken;
