/* 共享工具：REST 封装、登录校验、导航、格式化。 */

const API = {
  async request(method, url, body) {
    const options = { method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
      options.headers['X-Requested-With'] = 'XMLHttpRequest';
    }
    const res = await fetch(url, options);
    let data = {};
    if (res.status !== 204) {
      try { data = await res.json(); } catch (e) { data = {}; }
    }
    if (res.status === 401) {
      if (!location.pathname.endsWith('index.html') && location.pathname !== '/') {
        location.href = '/index.html';
      }
      throw new Error(data.message || data.detail || '未登录');
    }
    if (!res.ok) throw new Error(data.message || data.detail || `请求失败（${res.status}）`);
    return data;
  },
  get(url) { return this.request('GET', url); },
  post(url, body) { return this.request('POST', url, body || {}); },
  put(url, body) { return this.request('PUT', url, body || {}); },
  del(url) { return this.request('DELETE', url); },
};

async function requireLogin() {
  try {
    return await API.get('/api/system/me');
  } catch (e) {
    location.href = '/index.html';
    throw e;
  }
}

function queryParam(name) {
  return new URLSearchParams(location.search).get(name);
}

function currentProjectId() {
  const id = queryParam('project_id');
  if (!id) {
    location.href = '/projects.html';
    throw new Error('缺少 project_id');
  }
  return id;
}

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtTime(value) {
  if (!value) return '-';
  return String(value).replace('T', ' ').replace('Z', '').slice(0, 19);
}

function riskLabel(level) {
  const map = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
  return map[level] || level || '-';
}

function riskBadge(level) {
  return `<span class="badge risk-${esc(level || 'info')}">${esc(riskLabel(level))}</span>`;
}

function statusLabel(status) {
  const map = {
    created: '已创建', running: '运行中', completed: '已完成', failed: '失败', stopped: '已停止',
    pending: '等待中', success: '成功', skipped: '已跳过', idle: '空闲',
    verified: '已验证', unverified: '未验证', statically_confirmed: '静态确认',
    generating: '生成中', ready: '已就绪',
  };
  return map[status] || status || '-';
}

function statusBadge(status) {
  const map = {
    created: 'gray', running: 'blue', completed: 'green', failed: 'red', stopped: 'orange',
    pending: 'gray', success: 'green', skipped: 'gray', idle: 'gray',
    verified: 'green', unverified: 'gray', statically_confirmed: 'blue',
    generating: 'blue', ready: 'green',
  };
  return `<span class="badge ${map[status] || 'gray'}">${esc(statusLabel(status))}</span>`;
}

function roleLabel(role) {
  const map = {
    general_handler: '通用处理', env_checker: '环境检查', code_analyst: '代码分析',
    vuln_verifier: '漏洞验证', report_writer: '报告整理', ops_assistant: '运维辅助',
  };
  return map[role] || role || '-';
}

function stageLabel(name) {
  const map = {
    environment_scan: '环境检查', code_analysis: '代码分析',
    vulnerability_verify: '漏洞验证', report_generate: '报告生成', done: '完成',
  };
  return map[name] || name || '-';
}

function mountNav(active, user) {
  const nav = document.getElementById('nav');
  if (!nav) return;
  const pid = queryParam('project_id');
  const suffix = pid ? `?project_id=${encodeURIComponent(pid)}` : '';
  const items = [
    ['/projects.html', '项目列表', 'projects'],
    ['/monitor.html' + suffix, '实时监控', 'monitor'],
    ['/vulnerabilities.html' + suffix, '漏洞', 'vulnerabilities'],
    ['/attack-paths.html' + suffix, '攻击路径', 'attack-paths'],
    ['/report.html' + suffix, '报告', 'report'],
  ];
  if (user && user.role === 'admin') items.push(['/config.html', '系统配置', 'config']);
  nav.innerHTML = `
    <span class="brand">自动化安全评估系统</span>
    ${items.map(([href, text, key]) =>
      `<a href="${href}" class="${active === key ? 'active' : ''}">${text}</a>`).join('')}
    <span class="spacer"></span>
    <span class="user">${esc(user ? user.username : '')}${user && user.role === 'admin' ? '（管理员）' : ''}</span>
    <a href="#" id="logoutBtn">退出</a>
  `;
  document.getElementById('logoutBtn').addEventListener('click', async (e) => {
    e.preventDefault();
    try { await API.post('/api/system/logout'); } catch (e2) { /* ignore */ }
    location.href = '/index.html';
  });
}

function showAlert(id, message, type) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = message;
  el.className = `alert show ${type || 'error'}`;
}

function hideAlert(id) {
  const el = document.getElementById(id);
  if (el) el.className = 'alert';
}

function openModal(id) { document.getElementById(id)?.classList.add('open'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }

function modalBackdropClick(event, id) {
  if (event.target.id === id) closeModal(id);
}
