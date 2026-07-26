/* Auto Recon Web GUI — shared client helpers */
(function () {
  var root = document.documentElement;
  function current() {
    return root.getAttribute('data-theme') ||
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }
  function paint() {
    var t = current(), i = document.getElementById('themeIcon'), l = document.getElementById('themeLbl');
    if (i) i.textContent = t === 'dark' ? '☾' : '☀';
    if (l) l.textContent = t === 'dark' ? 'Dark' : 'Light';
  }
  var btn = document.getElementById('themeBtn');
  if (btn) btn.addEventListener('click', function () {
    root.setAttribute('data-theme', current() === 'dark' ? 'light' : 'dark'); paint();
  });
  paint();
})();

// transient toast notifications
function toast(msg, kind) {
  var box = document.getElementById('toasts');
  if (!box) { alert(msg); return; }
  var t = document.createElement('div');
  t.className = 'toast ' + (kind || 'info');
  t.textContent = msg;
  box.appendChild(t);
  setTimeout(function () { t.classList.add('show'); }, 10);
  setTimeout(function () { t.classList.remove('show'); setTimeout(function () { t.remove(); }, 300); }, 3800);
}

// copy text to clipboard with feedback
function copyText(text) {
  navigator.clipboard.writeText(text).then(function () { toast('Copied', 'ok'); },
    function () { toast('Copy failed', 'err'); });
}

// session config overrides saved by the Settings page (localStorage)
function configOverrides() {
  try { return JSON.parse(localStorage.getItem('ar_cfg') || '{}'); } catch (e) { return {}; }
}

// same-origin fetch; the httponly session cookie is sent automatically
async function api(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = r.status + '';
    try { msg = (await r.json()).detail || msg; } catch (e) {}
    throw new Error(msg);
  }
  const ct = r.headers.get('content-type') || '';
  return ct.includes('application/json') ? r.json() : r.text();
}

// global running-jobs badge in the header (polls on every page)
(function () {
  const badge = document.getElementById('jobBadge');
  if (!badge) return;
  async function tick() {
    try {
      const { jobs } = await api('/api/jobs');
      const running = jobs.filter(j => j.status === 'running').length;
      if (running) { badge.style.display = ''; badge.innerHTML = '<b>' + running + '</b> running'; }
      else { badge.style.display = 'none'; }
    } catch (e) {}
  }
  tick(); setInterval(tick, 3000);
})();

// classify a log line for coloring in the terminal pane
function logClass(line) {
  if (line.startsWith('$ ')) return 'cmd';
  if (/\bPHASE \d+:|━━━|═══/.test(line)) return 'head';
  if (/\[✔\]|✓|\bOK\b|completed|success|Pwn3d/i.test(line)) return 'ok';
  if (/\[!\]|WARN|warning|skip/i.test(line)) return 'warn';
  if (/\[✗\]|ERROR|failed|No open ports|invalid/i.test(line)) return 'err';
  return '';
}

// stream a job's output into a <div class="term"> and drive a pipeline tracker
function streamJob(jobId, termEl, opts) {
  opts = opts || {};
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws/jobs/' + jobId);
  ws.onmessage = function (ev) {
    const line = ev.data;
    if (line.startsWith('__JOB_END__')) {
      const st = (line.match(/status=(\w+)/) || [])[1] || 'done';
      if (opts.onend) opts.onend(st);
      return;
    }
    const span = document.createElement('span');
    span.className = 'l ' + logClass(line);
    span.textContent = line;
    termEl.appendChild(span);
    termEl.scrollTop = termEl.scrollHeight;
    if (opts.online) opts.online(line);
  };
  ws.onclose = function () { if (opts.onclose) opts.onclose(); };
  return ws;
}
