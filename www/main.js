import init, { unlock_pdf, lock_pdf } from './pkg/pdf_protect_unlock.js';

let wasmReady = false;

async function boot() {
    await init();
    wasmReady = true;
    updateButtons();
}
boot().catch(err => console.error('WASM init failed:', err));

// ========================== State ==========================
const state = {
    unlock: { file: null, bytes: null },
    lock:   { file: null, bytes: null },
};

// ========================== DOM Refs ==========================
const $  = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

// Tabs
$$('.tab').forEach(btn => btn.addEventListener('click', () => switchTab(btn.dataset.tab)));

function switchTab(id) {
    $$('.tab').forEach(t => { t.classList.toggle('active', t.dataset.tab === id); t.setAttribute('aria-selected', t.dataset.tab === id); });
    $$('.panel').forEach(p => p.classList.toggle('active', p.id === id));
    const url = new URL(location);
    url.searchParams.set('tab', id);
    history.replaceState(null, '', url);
}

const initialTab = new URLSearchParams(location.search).get('tab');
if (initialTab === 'lock' || initialTab === 'unlock') switchTab(initialTab);

// Eye toggles
$$('.eye-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const input = $(`#${btn.dataset.target}`);
        input.type = input.type === 'password' ? 'text' : 'password';
    });
});

// ========================== File Handling ==========================
function setupDropzone(zoneId, fileInputId, filenameId, mode) {
    const zone  = $(`#${zoneId}`);
    const input = $(`#${fileInputId}`);
    const label = $(`#${filenameId}`);

    zone.addEventListener('click', (e) => { if (e.target.closest('.file-btn') || e.target === input) return; input.click(); });
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file && file.type === 'application/pdf') loadFile(file, mode, zone, label);
    });
    input.addEventListener('change', () => {
        if (input.files[0]) loadFile(input.files[0], mode, zone, label);
    });
}

function loadFile(file, mode, zone, label) {
    state[mode].file = file;
    const reader = new FileReader();
    reader.onload = () => {
        state[mode].bytes = new Uint8Array(reader.result);
        label.textContent = file.name;
        zone.classList.add('has-file');
        updateButtons();
    };
    reader.readAsArrayBuffer(file);
}

setupDropzone('unlock-dropzone', 'unlock-file', 'unlock-filename', 'unlock');
setupDropzone('lock-dropzone',   'lock-file',   'lock-filename',   'lock');

// ========================== Input Validation ==========================
$('#unlock-password').addEventListener('input', updateButtons);
$('#lock-password').addEventListener('input', updateButtons);
$('#lock-password-confirm').addEventListener('input', updateButtons);
$('#lock-owner-password').addEventListener('input', updateButtons);

function updateButtons() {
    const canUnlock = wasmReady && state.unlock.bytes;
    $('#unlock-btn').disabled = !canUnlock;

    const pw  = $('#lock-password').value;
    const pw2 = $('#lock-password-confirm').value;
    const canLock = wasmReady && state.lock.bytes && pw.length > 0 && pw === pw2;
    $('#lock-btn').disabled = !canLock;
}

// ========================== Actions ==========================
$('#unlock-btn').addEventListener('click', async () => {
    const btn = $('#unlock-btn');
    const res = $('#unlock-result');
    const password = $('#unlock-password').value;
    const data = state.unlock.bytes;
    if (!data) return;

    setBusy(btn, true);
    res.innerHTML = '';

    try {
        const result = unlock_pdf(data, password);
        const blob = new Blob([result], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        const name = state.unlock.file.name.replace(/\.pdf$/i, '') + '_unlocked.pdf';
        res.innerHTML = `
            <div class="msg success">PDF unlocked successfully!</div>
            <a class="download-btn" href="${url}" download="${name}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Download ${name}
            </a>`;
    } catch (e) {
        res.innerHTML = `<div class="msg error">${escHtml(String(e))}</div>`;
    } finally {
        setBusy(btn, false);
    }
});

$('#lock-btn').addEventListener('click', async () => {
    const btn = $('#lock-btn');
    const res = $('#lock-result');
    const userPassword = $('#lock-password').value;
    const ownerPassword = $('#lock-owner-password').value || userPassword;
    const data = state.lock.bytes;
    if (!data || !userPassword) return;

    setBusy(btn, true);
    res.innerHTML = '';

    try {
        const result = lock_pdf(data, userPassword, ownerPassword);
        const blob = new Blob([result], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        const name = state.lock.file.name.replace(/\.pdf$/i, '') + '_protected.pdf';
        res.innerHTML = `
            <div class="msg success">PDF protected successfully!</div>
            <a class="download-btn" href="${url}" download="${name}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Download ${name}
            </a>`;
    } catch (e) {
        res.innerHTML = `<div class="msg error">${escHtml(String(e))}</div>`;
    } finally {
        setBusy(btn, false);
    }
});

// ========================== Utilities ==========================
function setBusy(btn, busy) {
    btn.disabled = busy;
    btn.querySelector('.btn-text').hidden = busy;
    btn.querySelector('.spinner').hidden  = !busy;
}

function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
