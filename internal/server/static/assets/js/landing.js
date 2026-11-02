// QPot landing page: QPot ID sign-in (kept in this browser only, like the
// dashboard) and live status from the instance's own API.
(function () {
    'use strict';
    const KEY = 'qpot_id';
    const $ = (id) => document.getElementById(id);

    function toast(msg) {
        const t = $('toast');
        t.textContent = msg;
        t.classList.add('show');
        setTimeout(() => t.classList.remove('show'), 2500);
    }

    function storedID() {
        try { return localStorage.getItem(KEY) || ''; } catch (e) { return ''; }
    }

    async function api(path, id) {
        const r = await fetch('/api' + path, { headers: { 'X-QPot-ID': id } });
        if (!r.ok) { const e = new Error(r.status); e.status = r.status; throw e; }
        return r.json();
    }

    function mask(id) {
        return id.length > 10 ? id.slice(0, 6) + '…' + id.slice(-4) : id;
    }

    function showLocked(message) {
        $('id-locked').classList.remove('hidden');
        $('id-unlocked').classList.add('hidden');
        $('status-dot').className = 'dot';
        $('status-text').textContent = 'Locked';
        $('stats').textContent = '';
        $('id-err').textContent = message || '';
    }

    async function refresh() {
        const id = storedID();
        if (!id) { showLocked(); return; }
        try {
            const [st, ov] = await Promise.all([api('/status', id), api('/overview', id)]);
            $('id-locked').classList.add('hidden');
            $('id-unlocked').classList.remove('hidden');
            $('id-value').textContent = mask(id);
            const hps = (st.honeypots || []).filter((h) => h.status !== 'disabled');
            const up = hps.filter((h) => h.running).length;
            const ok = st.overall === 'running' || up > 0;
            $('status-dot').className = 'dot ' + (ok ? 'ok' : 'bad');
            $('status-text').textContent = (ok ? 'Running' : 'Stopped') + ' · ' + up + '/' + hps.length + ' honeypots';
            const s = $('stats');
            s.textContent = '';
            const parts = [
                [String(ov.events_24h || 0), ' events'],
                [String(ov.unique_ips_24h || 0), ' attackers'],
                [(Number(ov.events_per_sec) || 0).toFixed(2), '/s'],
            ];
            parts.forEach(([v, label], i) => {
                const b = document.createElement('b');
                b.textContent = v;
                s.appendChild(b);
                s.appendChild(document.createTextNode(label + (i < parts.length - 1 ? ' · ' : ' in the last 24h')));
            });
        } catch (e) {
            if (e.status === 401 || e.status === 403) {
                try { localStorage.removeItem(KEY); } catch (_) { /* ignore */ }
                showLocked('That QPot ID was not accepted.');
            } else {
                $('status-dot').className = 'dot bad';
                $('status-text').textContent = 'Unreachable';
            }
        }
    }

    async function unlock() {
        const id = $('id-input').value.trim();
        if (!/^qp_[a-z0-9]{24}$/.test(id)) { $('id-err').textContent = 'A QPot ID looks like qp_ followed by 24 characters.'; return; }
        try {
            await api('/status', id);
            try { localStorage.setItem(KEY, id); } catch (_) { /* ignore */ }
            $('id-input').value = '';
            $('id-err').textContent = '';
            refresh();
        } catch (e) {
            $('id-err').textContent = (e.status === 401 || e.status === 403) ? 'That QPot ID was not accepted.' : 'The QPot API is not reachable.';
        }
    }

    async function exportMISP() {
        const id = storedID();
        if (!id) { toast('Unlock with your QPot ID first'); return; }
        try {
            const r = await fetch('/api/iocs/export?format=misp', { headers: { 'X-QPot-ID': id } });
            if (!r.ok) { toast('Export failed'); return; }
            const url = URL.createObjectURL(await r.blob());
            const a = document.createElement('a');
            a.href = url;
            a.download = 'qpot-iocs-misp.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (e) { toast('Export failed'); }
    }

    document.addEventListener('DOMContentLoaded', () => {
        $('id-unlock').addEventListener('click', unlock);
        $('id-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
        $('id-signout').addEventListener('click', () => {
            try { localStorage.removeItem(KEY); } catch (_) { /* ignore */ }
            showLocked();
        });
        $('export-misp').addEventListener('click', exportMISP);
        refresh();
        setInterval(refresh, 15000);
    });
})();
