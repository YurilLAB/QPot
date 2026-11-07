// QPot adapter for T-Pot's attack map.
//
// T-Pot feeds this page over a WebSocket. QPot serves the same "Traffic" and
// "Stats" messages from /api/map/stream as a fetch() stream, because fetch can
// send the X-QPot-ID header (a WebSocket cannot), so the feed is authenticated
// like the rest of QPot's API. QPotFeed mimics the WebSocket interface map.js
// uses (onopen / onmessage / onclose / onerror / close / readyState).
(function () {
    'use strict';
    const KEY = 'qpot_id';

    function qpotID() {
        try { return localStorage.getItem(KEY) || ''; } catch (e) { return ''; }
    }

    function mask(id) {
        return id.length > 10 ? id.slice(0, 6) + '…' + id.slice(-4) : id;
    }

    class QPotFeed {
        constructor() {
            this.readyState = 0; // CONNECTING
            this.onopen = null; this.onmessage = null; this.onclose = null; this.onerror = null;
            this._ctrl = new AbortController();
            this._start();
        }

        _emitClose(code, reason) {
            if (this.readyState === 3) return;
            this.readyState = 3;
            if (this.onclose) this.onclose({ code: code, reason: reason || '' });
        }

        async _start() {
            const id = qpotID();
            if (!id) {
                showSignIn();
                this._emitClose(1008, 'QPot ID required');
                return;
            }
            let resp;
            try {
                resp = await fetch('/api/map/stream', { headers: { 'X-QPot-ID': id }, signal: this._ctrl.signal, cache: 'no-store' });
            } catch (e) {
                if (this.onerror) this.onerror(e);
                this._emitClose(1006);
                return;
            }
            // 401: missing/malformed ID; 403: an ID for another instance.
            if (resp.status === 401 || resp.status === 403) {
                try { localStorage.removeItem(KEY); } catch (_) { /* ignore */ }
                showSignIn('This QPot did not accept the saved QPot ID. Sign in again with the ID of this instance.');
                this._emitClose(1008, 'QPot ID not accepted');
                return;
            }
            if (!resp.ok || !resp.body) {
                this._emitClose(1011, 'HTTP ' + resp.status);
                return;
            }
            this.readyState = 1; // OPEN
            if (this.onopen) this.onopen({});
            const reader = resp.body.getReader();
            const dec = new TextDecoder();
            let buf = '';
            try {
                for (;;) {
                    const { value, done } = await reader.read();
                    if (done) break;
                    buf += dec.decode(value, { stream: true });
                    let i;
                    while ((i = buf.indexOf('\n\n')) >= 0) {
                        const block = buf.slice(0, i);
                        buf = buf.slice(i + 2);
                        const data = block.split('\n').filter((l) => l.startsWith('data: ')).map((l) => l.slice(6)).join('\n');
                        if (data && this.onmessage) this.onmessage({ data: data });
                    }
                }
                this._emitClose(1006, 'stream ended');
            } catch (e) {
                this._emitClose(this._ctrl.signal.aborted ? 1000 : 1006);
            }
        }

        close() {
            this._ctrl.abort();
            this._emitClose(1000);
        }

        send() { /* the feed is one-way */ }
    }
    window.QPotFeed = QPotFeed;

    function showSignIn(message) {
        const el = document.getElementById('qpot-signin');
        if (!el) return;
        if (message) {
            const text = document.getElementById('qpot-signin-text');
            if (text) text.textContent = message;
        }
        el.classList.add('show');
    }

    function showID() {
        const id = qpotID();
        document.querySelectorAll('#settings-qpot-id .qpot-id-text').forEach((el) => {
            el.textContent = id ? mask(id) : 'Not signed in';
        });
        if (!id) showSignIn();
    }

    function copyID() {
        const id = qpotID();
        if (!id || !navigator.clipboard) return;
        navigator.clipboard.writeText(id).catch(() => { /* ignore */ });
    }

    function signOut() {
        try { localStorage.removeItem(KEY); } catch (_) { /* ignore */ }
        if (window.webSocket && typeof window.webSocket.close === 'function') window.webSocket.close();
        showID();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', showID);
    } else {
        showID();
    }
    document.addEventListener('click', (e) => {
        if (e.target.closest('#copy-qpot-id')) copyID();
        if (e.target.closest('#signout-qpot-id')) signOut();
    });
    window.QPotID = { get: qpotID, refresh: showID, copy: copyID, signOut: signOut };
})();
