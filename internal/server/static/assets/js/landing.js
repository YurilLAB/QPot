// QPot's part of the landing page: the QPot ID. T-Pot's page sits behind nginx's login; QPot's API
// wants this instance's QPot ID in the X-QPot-ID header instead. The ID is kept in this browser
// only (localStorage 'qpot_id', shared with the dashboard and the attack map) and never put in a
// URL. Values from the API only go in as text.
(function () {
  'use strict';
  var TPot = window.TPot = window.TPot || {};

  var KEY = 'qpot_id';
  var FORMAT = /^qp_[a-z0-9]{24}$/;

  function $(id) { return document.getElementById(id); }

  function id() {
    try { return window.localStorage.getItem(KEY) || ''; } catch (e) { return ''; }
  }

  function keep(value) {
    try { window.localStorage.setItem(KEY, value); } catch (e) { /* private window: this tab only */ }
  }

  function forget() {
    try { window.localStorage.removeItem(KEY); } catch (e) { /* nothing kept */ }
  }

  function get(path, value) {
    return fetch('/api' + path, { headers: { 'X-QPot-ID': value }, cache: 'no-store', credentials: 'same-origin' });
  }

  // ---------- the two states ----------

  function showSignedIn() {
    var value = id();
    $('signin').hidden = true;
    $('id-menu').hidden = false;
    // the ID is the credential: no character of it is ever shown
    $('id-label').textContent = 'Signed in';
    about(value);
  }

  // the band asks for the ID; message: why (empty: not signed in yet)
  function showSignedOut(message) {
    $('id-menu').hidden = true;
    $('signin').hidden = false;
    $('signin-error').textContent = message || '';
    $('version').textContent = '';
  }

  // the version of this QPot next to the brand, as T-Pot shows its own
  function about(value) {
    get('/overview', value).then(function (r) { return r.ok ? r.json() : null; }).then(function (o) {
      var v = o && typeof o.version === 'string' ? o.version : '';
      $('version').textContent = /^[0-9A-Za-z.+_-]{1,32}$/.test(v) ? v : '';
      var host = o && typeof o.hostname === 'string' ? o.hostname : '';
      if (host) $('version').setAttribute('title', 'QPot on ' + host);
    }, function () { /* the version is a nicety */ });
  }

  function signIn(ev) {
    ev.preventDefault();
    var input = $('signin-id'), value = input.value.trim(), err = $('signin-error');
    if (!FORMAT.test(value)) {
      err.textContent = 'A QPot ID is qp_ and 24 lowercase letters or digits. `qpot id` prints it on this host.';
      input.focus();
      return;
    }
    err.textContent = 'Checking…';
    get('/status', value).then(function (r) {
      if (r.status === 401 || r.status === 403) {
        err.textContent = 'This QPot did not accept that ID. It belongs to another instance, or it was mistyped.';
        return;
      }
      if (!r.ok) {
        err.textContent = 'QPot answered ' + r.status + '. Try again in a moment.';
        return;
      }
      keep(value);
      input.value = '';
      err.textContent = '';
      showSignedIn();
      document.dispatchEvent(new CustomEvent('qpot:auth'));
    }, function () {
      err.textContent = 'The QPot API is not reachable. Is qpot serve running?';
    });
  }

  TPot.qpot = {
    id: id,
    // pulse.js could not use the saved ID (none, or refused): forget a refused one and ask
    signedOut: function (message) {
      if (message) forget();
      showSignedOut(message);
    }
  };

  document.addEventListener('DOMContentLoaded', function () {
    $('signin').addEventListener('submit', signIn);
    TPot.menu($('id-menu'), function (action) {
      if (action === 'change') {
        forget();
        showSignedOut('');
        document.dispatchEvent(new CustomEvent('qpot:auth'));
        $('signin-id').focus();
      }
      if (action === 'dashboard') window.location.assign('/dashboard');
      if (action === 'signout') {
        forget();
        showSignedOut('');
        document.dispatchEvent(new CustomEvent('qpot:auth'));
      }
    });
    if (id()) showSignedIn(); else showSignedOut('');
  });
})();
