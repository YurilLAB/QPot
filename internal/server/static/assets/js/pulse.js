// The pulse: the attacks of this QPot, per time range, from GET /api/pulse (T-Pot asks
// Elasticsearch here; QPot's own API answers with the same aggregations, already reduced).
//
// Everything the API returns comes from attackers: source addresses, countries, reputations and
// names are checked here and anything that does not fit is dropped before it is shown or put in a
// link. A source with a value that does not fit is left out as a whole. The page only ever sets text
// (textContent), never markup.
(function () {
  'use strict';
  var TPot = window.TPot = window.TPot || {};

  var PULSE = '/api/pulse?range=';
  var TIMEOUT = 5000;
  var SHOWN = 7;      // the page shows five of them, or seven when there are no sensors
  var REUSE = 2000;   // the lists reuse an answer of the overview this young (the API caches 2 s)

  // the ranges of T-Pot's assets/queries.json: points of the curve, seconds between two answers of
  // the overview and of the lists, and the words for them
  var RANGES = {
    '24h': { points: 48, every: 15, lists: 60, name: 'the last 24 hours', short: '24 h', per: '30 min' },
    '1h': { points: 60, every: 10, lists: 30, name: 'the last hour', short: '1 h', per: 'minute' },
    '1m': { points: 30, every: 4, lists: 10, name: 'the last minute', short: '1 min', per: '2 s' }
  };
  var DEFAULT = '24h';

  // ---------- checks of the values that come from attackers ----------

  var IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  var IPV6_CHARS = /^[0-9A-Fa-f:.]{2,45}$/;
  // a honeypot of QPot's catalogue: letters, digits, - and _
  var TYPE = /^[A-Za-z0-9_-]{1,40}$/;
  // a country of the GeoIP database (a name, or its two-letter code): letters, spaces and . , ' ( ) -
  var COUNTRY = /^[\p{L}\p{M}][\p{L}\p{M} .,'()-]{0,55}$/u;
  // a category of a reputation list, i.e. "known attacker", "bot, crawler"
  var REPUTATION = /^[a-z0-9][a-z0-9 ,-]{0,39}$/i;
  // a node of a QPot cluster
  var SENSOR = /^[A-Za-z_][A-Za-z0-9_.-]{0,62}$/;

  function isIPv6(s) {
    if (!IPV6_CHARS.test(s) || s.indexOf(':') < 0) return false;
    try {
      // the URL parser knows every form of IPv6; only hex digits, colons and dots get this far
      return new URL('http://[' + s + ']/').hostname.length > 2;
    } catch (e) {
      return false;
    }
  }

  function ip(value) {
    return typeof value === 'string' && (IPV4.test(value) || isIPv6(value)) ? value : null;
  }

  function type(value) {
    return typeof value === 'string' && TYPE.test(value) ? value : null;
  }

  function sensor(value) {
    return typeof value === 'string' && SENSOR.test(value) ? value : null;
  }

  // an optional text: '' when there is none, null when there is one that does not fit
  function optional(value, pattern) {
    if (value === undefined || value === null || value === '') return '';
    return typeof value === 'string' && pattern.test(value) ? value : null;
  }

  function count(value) {
    var n = Number(value);
    return isFinite(n) && n >= 0 ? Math.floor(n) : 0;
  }

  function stamp(value) {
    return typeof value === 'number' && isFinite(value) && value > 0 ? value : null;
  }

  // ---------- links into the dashboard's events, built from checked values only ----------

  // value has passed type(), ip() or sensor(): no quotes, no markup; encoded all the same
  function events(field, value, range) {
    return '/dashboard#events?' + field + '=' + encodeURIComponent(value) + '&range=' + encodeURIComponent(range);
  }

  // ---------- reading the answers ----------

  function slots(list, points) {
    return (Array.isArray(list) ? list : []).map(function (b) {
      return { key: count(b && b.key), n: count(b && b.n) };
    }).sort(function (x, y) { return x.key - y.key; }).slice(-points);
  }

  function parseOverview(a, range, points) {
    var types = [];
    (Array.isArray(a.types) ? a.types : []).forEach(function (b) {
      var t = type(b && b.type);
      // shown with a capital, as T-Pot's types are; the link keeps QPot's name
      if (t) types.push({ type: t.charAt(0).toUpperCase() + t.slice(1), n: count(b.n), slots: slots(b.slots, points),
                          link: events('honeypot', t, range) });
    });
    return {
      range: range,
      partial: a.partial === true,
      total: count(a.total),
      previous: count(a.previous),
      // the range before, point for point (one span earlier)
      before: slots(a.before, points),
      slots: slots(a.slots, points),
      types: types.slice(0, SHOWN),
      sources: count(a.sources),
      honeypots: count(a.honeypots),
      latest: stamp(a.latest)
    };
  }

  function parseSources(a, range) {
    var out = [];
    (Array.isArray(a.top_sources) ? a.top_sources : []).forEach(function (b) {
      var address = ip(b && b.ip), country = optional(b && b.country, COUNTRY), rep = optional(b && b.rep, REPUTATION);
      if (!address || country === null || rep === null) return;
      out.push({ ip: address, n: count(b.n), country: country, rep: rep, link: events('source_ip', address, range) });
    });
    return out.slice(0, SHOWN);
  }

  function parseSensors(a, range) {
    var out = [];
    (Array.isArray(a.sensors) ? a.sensors : []).forEach(function (b) {
      var name = sensor(b && b.name);
      if (!name) return;
      out.push({ name: name, n: count(b.n), latest: stamp(b.latest), link: events('node', name, range) });
    });
    return out;
  }

  // attacks that came in since the previous answer of the same range, per point (the sum slides)
  function fresh(previous, now) {
    if (!previous || previous.range !== now.range) return null;
    // QPot: no points over time (no /api/pulse yet): the growth of the totals
    if (!now.slots.length) {
      return { attacks: Math.max(0, now.total - previous.total), sources: Math.max(0, now.sources - previous.sources) };
    }
    var seen = {}, newest = 0;
    previous.slots.forEach(function (b) { seen[b.key] = b.n; if (b.key > newest) newest = b.key; });
    var n = 0;
    now.slots.forEach(function (b) {
      if (b.key in seen) n += Math.max(0, b.n - seen[b.key]);
      else if (b.key > newest) n += b.n;
    });
    return { attacks: n, sources: Math.max(0, now.sources - previous.sources) };
  }

  // ---------- asking QPot ----------

  // a failed answer: status 0 when the API was not reached, `signin` when the QPot ID is missing
  // or not this instance's
  function failure(status, text) {
    var e = new Error(text);
    e.status = status;
    e.signin = status === 401 || status === 403;
    return e;
  }

  var answers = {};   // range -> { at, body }

  // QPot: GET /api/pulse is not in qpot serve yet (planned in the web UI's API contract). Until it
  // is, the page shows what the API already has - the counters of the last 24 hours
  // (GET /api/overview) and the top sources of the last 24 hours (GET /api/ioc) - and says that the
  // timeline is not available yet. USE_PULSE switches to /api/pulse; a 404 from it falls back too.
  var USE_PULSE = false;
  var partial = !USE_PULSE;

  function get(path, id) {
    var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, TIMEOUT) : 0;
    return fetch(path, {
      headers: { 'X-QPot-ID': id },
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (r) {
      clearTimeout(timer);
      if (r.status === 401 || r.status === 403) {
        throw failure(r.status, 'This QPot did not accept the saved QPot ID. Sign in again.');
      }
      if (r.status === 503) throw failure(503, 'QPot\'s database is not reachable. After a start it can take a minute.');
      if (r.status === 404) throw failure(404, 'Not available yet.');
      if (!r.ok) throw failure(r.status, 'QPot answered ' + r.status + '.');
      return r.json();
    }, function () {
      clearTimeout(timer);
      throw failure(0, 'The QPot API is not reachable. Is qpot serve running?');
    }).then(function (body) {
      if (!body || typeof body !== 'object') throw failure(502, 'QPot sent an answer the page cannot read.');
      return body;
    });
  }

  // the country's name for a two-letter code of the GeoIP database (T-Pot shows names)
  var regions = null;
  try { regions = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) { regions = null; }

  function countryName(code) {
    if (typeof code !== 'string' || !/^[A-Z]{2}$/.test(code)) return code;
    try { return (regions && regions.of(code)) || code; } catch (e) { return code; }
  }

  function time(value) {
    var t = typeof value === 'string' ? Date.parse(value) : NaN;
    return isFinite(t) && t > 0 ? t : null;
  }

  // the answer of /api/pulse, as far as /api/overview and /api/ioc give it: no points over time
  function askPartial(id) {
    return Promise.all([get('/api/overview', id), get('/api/ioc', id).catch(function () { return {}; })]).then(function (both) {
      var o = both[0], ioc = both[1];
      var types = (Array.isArray(o.honeypots) ? o.honeypots : []).map(function (h) {
        return { type: h && h.name, n: count(h && h.hits_24h) };
      }).filter(function (t) { return t.n > 0; }).sort(function (x, y) { return y.n - x.n; });
      var latest = null;
      (Array.isArray(o.recent_events) ? o.recent_events : []).forEach(function (e) {
        var t = time(e && e.time);
        if (t !== null && (latest === null || t > latest)) latest = t;
      });
      var top = (Array.isArray(ioc.ioc_list) ? ioc.ioc_list : []).map(function (s) {
        return { ip: s && s.source_ip, n: count(s && s.attack_count), country: countryName(s && s.country), rep: '' };
      }).sort(function (x, y) { return y.n - x.n; }).slice(0, 12);
      return {
        partial: true,
        total: count(o.events_24h),
        sources: count(o.unique_ips_24h),
        honeypots: types.length,
        latest: latest,
        types: types,
        top_sources: top,
        sensors: []
      };
    });
  }

  function ask(range) {
    var id = TPot.qpot ? TPot.qpot.id() : '';
    if (!id) return Promise.reject(failure(401, 'Sign in with this QPot\'s ID to see its attacks.'));
    var answer = partial ? askPartial(id) : get(PULSE + encodeURIComponent(range), id).catch(function (err) {
      if (!err || err.status !== 404) throw err;
      partial = true;
      return askPartial(id);
    });
    return answer.then(function (body) {
      answers[range] = { at: Date.now(), body: body };
      return body;
    });
  }

  function recent(range) {
    var a = answers[range];
    return a && Date.now() - a.at < REUSE ? Promise.resolve(a.body) : ask(range);
  }

  function range(key) {
    return RANGES[key] ? key : DEFAULT;
  }

  TPot.pulse = {
    load: function () { return Promise.resolve(RANGES); },
    // the ranges: { key: {points, every, lists, name, short, per} }; only the last 24 hours while
    // this qpot serve has no /api/pulse
    ranges: function () { return partial ? { '24h': RANGES['24h'] } : RANGES; },
    partial: function () { return partial; },
    overview: function (key) {
      var k = range(key);
      return ask(k).then(function (a) { return parseOverview(a, k, RANGES[k].points); });
    },
    sources: function (key) {
      var k = range(key);
      return recent(k).then(function (a) { return parseSources(a, k); });
    },
    sensors: function (key) {
      var k = range(key);
      return recent(k).then(function (a) { return parseSensors(a, k); });
    },
    fresh: fresh
  };
})();
