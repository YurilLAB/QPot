/* StoreView remote operator console. All equipment values come from the controller. */
"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const state = { authenticated: false, credentials: null, access: 0, generation: 0, units: [], alarms: [], config: {}, selected: "", view: "dashboard", tab: "status", clock: "", history: [], deviceHistory: [], timer: null, refreshing: null, queue: Promise.resolve(), busy: false, historyGeneration: 0 };
  const viewNames = ["dashboard", "equipment", "alarms", "history", "configuration", "about"];
  const svgNS = "http://www.w3.org/2000/svg";
  class ControllerError extends Error { constructor(message, code) { super(message); this.code = code; } }
  const errorMessages = { 2: "The controller could not apply this change.", 3: "The value or request is invalid.", 9: "The controller could not read the request.", 11: "This function is not available.", 12: "This alarm record is no longer available. Refresh the alarm list.", 14: "This equipment is no longer available. Refresh the equipment list.", 15: "Your session has expired. Please log in again.", 16: "History is not recorded for this parameter.", 17: "No history is available for the selected period.", 63: "The equipment is offline. Check its communication status." };
  function text(id, value) { $(id).textContent = value === null || value === undefined || value === "" ? "—" : String(value); }
  function element(tag, content, className) { const node = document.createElement(tag); if (content !== undefined) node.textContent = String(content); if (className) node.className = className; return node; }
  function bool(value) { return value === true || value === 1 || value === "1" || value === "true" || value === "on"; }
  function number(value) { if (value === "" || value === null || value === undefined) return null; const n = Number(value); return Number.isFinite(n) ? n : null; }
  function temp(value) { const n = number(value); return n === null ? "—" : `${n.toFixed(1)} °C`; }
  function date(value) { if (!value) return "—"; const d = new Date(value); return Number.isFinite(d.getTime()) ? d.toLocaleString("en-GB", { timeZone: "UTC", hour12: false }) + " UTC" : String(value); }
  function datetimeInput(value) { const d = new Date(value); return Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 16) : ""; }
  function xmlValue(node, key, fallback = "") { if (!node) return fallback; const attr = node.getAttribute(key); if (attr !== null) return attr; const child = Array.from(node.children).find((item) => item.localName === key); return child ? child.textContent : fallback; }
  function xmlNodes(node, name) { return node ? Array.from(node.getElementsByTagName(name)) : []; }
  function escapeXML(value) { return String(value).replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" })[c]); }
  function notice(message, error = false) { $("notice-text").textContent = message; $("notice").classList.toggle("error", error); $("notice").hidden = false; }
  function connection(message, online) { text("connection-status", message); $("connection-lamp").className = `lamp ${online ? "online" : "offline"}`; }
  async function transfer(path, options, consume) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 10000);
    const headers = new Headers(options.headers || {});
    if (path.startsWith("/exports/") && state.authenticated && state.credentials) {
      const bytes = new TextEncoder().encode(state.credentials.user + ":" + state.credentials.password);
      headers.set("AKSM-Auth", "Basic " + btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join("")));
    }
    try { return await consume(await fetch(path, { credentials: "same-origin", cache: "no-store", ...options, headers, signal: controller.signal })); }
    catch (error) { if (error.name === "AbortError") throw new Error("The controller did not respond in time. Try again."); throw error; }
    finally { clearTimeout(timer); }
  }
  function stopPolling() { clearTimeout(state.timer); state.timer = null; }
  function showLogin(message = "") {
    stopPolling(); state.authenticated = false; state.credentials = null; state.access = 0; state.generation++; state.historyGeneration++; state.units = []; state.alarms = []; state.selected = "";
    $("console").hidden = true; $("login-view").hidden = false; $("logout").hidden = true; $("operator-name").textContent = "";
    $("username").value = ""; $("password").value = ""; $("login-error").textContent = message; $("login-error").hidden = !message;
    $("notice").hidden = true; connection(message ? "Session ended" : "System available", !message);
    $("username").focus();
  }
  function command(action, attrs = {}, children = "", options = {}) {
    const generation = state.generation;
    const task = async () => {
      if (!options.public && (!state.authenticated || generation !== state.generation)) throw new ControllerError("Session changed.", "stale");
      // This StoreView generation authenticates each XML body. Keep credentials
      // only in this page's memory; neither cookies nor browser storage supply them.
      const fields = { action, storeview_only: "1", version: "C", lang: "e", ...(!options.public ? state.credentials : {}), ...attrs };
      const xml = `<cmd ${Object.entries(fields).map(([key, value]) => `${key}="${escapeXML(value)}"`).join(" ")}${children ? `>${children}</cmd>` : "/>"}`;
      const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch("/xml.cgi", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" }, body: "xml=" + encodeURIComponent(xml), signal: controller.signal, cache: "no-store" });
        const body = await response.text();
        if (!response.ok) throw new Error(`The controller returned HTTP ${response.status}.`);
        const document = new DOMParser().parseFromString(body, "application/xml");
        if (document.querySelector("parsererror")) throw new Error("The controller returned an invalid response.");
        const root = document.documentElement;
        if (!root || root.localName !== "resp") throw new Error("The controller response was not recognized.");
        const code = Number(root.getAttribute("error"));
        if (!root.hasAttribute("error") || !Number.isInteger(code)) throw new Error("The controller response has no result code.");
        if (code !== 0) {
          if (code === 15 && !options.public && state.authenticated && generation === state.generation) showLogin(errorMessages[15]);
          throw new ControllerError(errorMessages[code] || `The controller refused the request (error ${code}).`, code);
        }
        if (!options.public && generation !== state.generation) throw new ControllerError("Session changed.", "stale");
        return root;
      } catch (error) { if (error.name === "AbortError") throw new Error("The controller did not respond in time. Try again."); throw error; }
      finally { clearTimeout(timeout); }
    };
    const result = state.queue.then(task, task); state.queue = result.catch(() => {}); return result;
  }
  function parseUnit(node) {
    return { node: xmlValue(node, "node"), name: xmlValue(node, "name"), model: xmlValue(node, "modelname"), serial: xmlValue(node, "device_id"), address: xmlValue(node, "node"), temperature: number(xmlValue(node, "value")), setpoint: number(xmlValue(node, "ctrl_val")), defrost: bool(xmlValue(node, "defrost")), compressor: null, door: null, enabled: null, online: bool(xmlValue(node, "online", "1")), status: xmlValue(node, "status"), alarm: bool(xmlValue(node, "alarm")), min: null, max: null, updated: "", type: xmlValue(node, "type") };
  }
  function epochDate(value) { const n = number(value); return n !== null && n > 0 ? new Date(n * 1000).toISOString() : ""; }
  function parseAlarm(node) { return { id: xmlValue(node, "ref"), node: xmlValue(node, "addr"), name: xmlValue(node, "deviceName"), message: xmlValue(node, "name"), priority: xmlValue(node, "action"), active: xmlValue(node, "status") === "active", acknowledged: xmlValue(node, "acknowledgement").toLowerCase() === "yes", occurred: epochDate(xmlValue(node, "epoch")), acktime: epochDate(xmlValue(node, "epoch_acked")) }; }
  function selectedUnit() { return state.units.find((unit) => unit.node === state.selected); }
  function activeAlarms() { return state.alarms.filter((alarm) => alarm.active); }
  function alarmState(alarm) { return alarm.active ? (alarm.acknowledged ? "Active · acknowledged" : "Active") : "Cleared"; }
  function unitStatus(unit) { return !unit.online ? "Offline" : unit.enabled === false ? "Main switch off" : unit.alarm ? "Alarm" : unit.defrost ? "Defrost" : unit.status || "Normal"; }
  function statusCell(unit) { return element("span", unitStatus(unit), `state ${!unit.online || unit.enabled === false ? "off" : unit.alarm ? "alarm" : unit.defrost ? "warn" : ""}`); }
  function tableRow(values) { const row = element("tr"); values.forEach((value) => { const cell = element("td"); if (value instanceof Node) cell.append(value); else cell.textContent = value === null || value === undefined || value === "" ? "—" : String(value); row.append(cell); }); return row; }
  function fillTable(id, rows, columns, empty = "No records available.") { const body = $(id); body.replaceChildren(); if (!rows.length) { const td = element("td", empty, "empty-cell"); td.colSpan = columns; const tr = element("tr"); tr.append(td); body.append(tr); } else rows.forEach((row) => body.append(row)); }
  function unitLink(unit) { const link = element("button", unit.name, "table-link"); link.type = "button"; link.dataset.unit = unit.node; return link; }
  function properties(id, values) { const list = $(id); list.replaceChildren(); values.forEach(([name, value]) => list.append(element("dt", name), element("dd", value === null || value === undefined || value === "" ? "—" : value))); }
  function ackButton(alarm) { if (alarm.acknowledged || !alarm.active) return element("span", alarm.acknowledged ? "Acknowledged" : "—"); const button = element("button", "Acknowledge", "ack-button"); button.type = "button"; button.dataset.ack = alarm.id; button.disabled = state.busy || !(state.access & 16384); button.setAttribute("aria-label", `Acknowledge ${alarm.message} on ${alarm.name}`); if (!(state.access & 16384)) button.title = "Your account cannot acknowledge alarms."; return button; }
  function renderAlarms() {
    const filter = $("alarm-filter").value;
    const filtered = state.alarms.filter((alarm) => filter === "all" || (filter === "active" && alarm.active && !alarm.acknowledged) || (filter === "acknowledged" && alarm.active && alarm.acknowledged) || (filter === "cleared" && !alarm.active));
    fillTable("all-alarms", filtered.map((alarm) => tableRow([date(alarm.occurred), alarm.name, alarm.message, alarm.priority, alarmState(alarm), alarm.acktime ? date(alarm.acktime) : alarm.acknowledged ? "Yes" : "No", ackButton(alarm)])), 7, "No alarms in this view.");
    text("alarm-summary", `${filtered.length} record${filtered.length === 1 ? "" : "s"}`);
    fillTable("dashboard-alarms", activeAlarms().slice(0, 8).map((alarm) => tableRow([date(alarm.occurred), alarm.name, alarm.message, alarm.priority, alarmState(alarm)])), 5, "No active alarms.");
    fillTable("device-alarms", state.alarms.filter((alarm) => alarm.node === state.selected).map((alarm) => tableRow([date(alarm.occurred), alarm.message, alarm.priority, alarmState(alarm), ackButton(alarm)])), 5, "No alarms for this equipment.");
    text("alarm-count", activeAlarms().filter((alarm) => !alarm.acknowledged).length); $("alarm-count").classList.toggle("has-alarms", activeAlarms().some((alarm) => !alarm.acknowledged));
  }
  function renderEquipment() {
    const unit = selectedUnit();
    if (!unit) {
      text("equipment-heading", "Equipment"); text("device-model", ""); text("device-address", ""); text("device-updated", "");
      $("device-status").replaceChildren(); properties("device-values", []);
      $("unit-setpoint").value = ""; $("unit-setpoint").removeAttribute("min"); $("unit-setpoint").removeAttribute("max"); $("unit-enabled").value = "";
      for (const id of ["unit-setpoint", "unit-enabled", "save-unit", "start-defrost", "stop-defrost"]) $(id).disabled = true;
      text("unit-save-status", "Waiting for equipment data…");
      return;
    }
    if ($("unit-save-status").textContent === "Waiting for equipment data…") $("unit-save-status").textContent = "";
    text("equipment-heading", unit.name); text("device-model", unit.model); text("device-address", unit.address); $("device-status").replaceChildren(statusCell(unit));
    properties("device-values", [["Temperature", temp(unit.temperature)], ["Temperature setpoint", temp(unit.setpoint)], ["Operating status", unitStatus(unit)], ["Main switch", unit.enabled === null ? "—" : unit.enabled ? "On" : "Off"], ["Defrost", unit.defrost ? "Active" : "Inactive"], ["Compressor", unit.compressor === null ? "—" : unit.compressor ? "Running" : "Stopped"], ["Door", unit.door === null ? "—" : unit.door ? "Open" : "Closed"], ["Communication", unit.online ? "Online" : "Offline"], ["Controller model", unit.model], ["Network address", unit.address]]);
    text("device-updated", "Last updated: " + date(unit.updated || state.clock));
    if (!$("unit-settings-form").dataset.dirty) {
      $("unit-setpoint").value = unit.setpoint === null ? "" : unit.setpoint;
      $("unit-enabled").value = String(unit.enabled);
      if (unit.min !== null) $("unit-setpoint").min = unit.min; else $("unit-setpoint").removeAttribute("min");
      if (unit.max !== null) $("unit-setpoint").max = unit.max; else $("unit-setpoint").removeAttribute("max");
      text("setpoint-range", unit.min !== null && unit.max !== null ? `Allowed range: ${temp(unit.min)} to ${temp(unit.max)}` : "");
    }
    const canControl = Boolean(state.access & 256);
    $("unit-setpoint").disabled = state.busy || !canControl; $("unit-enabled").disabled = state.busy || !canControl; $("save-unit").disabled = state.busy || !canControl;
    $("start-defrost").disabled = state.busy || !canControl || unit.defrost || unit.enabled !== true; $("stop-defrost").disabled = state.busy || !canControl || !unit.defrost;
    if (!canControl) text("unit-save-status", "Read-only access");
  }
  function renderConfiguration() {
    const c = state.config;
    properties("configuration-properties", [["Site name", c.site], ["Unit name", c.hostname], ["Application", c.application], ["Temperature unit", "°C"], ["Controller time", date(state.clock)], ["Equipment count", state.units.length]]);
    properties("network-properties", [["Unit name", c.hostname], ["XML interface", "Enabled"], ["Equipment online", `${state.units.filter((unit) => unit.online).length} / ${state.units.length}`]]);
    properties("system-properties", [["Product", c.model || "AK-SM 800A"], ["Current Firmware Version", c.software], ["StoreView version", c.uiVersion], ["Serial number", c.serial], ["Unit name", c.hostname], ["Site name", c.site], ["Controller time", date(state.clock)]]);
    fillTable("inventory-values", state.units.map((unit) => tableRow([unitLink(unit), unit.type, unit.model, unit.address, unit.serial])), 5);
  }
  function render() {
    const c = state.config; text("plant-name", c.site); text("plant-location", c.hostname || "Remote management"); text("system-clock", date(state.clock)); text("controller-address", c.hostname);
    text("footer-model", `${c.model || "AK-SM 800A"}${c.software ? " · Software " + c.software : ""}`);
    text("summary-units", state.units.length); text("summary-alarm-units", state.units.filter((unit) => unit.alarm).length); text("summary-alarms", activeAlarms().length); text("summary-communications", `${state.units.filter((unit) => unit.online).length} / ${state.units.length} online`); text("tree-summary", `${state.units.length} configured units`); text("network-status", state.units.every((unit) => unit.online) ? "Online" : "Check equipment");
    const tree = $("unit-tree"); tree.replaceChildren(); state.units.forEach((unit) => { const button = element("button"); button.type = "button"; button.dataset.unit = unit.node; button.setAttribute("aria-current", String(unit.node === state.selected)); button.append(element("span", undefined, `unit-dot ${!unit.online || unit.enabled === false ? "off" : unit.alarm ? "alarm" : ""}`), element("span", unit.name, "tree-label"), element("span", temp(unit.temperature), "tree-temp")); tree.append(button); });
    fillTable("dashboard-units", state.units.map((unit) => tableRow([unitLink(unit), unit.address, temp(unit.temperature), temp(unit.setpoint), unit.defrost ? "Active" : "Inactive", unit.compressor === null ? "—" : unit.compressor ? "Running" : "Stopped", statusCell(unit)])), 7, "No refrigeration equipment configured.");
    const selection = $("history-unit").value; $("history-unit").replaceChildren(); state.units.forEach((unit) => { const option = element("option", unit.name); option.value = unit.node; $("history-unit").append(option); }); if (state.units.some((unit) => unit.node === selection)) $("history-unit").value = selection; else $("history-unit").value = state.selected;
    renderEquipment(); renderAlarms(); renderConfiguration(); text("last-refresh", "Last update: " + date(state.clock));
  }
  function setView(view, focus = true) {
    if (!viewNames.includes(view)) return; state.view = view;
    document.querySelectorAll(".view").forEach((node) => { node.hidden = node.id !== "view-" + view; });
    document.querySelectorAll(".main-nav [data-view]").forEach((button) => { if (button.dataset.view === view) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current"); });
    if (focus) $("workspace").focus({ preventScroll: true });
    if (view === "history" && !state.history.length) loadHistory().catch(reportError);
  }
  function setTab(tab) {
    if (!["status", "alarms", "settings", "graph"].includes(tab)) return; state.tab = tab;
    document.querySelectorAll(".device-tab").forEach((node) => { node.hidden = node.id !== "device-tab-" + tab; });
    document.querySelectorAll("[data-device-tab]").forEach((button) => { if (button.dataset.deviceTab === tab) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current"); });
    if (tab === "graph") loadDeviceHistory().catch(reportError);
  }
  function selectUnit(node) {
    if (!state.units.some((unit) => unit.node === node)) return;
    if (node !== state.selected) { state.selected = node; delete $("unit-settings-form").dataset.dirty; text("unit-save-status", ""); state.deviceHistory = []; }
    setView("equipment"); render(); if (state.tab === "graph") loadDeviceHistory().catch(reportError);
  }
  function reportError(error) { if (error.code === "stale" || (error.code === 15 && !state.authenticated)) return; notice(error.message || "The operation failed. Refresh and try again.", true); }

  // Controller contract and actions are grouped below; the view consumes no invented values.
  async function refresh() {
    if (!state.authenticated) return; if (state.refreshing) return state.refreshing;
    const generation = state.generation; stopPolling();
    state.refreshing = (async () => {
      try {
        const devices = await command("read_devices");
        const units = xmlNodes(devices, "device").map(parseUnit);
        const values = units.map((unit) => ["AirTemperature", "Setpoint", "Defrost", "Compressor", "Door", "MainSwitch"].map((tag) => `<val nodetype="16" node="${escapeXML(unit.node)}" tag="${tag}" field="all"/>`).join("")).join("");
        const parameters = values ? await command("read_val", { units: "S", num_only: "1" }, values) : null;
        const summary = await command("alarm_summary");
        const alarms = [];
        for (const [group, active, acknowledged] of [["active", true, false], ["acked", true, true], ["cleared", false, false]]) {
          for (const reference of xmlNodes(summary.querySelector(group), "ref")) {
            const id = reference.textContent.trim(); const old = state.alarms.find((alarm) => alarm.id === id);
            if (old && old.active === active && (group === "cleared" || old.acknowledged === acknowledged)) { alarms.push(old); continue; }
            try { const detail = await command("alarm_detail", { current: id, expanded: 2, date_format: 2, time_format: 1, units: "S" }); alarms.push(parseAlarm(detail)); } catch (error) { if (error.code !== 12) throw error; }
          }
        }
        const clock = await command("read_date_time");
        if (generation !== state.generation) return;
        xmlNodes(parameters, "val").forEach((value) => {
          const unit = units.find((candidate) => candidate.node === xmlValue(value, "node")); if (!unit) return;
          const tag = xmlValue(value, "tag"), current = xmlValue(value, "value", value.textContent.trim());
          if (tag === "AirTemperature") unit.temperature = number(current);
          if (tag === "Setpoint") { unit.setpoint = number(current); unit.min = number(xmlValue(value, "min")); unit.max = number(xmlValue(value, "max")); }
          if (tag === "Defrost") unit.defrost = bool(current);
          if (tag === "Compressor") unit.compressor = bool(current);
          if (tag === "Door") unit.door = bool(current);
          if (tag === "MainSwitch") unit.enabled = bool(current);
        });
        state.units = units;
        state.alarms = alarms.sort((a, b) => Number(b.id) - Number(a.id));
        const epoch = number(xmlValue(clock, "epoch")); state.clock = epoch === null ? "" : new Date(epoch * 1000).toISOString();
        state.config = { ...state.config, site: xmlValue(devices, "store_name"), hostname: xmlValue(devices, "unit_name"), software: xmlValue(devices, "software") };
        if (!state.units.some((unit) => unit.node === state.selected)) { state.selected = state.units[0]?.node || ""; delete $("unit-settings-form").dataset.dirty; }
        if (!$("history-to").value && state.clock) { $("history-to").value = datetimeInput(state.clock); $("history-from").value = datetimeInput(new Date(new Date(state.clock).getTime() - 6 * 3600000)); }
        render(); connection("Connected", true);
      } catch (error) { if (generation === state.generation && state.authenticated) { connection("Communication interrupted", false); reportError(error); } }
      finally { state.refreshing = null; if (state.authenticated && generation === state.generation && !document.hidden) state.timer = setTimeout(refresh, 5000); }
    })(); return state.refreshing;
  }
  async function operation(button, task) {
    if (state.busy) return; state.busy = true; const oldText = button.textContent; button.disabled = true; button.textContent = "Please wait…"; stopPolling(); renderEquipment();
    try { if (state.refreshing) await state.refreshing; stopPolling(); await task(); } catch (error) { reportError(error); } finally { state.busy = false; button.textContent = oldText; button.disabled = false; if (state.authenticated) { await refresh(); renderEquipment(); } }
  }
  async function getHistory(node, from, to) {
    const first = new Date(from), last = new Date(to);
    const start = `<starttime><year>${first.getUTCFullYear() % 100}</year><month>${first.getUTCMonth() + 1}</month><day>${first.getUTCDate()}</day><hour>${first.getUTCHours()}</hour><minute>${first.getUTCMinutes()}</minute><second>${first.getUTCSeconds()}</second></starttime>`;
    const series = {};
    for (const [tag, key] of [["AirTemperature", "temperature"], ["Setpoint", "setpoint"], ["Defrost", "defrost"], ["Compressor", "compressor"]]) {
      let response;
      try { response = await command("read_history", { node, nodetype: 16, tag, sample_rate: 60, units: "S" }, start); }
      catch (error) { if (error.code === 17) return []; throw error; }
      const epoch = number(xmlValue(response.querySelector("starttime"), "epoch"));
      const rate = number(xmlValue(response, "actual_sample_rate", xmlValue(response, "real_sample_rate")));
      if (epoch === null || rate === null || rate <= 0) throw new Error("The history response has no recording interval.");
      series[key] = new Map();
      xmlNodes(response.querySelector("data"), "y").forEach((value, index) => { const time = (epoch + index * rate) * 1000; if (time >= first.getTime() && time <= last.getTime()) series[key].set(time, number(value.textContent)); });
    }
    return Array.from(series.temperature, ([time, temperature]) => ({ time: new Date(time).toISOString(), temperature, setpoint: series.setpoint.get(time) ?? null, defrost: series.defrost.get(time) === undefined || series.defrost.get(time) === null ? null : Boolean(series.defrost.get(time)), compressor: series.compressor.get(time) === undefined || series.compressor.get(time) === null ? null : Boolean(series.compressor.get(time)) })).filter((sample) => sample.temperature !== null);
  }
  async function loadHistory() {
    if (!state.authenticated || !$("history-unit").value) return;
    if (!$("history-form").reportValidity()) return;
    const from = new Date($("history-from").value + "Z"); const to = new Date($("history-to").value + "Z");
    if (from >= to) throw new Error("The end time must be later than the start time.");
    const node = $("history-unit").value; const generation = ++state.historyGeneration; const session = state.generation;
    const samples = await getHistory(node, from.toISOString(), to.toISOString());
    if (generation !== state.historyGeneration || session !== state.generation) return;
    state.history = samples; drawChart("history-chart", "history-stats", samples);
    text("history-caption", state.units.find((unit) => unit.node === node)?.name); text("history-record-count", `${samples.length} samples`);
    fillTable("history-values", samples.slice().reverse().map((sample) => tableRow([date(sample.time), sample.temperature.toFixed(1), sample.setpoint === null ? "—" : sample.setpoint.toFixed(1), sample.defrost === null ? "—" : sample.defrost ? "Active" : "Inactive", sample.compressor === null ? "—" : sample.compressor ? "Running" : "Stopped"])), 5, "No samples in the selected time range.");
  }
  async function loadDeviceHistory() {
    const node = state.selected; const clock = new Date(state.clock); if (!node || !Number.isFinite(clock.getTime())) return;
    const session = state.generation; const period = $("device-period").value;
    const samples = await getHistory(node, new Date(clock.getTime() - Number(period) * 3600000).toISOString(), clock.toISOString());
    if (session !== state.generation || node !== state.selected || period !== $("device-period").value) return;
    state.deviceHistory = samples; drawChart("device-chart", "device-chart-stats", samples);
  }
  function drawChart(id, statsId, samples) {
    const container = $(id); container.replaceChildren(); $(statsId).replaceChildren();
    if (!samples.length) { container.append(element("p", "No history samples available for this period.", "field-help")); return; }
    const width = 900, height = 270, left = 55, right = 22, top = 18, bottom = 36;
    const all = samples.flatMap((sample) => [sample.temperature, sample.setpoint]).filter((value) => value !== null);
    const low = Math.floor(Math.min(...all) - 1), high = Math.ceil(Math.max(...all) + 1);
    const times = samples.map((sample) => new Date(sample.time).getTime()); const start = Math.min(...times), end = Math.max(...times);
    const x = (time) => left + ((time - start) / (end - start || 1)) * (width - left - right);
    const y = (value) => top + ((high - value) / (high - low || 1)) * (height - top - bottom);
    function shape(name, attrs, content) { const node = document.createElementNS(svgNS, name); Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value))); if (content !== undefined) node.textContent = content; return node; }
    const svg = shape("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `Temperature and setpoint from ${date(samples[0].time)} to ${date(samples[samples.length - 1].time)}` });
    for (let i = 0; i < 5; i++) { const value = low + ((high - low) * i) / 4; const py = y(value); svg.append(shape("line", { x1: left, y1: py, x2: width - right, y2: py, stroke: "#dce4e9" }), shape("text", { x: left - 8, y: py + 4, "text-anchor": "end" }, value.toFixed(1))); }
    svg.append(shape("text", { x: 12, y: 13 }, "°C"));
    for (let i = 0; i < 5; i++) { const time = start + ((end - start) * i) / 4; const px = x(time); const label = new Date(time).toISOString().slice(11, 16); svg.append(shape("line", { x1: px, y1: top, x2: px, y2: height - bottom, stroke: "#edf1f3" }), shape("text", { x: px, y: height - 12, "text-anchor": "middle" }, label)); }
    for (const [key, color, dash] of [["setpoint", "#b45b39", "6 4"], ["temperature", "#357da1", ""]]) { const points = samples.filter((sample) => sample[key] !== null).map((sample) => `${x(new Date(sample.time).getTime()).toFixed(2)},${y(sample[key]).toFixed(2)}`).join(" "); if (points) svg.append(shape("polyline", { points, fill: "none", stroke: color, "stroke-width": 2, "stroke-dasharray": dash })); }
    container.append(svg);
    const values = samples.map((sample) => sample.temperature); const stats = $(statsId);
    const legend = element("span"); legend.append(element("i", undefined, "legend-line"), document.createTextNode("Temperature")); const setpoint = element("span"); setpoint.append(element("i", undefined, "legend-line setpoint"), document.createTextNode("Setpoint"));
    stats.append(legend, setpoint, element("span", `Min ${temp(Math.min(...values))}`), element("span", `Max ${temp(Math.max(...values))}`), element("span", `Average ${temp(values.reduce((sum, value) => sum + value, 0) / values.length)}`), element("span", "Time: UTC"));
  }
  async function download(path, filename) {
    const generation = state.generation;
    try { const blob = await transfer(path, {}, async (response) => { if (generation !== state.generation) return null; if (response.status === 401 || response.status === 403) { showLogin(errorMessages[15]); return null; } if (!response.ok) throw new Error(`Export failed (HTTP ${response.status}).`); return response.blob(); }); if (!blob || generation !== state.generation) return; const url = URL.createObjectURL(blob); const link = element("a"); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (error) { if (generation === state.generation) reportError(error); }
  }
  function historyExport(node, from, to) { const query = new URLSearchParams({ node }); if (from) query.set("from", from); if (to) query.set("to", to); return download("/exports/history.csv?" + query, "temperature-history.csv"); }
  async function readSnapshot() {
    const generation = state.generation;
    const body = await transfer("/exports/config.xml", {}, async (response) => { if (generation !== state.generation) throw new ControllerError("Session changed.", "stale"); if (response.status === 401 || response.status === 403) { showLogin(errorMessages[15]); throw new ControllerError(errorMessages[15], 15); } if (!response.ok) throw new Error("System information could not be loaded."); return response.text(); });
    const doc = new DOMParser().parseFromString(body, "application/xml");
    if (doc.querySelector("parsererror") || doc.documentElement.localName !== "configuration") throw new Error("The system information response was not recognized.");
    if (generation !== state.generation) return;
    const identity = doc.querySelector("controller");
    state.config = { ...state.config, model: xmlValue(identity, "model"), serial: xmlValue(identity, "serial"), application: xmlValue(identity, "application"), hostname: xmlValue(identity, "unit_name"), site: xmlValue(identity, "store_name"), software: xmlValue(identity, "firmware") };
    render();
  }
  async function readVersion() {
    try { const body = await transfer("/SVB5.ver", {}, async (response) => response.ok ? response.text() : ""); const version = body.trim(); if (!version || version.length > 60) return; state.config.uiVersion = version; text("login-version", version); if (state.authenticated) renderConfiguration(); } catch (_) { /* A failed version read does not prevent operator log in. */ }
  }

  document.addEventListener("click", (event) => {
    const target = event.target.closest("button"); if (!target) return;
    if (target.dataset.view) setView(target.dataset.view);
    if (target.dataset.unit) selectUnit(target.dataset.unit);
    if (target.dataset.deviceTab) setTab(target.dataset.deviceTab);
    if (target.classList.contains("refresh")) refresh();
    if (target.dataset.ack) operation(target, async () => { await command("write_alarm_ack", { ref: target.dataset.ack }); notice("Alarm acknowledged."); });
  });
  $("dismiss-notice").addEventListener("click", () => { $("notice").hidden = true; });
  $("site-node").addEventListener("click", () => setView("dashboard"));
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault(); const submit = $("login-submit"); if (submit.disabled) return; submit.disabled = true; submit.textContent = "Connecting…"; $("login-error").hidden = true;
    const user = $("username").value.trim(); const password = $("password").value; $("password").value = "";
    try { const auth = await command("getauth", { user, password }, "", { public: true }); state.access = number(xmlValue(auth, "authtype")) || 0; if (!state.access || !xmlValue(auth, "authorization")) throw new ControllerError("The user name or password is incorrect.", 15); state.credentials = { user, password }; $("username").value = ""; state.authenticated = true; state.generation++; $("login-view").hidden = true; $("console").hidden = false; $("logout").hidden = false; text("operator-name", user); delete $("unit-settings-form").dataset.dirty; state.history = []; $("history-from").value = ""; $("history-to").value = ""; setView("dashboard", false); render(); await refresh(); if (state.authenticated) { await readSnapshot().catch(reportError); $("workspace").focus(); } }
    catch (error) { $("login-error").textContent = error.code === 15 ? "The user name or password is incorrect." : error.message; $("login-error").hidden = false; connection("Log in required", false); $("password").focus(); }
    finally { submit.disabled = false; submit.textContent = "Log in"; }
  });
  $("logout").addEventListener("click", async () => { showLogin(); $("login-submit").disabled = true; try { await state.queue; await transfer("/logout", { method: "POST" }, async (response) => { if (!response.ok) throw new Error("Log out failed"); }); } catch (error) { $("login-error").textContent = "The controller could not confirm log out. Close this browser window to end remote access."; $("login-error").hidden = false; } finally { $("login-submit").disabled = false; } });
  $("alarm-filter").addEventListener("change", renderAlarms);
  $("unit-settings-form").addEventListener("input", () => { $("unit-settings-form").dataset.dirty = "true"; text("unit-save-status", "Unsaved changes"); });
  $("unit-settings-form").addEventListener("submit", (event) => { event.preventDefault(); const node = state.selected; const setpoint = $("unit-setpoint").value; const enabled = $("unit-enabled").value === "true"; operation($("save-unit"), async () => { await command("write_val", { units: "S" }, `<val nodetype="16" node="${escapeXML(node)}" tag="Setpoint" set="${escapeXML(setpoint)}"/>`); await command("set_main_switch", { node, nodetype: 16, operation: enabled ? 1 : 0 }); if (state.selected === node) { delete $("unit-settings-form").dataset.dirty; text("unit-save-status", "Settings saved"); } notice("Equipment settings saved."); }); });
  for (const [id, value] of [["start-defrost", 1], ["stop-defrost", 0]]) $(id).addEventListener("click", () => { const node = state.selected; operation($(id), async () => { await command("set_defrost", { node, nodetype: 16, operation: value }); notice(value ? "Manual defrost started." : "Manual defrost ended."); }); });
  $("history-form").addEventListener("submit", (event) => { event.preventDefault(); loadHistory().catch(reportError); });
  $("device-draw").addEventListener("click", () => loadDeviceHistory().catch(reportError));
  $("device-period").addEventListener("change", () => loadDeviceHistory().catch(reportError));
  $("history-export").addEventListener("click", () => { if (!$("history-form").reportValidity()) return; const from = new Date($("history-from").value + "Z"), to = new Date($("history-to").value + "Z"); if (from >= to) { notice("The end time must be later than the start time.", true); return; } historyExport($("history-unit").value, from.toISOString(), to.toISOString()); });
  $("device-export").addEventListener("click", () => { const to = new Date(state.clock); if (state.selected && Number.isFinite(to.getTime())) historyExport(state.selected, new Date(to.getTime() - Number($("device-period").value) * 3600000).toISOString(), to.toISOString()); });
  $("export-alarms").addEventListener("click", () => download("/exports/alarms.csv", "alarm-history.csv"));
  $("config-export").addEventListener("click", () => download("/exports/config.xml", "system-configuration.xml"));
  $("maintenance-export").addEventListener("click", () => download("/exports/maintenance.zip", "site-maintenance.zip"));
  document.addEventListener("visibilitychange", () => { if (document.hidden) stopPolling(); else if (state.authenticated) refresh(); });
  window.addEventListener("pagehide", stopPolling);
  showLogin(); readVersion();
})();
