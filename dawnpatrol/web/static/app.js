// DawnPatrol console: run progress polling, the start form, delete confirmations.
// Text from the server is only ever set with textContent: log lines and
// stage names can contain attacker-written strings.
(function () {
  "use strict";

  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    var msg = form.getAttribute && form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) ev.preventDefault();
  });

  var live = document.querySelector("[data-poll]");
  if (!live) return;
  var url = live.getAttribute("data-poll");
  var logEl = document.querySelector("[data-log]");
  var follow = document.querySelector("[data-follow]");
  var statusEl = document.querySelector("[data-status]");
  var lastState = null;

  function duration(s) {
    if (s === null || s === undefined || isNaN(s)) return "";
    s = Math.round(s);
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    if (h) return h + "h " + String(m).padStart(2, "0") + "m";
    return m ? m + "m " + String(sec).padStart(2, "0") + "s" : sec + "s";
  }
  function when(iso) {
    if (!iso) return "—";
    return iso.replace("T", " ").slice(0, 16) + " UTC";
  }
  function setField(name, text) {
    var el = live.querySelector('[data-field="' + name + '"]');
    if (el) el.textContent = text;
  }

  function render(p) {
    var running = p.state === "running";
    live.querySelector("[data-pulse]").hidden = !running;
    var form = document.querySelector("[data-start-form]");
    var busyNote = document.querySelector("[data-busy-note]");
    if (form) form.hidden = running;
    if (busyNote) busyNote.hidden = !running;
    live.querySelector("[data-headline]").textContent =
      running ? "Run in progress" : (p.state === "idle" ? "No run yet" : "Last run: " + p.state);
    var report = live.querySelector("[data-report]");
    report.hidden = p.state !== "finished";
    if (p.run_id) report.setAttribute("href", "/runs/" + encodeURIComponent(p.run_id));
    setField("run_id", p.run_id || "—");
    setField("started_at", when(p.started_at));
    setField("trigger", p.trigger || "—");
    setField("elapsed", duration(p.elapsed_seconds));
    setField("current_stage", p.current_stage || "—");
    setField("model_calls", String(p.model_calls || 0));
    setField("tool_calls", String(p.tool_calls || 0) + (p.tool_budget ? " / " + p.tool_budget : ""));
    setField("send_email", p.send_email ? "yes" : "no");
    var r = p.result;
    setField("result", r ? ((r.status || "") +
      (r.finding_count !== null && r.finding_count !== undefined ? ", " + r.finding_count + " finding(s)" : "") +
      (r.error ? " — " + r.error : "")) : "—");

    var strip = live.querySelector("[data-stages]");
    var stages = p.stages || {};
    if (strip) {
      Object.keys(stages).forEach(function (name) {
        var st = stages[name];
        var li = strip.querySelector('[data-stage="' + name + '"]');
        if (!li) {
          li = document.createElement("li");
          li.setAttribute("data-stage", name);
          var n = document.createElement("span"); n.className = "stage-name"; n.textContent = name;
          var t = document.createElement("span"); t.className = "stage-time";
          li.appendChild(n); li.appendChild(t); strip.appendChild(li);
        }
        li.className = "stage stage-" + st.state;
        li.querySelector(".stage-time").textContent =
          st.seconds !== null && st.seconds !== undefined ? duration(st.seconds)
            : (st.state === "active" ? "running" : "");
      });
    }

    if (logEl) {
      var lines = (p.log || []).map(function (l) {
        return l.ts + " " + (l.level + "       ").slice(0, 7) + " " + l.logger + "  " + l.msg;
      });
      logEl.textContent = lines.join("\n");
      if (!follow || follow.checked) logEl.scrollTop = logEl.scrollHeight;
    }
    if (lastState === "running" && !running && statusEl) {
      statusEl.textContent = "Run " + p.state + ".";
    }
    lastState = p.state;
  }

  function poll() {
    fetch(url, { headers: { "Accept": "application/json" }, credentials: "same-origin", cache: "no-store" })
      .then(function (resp) {
        if (resp.status === 401) { window.location = "/login?next=/runs"; throw new Error("login"); }
        return resp.json();
      })
      .then(function (p) {
        if (p.error) { if (statusEl) statusEl.textContent = p.error; return; }
        render(p);
        if (statusEl && p.state === "running") statusEl.textContent = "Refreshes every 2 seconds.";
      })
      .catch(function () { /* keep polling */ })
      .finally(function () { setTimeout(poll, 2000); });
  }
  if (logEl && (!follow || follow.checked)) logEl.scrollTop = logEl.scrollHeight;
  setTimeout(poll, 2000);
})();
