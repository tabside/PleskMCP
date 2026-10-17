/* Bestellformular AI Hosting: holt Preisliste, Länder und ein Formular-Token vom Dienst, prüft die
   Verfügbarkeit neuer Domains live und sendet die Bestellung als JSON. Kein Framework nötig. */
(function () {
  "use strict";
  var SIGNUP_BASE = "https://mcp.example.com/plesk"; // PUBLIC_BASE_URL des PleskMCP-Dienstes
  var form = document.getElementById("aih-order");
  if (!form) return;
  var state = { config: null, token: null, tokenAt: 0, tld: null, available: null, busy: false };
  var el = function (id) { return document.getElementById(id); };
  var fmt = function (n, cur) { return (cur || "CHF") + " " + Number(n).toFixed(2); };

  function setError(field, text) {
    var box = form.querySelector('[data-error-for="' + field + '"]');
    if (box) box.textContent = text || "";
    var input = form.elements[field];
    if (input && input.setAttribute) input.setAttribute("aria-invalid", text ? "true" : "false");
  }
  function clearErrors() {
    form.querySelectorAll(".error").forEach(function (e) { e.textContent = ""; });
    el("aih-error").hidden = true;
  }
  function globalError(text) { el("aih-error").textContent = text; el("aih-error").hidden = false; }

  function fetchJson(url, opts) {
    return fetch(url, Object.assign({ credentials: "omit" }, opts || {})).then(function (r) {
      return r.json().then(function (data) { return { status: r.status, data: data }; });
    });
  }

  function loadToken() {
    return fetchJson(SIGNUP_BASE + "/signup/token").then(function (r) {
      state.token = r.data.token; state.tokenAt = Date.now(); state.minFill = (r.data.min_fill_seconds || 0) * 1000;
    });
  }

  function loadConfig() {
    return fetchJson(SIGNUP_BASE + "/signup/config").then(function (r) {
      state.config = r.data;
      var countries = form.elements.country;
      countries.innerHTML = "";
      r.data.countries.forEach(function (c) {
        var o = document.createElement("option"); o.value = c.code; o.textContent = c.name; countries.appendChild(o);
      });
      countries.value = "CH";
      el("aih-terms-link").href = r.data.terms_url;
      el("aih-terms-version").textContent = r.data.terms_version;
      var tlds = r.data.price_list.tlds.filter(function (t) { return t.orderable; });
      el("aih-tld-list").textContent = tlds.map(function (t) { return "." + t.tld + " (" + fmt(t.price_per_year, r.data.price_list.currency) + ")"; }).join(", ");
      if (!r.data.new_domains_enabled) {
        form.elements.domain_mode.value = "own";
        el("aih-mode-new").disabled = true;
        el("aih-new-hint").textContent = "Neue Domains können derzeit nicht online bestellt werden.";
      }
      updateSummary();
    });
  }

  function currentMode() { return form.querySelector('input[name="domain_mode"]:checked').value; }

  function normalize(d) { return (d || "").trim().toLowerCase().replace(/\.$/, "").replace(/^www\./, ""); }

  function tldFor(domain) {
    var parts = domain.split(".");
    for (var i = 1; i < parts.length; i++) {
      var cand = parts.slice(i).join(".");
      var hit = state.config.price_list.tlds.filter(function (t) { return t.tld === cand; })[0];
      if (hit) return hit;
    }
    return null;
  }

  function updateSummary() {
    if (!state.config) return;
    var cur = state.config.price_list.currency;
    var hosting = state.config.price_list.hosting.price_per_year;
    var domain = normalize(form.elements.domain.value);
    var rows = '<tr><td>' + state.config.price_list.hosting.name + ' (1 Jahr)</td><td>' + fmt(hosting, cur) + '</td></tr>';
    var total = hosting;
    state.tld = null;
    if (currentMode() === "new" && domain) {
      var tld = tldFor(domain);
      if (tld && tld.orderable) {
        state.tld = tld;
        rows += '<tr><td>Domain ' + escapeHtml(domain) + ' (1 Jahr)</td><td>' + fmt(tld.price_per_year, cur) + '</td></tr>';
        total += tld.price_per_year;
      }
    }
    rows += '<tr class="total"><td>Total pro Jahr inkl. MwSt</td><td>' + fmt(total, cur) + '</td></tr>';
    el("aih-summary-rows").innerHTML = rows;
    var phoneLabel = el("aih-phone-label");
    phoneLabel.textContent = (state.tld && state.tld.owner_fields.indexOf("phone") >= 0) ? "Telefon (für die Domain-Registrierung erforderlich)" : "Telefon (optional)";
  }

  function escapeHtml(s) { return s.replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  var checkTimer = null;
  function checkAvailability() {
    var out = el("aih-availability");
    out.className = "availability"; out.textContent = "";
    state.available = null;
    if (currentMode() !== "new") return;
    var domain = normalize(form.elements.domain.value);
    if (!domain || domain.indexOf(".") < 0) return;
    out.textContent = "Verfügbarkeit wird geprüft ...";
    fetchJson(SIGNUP_BASE + "/signup/check-domain?domain=" + encodeURIComponent(domain)).then(function (r) {
      if (normalize(form.elements.domain.value) !== domain) return;
      if (!r.data.ok) { out.textContent = r.data.message || "Prüfung nicht möglich."; return; }
      if (!r.data.orderable) { out.className = "availability taken"; out.textContent = r.data.message; return; }
      state.available = r.data.available;
      out.className = "availability " + (r.data.available ? "free" : "taken");
      out.textContent = r.data.available ? domain + " ist verfügbar: " + fmt(r.data.price_per_year, r.data.currency) + " pro Jahr" : domain + " ist nicht verfügbar.";
    }).catch(function () { out.textContent = "Prüfung nicht möglich."; });
  }

  form.elements.domain.addEventListener("input", function () { updateSummary(); clearTimeout(checkTimer); checkTimer = setTimeout(checkAvailability, 600); });
  form.querySelectorAll('input[name="domain_mode"]').forEach(function (r) {
    r.addEventListener("change", function () { updateSummary(); checkAvailability(); el("aih-own-hint").hidden = currentMode() !== "own"; });
  });

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (state.busy) return;
    clearErrors();
    if (currentMode() === "new" && state.available === false) { setError("domain", "Diese Domain ist nicht verfügbar."); return; }
    var payload = {};
    ["company", "first_name", "last_name", "street", "zip", "city", "country", "email", "phone", "domain", "website"].forEach(function (k) { payload[k] = form.elements[k].value; });
    payload.domain_mode = currentMode();
    payload.terms = form.elements.terms.checked ? "1" : "";
    payload.token = state.token;
    var wait = Math.max(0, state.tokenAt + (state.minFill || 0) - Date.now());
    state.busy = true; var btn = form.querySelector("button[type=submit]"); btn.disabled = true; btn.textContent = "Bestellung wird gesendet ...";
    setTimeout(function () {
      fetchJson(SIGNUP_BASE + "/signup", { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify(payload) })
        .then(function (r) {
          if (r.data.ok) { window.location.href = r.data.redirect; return; }
          if (r.data.errors) Object.keys(r.data.errors).forEach(function (f) { setError(f, r.data.errors[f]); });
          globalError(r.data.message || "Bitte die markierten Felder prüfen.");
          if (/^token_/.test(r.data.error || "")) loadToken();
        })
        .catch(function () { globalError("Die Bestellung konnte nicht gesendet werden. Bitte später erneut versuchen."); })
        .then(function () { state.busy = false; btn.disabled = false; btn.textContent = "Kostenpflichtig bestellen"; });
    }, wait);
  });

  Promise.all([loadConfig(), loadToken()]).catch(function () { globalError("Das Bestellformular konnte nicht geladen werden. Bitte die Seite neu laden."); });
})();
