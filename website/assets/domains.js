/* Domainpreise aus der gemeinsamen Preisliste (/assets/domains.json). Die statische Tabelle bleibt als Fallback stehen. */
(function () {
  "use strict";
  var table = document.getElementById("domains-table");
  if (!table || !window.fetch) return;
  fetch("/assets/domains.json").then(function (r) { return r.json(); }).then(function (list) {
    var rows = list.tlds.map(function (t) {
      var price = t.price_per_year != null ? "Fr. " + Number(t.price_per_year).toFixed(2) : "auf Anfrage";
      var extra = t.orderable ? "" : " <span class=\"note2\">(auf Anfrage)</span>";
      return "<tr><th scope=\"row\">." + t.tld + extra + "</th><td>" + price + "</td></tr>";
    });
    table.querySelector("tbody").innerHTML = rows.join("");
    var stamp = document.getElementById("domains-updated");
    if (stamp && list.updated) stamp.textContent = "Preise inkl. MwSt, vorbehaltlich Änderungen. Letzte Anpassung: " + list.updated;
  }).catch(function () {});
})();
