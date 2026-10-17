/* Domainpreise aus der gemeinsamen Preisliste (assets/domains.json). */
(function () {
  "use strict";
  var table = document.getElementById("domains-table");
  if (!table) return;
  fetch("/assets/domains.json").then(function (r) { return r.json(); }).then(function (list) {
    var cur = list.currency || "CHF";
    var rows = list.tlds.map(function (t) {
      var price = t.orderable && t.price_per_year != null ? cur + " " + Number(t.price_per_year).toFixed(2) + " pro Jahr" : "auf Anfrage";
      var note = t.note ? ' <span class="hint">' + t.note + "</span>" : "";
      var order = t.orderable ? ' <a href="/ki-hosting/bestellen/">online bestellbar</a>' : "";
      return "<tr><td>." + t.tld + "</td><td>" + price + "</td><td>" + note + order + "</td></tr>";
    });
    table.querySelector("tbody").innerHTML = rows.join("");
    var stamp = document.getElementById("domains-updated");
    if (stamp && list.updated) stamp.textContent = "Stand " + list.updated + ", alle Preise inkl. MwSt.";
  }).catch(function () { table.querySelector("tbody").innerHTML = '<tr><td colspan="3">Die Preisliste konnte nicht geladen werden.</td></tr>'; });
})();
