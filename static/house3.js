// House 3 of the "three houses" experiment: if this runs, the client executes
// JavaScript. One same-origin ping with a few coarse facts that tell browsers
// from headless ones (webdriver flag, screen size, time zone, language, cores).
(function () {
  "use strict";
  var el = document.getElementById("house");
  if (!el) return;
  var r = el.getAttribute("data-r") || "";
  var q = "r=" + encodeURIComponent(r);
  function add(k, v) { if (v !== undefined && v !== null && v !== "") q += "&" + k + "=" + encodeURIComponent(String(v).slice(0, 24)); }
  try {
    add("wd", navigator.webdriver ? 1 : 0);
    add("sw", screen.width); add("sh", screen.height);
    add("tz", Intl.DateTimeFormat().resolvedOptions().timeZone);
    add("lang", navigator.language);
    add("hc", navigator.hardwareConcurrency);
  } catch (e) { /* keep the ping even if a fact is unavailable */ }
  var done = function (ok) { var s = document.getElementById("js-state"); if (s) s.textContent = ok ? "ran (pinged the server)" : "ran (ping failed)"; };
  if (typeof fetch !== "function") { done(false); return; }
  fetch("/houses/3/js-ping?" + q, { method: "GET", credentials: "omit", cache: "no-store" })
    .then(function (res) { done(res.ok); }, function () { done(false); });
})();
