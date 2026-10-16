// Mythaia site: reveal on scroll, copy the certificate fingerprint, remember the language.
// Nothing here talks to a server.
(function () {
  "use strict";

  var KEY = "mythaia.lang";
  var PAGES = { en: "", ru: "ru/", tk: "tk/", zh: "zh/", fa: "fa/" };

  function stored() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }
  function store(code) {
    try { localStorage.setItem(KEY, code); } catch (e) { /* private mode: fine */ }
  }

  // First visit to the English root: follow the browser's language once.
  var root = document.documentElement.lang === "en";
  if (root && !stored()) {
    var wanted = (navigator.languages || [navigator.language || ""]).map(function (l) {
      return String(l).toLowerCase().split("-")[0];
    });
    for (var i = 0; i < wanted.length; i++) {
      var code = wanted[i];
      if (code === "en") break;
      if (PAGES[code]) {
        store(code);
        location.replace(PAGES[code] + location.hash);
        return;
      }
    }
  }

  document.addEventListener("click", function (event) {
    var link = event.target.closest && event.target.closest("a[data-lang]");
    if (link) store(link.getAttribute("data-lang"));

    // Close the language menu on a click outside it.
    document.querySelectorAll("details.langs[open]").forEach(function (menu) {
      if (!menu.contains(event.target)) menu.removeAttribute("open");
    });

    var button = event.target.closest && event.target.closest("button[data-copy]");
    if (button) {
      var source = document.getElementById(button.getAttribute("data-copy"));
      var label = button.textContent;
      var done = function () {
        button.textContent = button.getAttribute("data-done");
        setTimeout(function () { button.textContent = label; }, 2000);
      };
      if (navigator.clipboard && source) navigator.clipboard.writeText(source.textContent.trim()).then(done, function () {});
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      document.querySelectorAll("details.langs[open]").forEach(function (menu) { menu.removeAttribute("open"); });
    }
  });

  var items = document.querySelectorAll(".reveal");
  if (!("IntersectionObserver" in window)) {
    items.forEach(function (el) { el.classList.add("in"); });
    return;
  }
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add("in");
        observer.unobserve(entry.target);
      }
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  items.forEach(function (el, index) {
    el.style.transitionDelay = (index % 4) * 70 + "ms";
    observer.observe(el);
  });
})();
