// Copy buttons and the theme toggle. The site works without this file.
(function () {
  "use strict";
  try {
    var saved = localStorage.getItem("cactarium-theme");
    if (saved === "dark" || saved === "light") document.documentElement.dataset.theme = saved;
  } catch (e) {}
  document.addEventListener("click", function (ev) {
    var copy = ev.target.closest("[data-copy]");
    if (copy && navigator.clipboard) {
      navigator.clipboard.writeText(copy.getAttribute("data-copy")).then(function () {
        copy.setAttribute("aria-label", "Copied");
        copy.classList.add("copied");
        setTimeout(function () { copy.setAttribute("aria-label", "Copy command"); copy.classList.remove("copied"); }, 1500);
      });
    }
    var toggle = ev.target.closest("[data-theme-toggle]");
    if (toggle) {
      var root = document.documentElement;
      var dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
      root.dataset.theme = dark ? "light" : "dark";
      try { localStorage.setItem("cactarium-theme", root.dataset.theme); } catch (e) {}
    }
  });
})();
