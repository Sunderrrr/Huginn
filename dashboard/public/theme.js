// Apply the saved theme before first paint (avoids a flash of dark).
// Lives as an external file so a strict CSP (script-src 'self') allows it.
(function () {
  try {
    document.documentElement.dataset.theme =
      localStorage.getItem("huginn.theme") || "dark";
  } catch (e) {
    document.documentElement.dataset.theme = "dark";
  }
})();
