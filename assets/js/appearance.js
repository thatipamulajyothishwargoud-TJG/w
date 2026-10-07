(function () {
  'use strict';
  // The portal is intentionally light-only. Keep the value stable for older
  // sessions that may still have a dark or night preference stored.
  document.documentElement.dataset.appearance = 'light';
  try { localStorage.setItem('hr-appearance', 'light'); } catch (_) {}
})();
