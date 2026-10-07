(function () {
  'use strict';

  const shell = document.querySelector('.app-shell');
  if (!shell || !window.matchMedia || !window.matchMedia('(pointer: fine)').matches) return;

  const cursor = document.createElement('div');
  cursor.className = 'portal-cursor';
  cursor.setAttribute('aria-hidden', 'true');
  cursor.innerHTML = '<span class="portal-cursor-arrow"><svg viewBox="0 0 64 72" aria-hidden="true"><path class="cursor-edge" d="M37 66 25 44 11 58 6 5 54 33 36 38 49 58Z"></path><path class="cursor-face" d="M7 5 54 33 35 37 47 57 39 62 27 41 13 54Z"></path></svg></span>';

  const light = document.createElement('div');
  light.className = 'portal-cursor-light';
  light.setAttribute('aria-hidden', 'true');
  const trails = Array.from({ length: 3 }, function (_, index) {
    const node = document.createElement('i');
    node.className = 'portal-cursor-trail trail-' + (index + 1);
    node.setAttribute('aria-hidden', 'true');
    return node;
  });
  document.body.append(light, ...trails, cursor);
  shell.classList.add('portal-cursor-active');

  let x = window.innerWidth / 2;
  let y = window.innerHeight / 2;
  let targetX = x;
  let targetY = y;
  let lastX = x;
  let lastY = y;
  let frame = 0;

  function interactiveTarget(element) {
    return element && element.closest ? element.closest('a,button,input,select,textarea,[role="button"],[data-command]') : null;
  }

  function updatePointer(event) {
    if (!event || typeof event.clientX !== 'number') return;
    const maxX = Math.max(0, window.innerWidth - 1);
    const maxY = Math.max(0, window.innerHeight - 1);
    let nextX = Math.max(0, Math.min(maxX, event.clientX));
    let nextY = Math.max(0, Math.min(maxY, event.clientY));
    const interactive = interactiveTarget(event.target);
    cursor.classList.toggle('is-hover', !!interactive);

    // A small magnetic pull makes buttons and links feel physical without
    // preventing the pointer from reaching any edge of the viewport.
    if (interactive) {
      const rect = interactive.getBoundingClientRect();
      nextX += (rect.left + rect.width / 2 - nextX) * .08;
      nextY += (rect.top + rect.height / 2 - nextY) * .08;
    }
    targetX = nextX;
    targetY = nextY;
    cursor.classList.add('is-visible');
    light.classList.add('is-visible');
    trails.forEach(function (node) { node.classList.add('is-visible'); });
    shell.style.setProperty('--pointer-x', ((nextX / Math.max(1, window.innerWidth)) * 100).toFixed(2) + '%');
    shell.style.setProperty('--pointer-y', ((nextY / Math.max(1, window.innerHeight)) * 100).toFixed(2) + '%');
  }

  function hidePointer() {
    cursor.classList.remove('is-visible');
    light.classList.remove('is-visible');
    trails.forEach(function (node) { node.classList.remove('is-visible'); });
  }

  function render() {
    x += (targetX - x) * .34;
    y += (targetY - y) * .34;
    const vx = Math.max(-14, Math.min(14, x - lastX));
    const vy = Math.max(-14, Math.min(14, y - lastY));
    lastX = x;
    lastY = y;
    cursor.style.transform = 'translate3d(' + x + 'px,' + y + 'px,0) translate(-50%,-50%) rotateX(' + (-vy * .72) + 'deg) rotateY(' + (vx * .72) + 'deg)';
    light.style.transform = 'translate3d(' + x + 'px,' + y + 'px,0) translate(-50%,-50%)';
    trails.forEach(function (node, index) {
      const strength = .18 - index * .035;
      const tx = x - (targetX - x) * (index + 1) * strength;
      const ty = y - (targetY - y) * (index + 1) * strength;
      node.style.transform = 'translate3d(' + tx + 'px,' + ty + 'px,0) translate(-50%,-50%)';
    });
    frame = requestAnimationFrame(render);
  }

  document.addEventListener('pointermove', updatePointer, { passive: true, capture: true });
  document.addEventListener('mousemove', updatePointer, { passive: true, capture: true });
  document.addEventListener('pointerdown', function () { cursor.classList.add('is-press'); }, { passive: true, capture: true });
  document.addEventListener('pointerup', function () { cursor.classList.remove('is-press'); }, { passive: true, capture: true });
  document.addEventListener('pointerenter', updatePointer, { passive: true, capture: true });
  window.addEventListener('blur', hidePointer, { passive: true });
  document.addEventListener('visibilitychange', function () { if (document.hidden) hidePointer(); }, { passive: true });
  window.addEventListener('resize', function () {
    targetX = Math.max(0, Math.min(window.innerWidth - 1, targetX));
    targetY = Math.max(0, Math.min(window.innerHeight - 1, targetY));
  }, { passive: true });
  frame = requestAnimationFrame(render);

  window.addEventListener('pagehide', function () {
    cancelAnimationFrame(frame);
    cursor.remove();
    light.remove();
    trails.forEach(function (node) { node.remove(); });
    shell.classList.remove('portal-cursor-active');
  }, { once: true });
})();
