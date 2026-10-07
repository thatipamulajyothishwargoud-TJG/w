/* ── LOGIN PAGE 3D MODEL ──────────────────────────────────────
   Decorative wireframe icosahedron + particle shell, rendered inside
   the branding panel. Colors are read from the app's CSS variables
   (--cyan / --cyan-bright) so it always matches the current theme.
   Skipped on mobile — the branding panel itself is hidden there. */
(function () {
  var container = document.getElementById('login-3d');
  if (!container || typeof THREE === 'undefined') return;
  if (window.innerWidth <= 1024) return; // panel is display:none below this breakpoint

  var root = getComputedStyle(document.documentElement);
  var cyan       = (root.getPropertyValue('--cyan') || '#1fa0c0').trim();
  var cyanBright = (root.getPropertyValue('--cyan-bright') || '#28c0e0').trim();

  var width  = container.clientWidth  || 460;
  var height = container.clientHeight || 460;

  var scene, camera, renderer, group, particles;
  try {
    scene  = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(42, width / height, 0.1, 100);
    camera.position.z = 6.4;

    renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    if (!renderer) return;
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setSize(width, height);
    container.appendChild(renderer.domElement);
  } catch (e) {
    return; // WebGL unavailable — fail silently, page still works fine without it
  }

  group = new THREE.Group();
  scene.add(group);

  var geo = new THREE.IcosahedronGeometry(2, 1);

  var wireMesh = new THREE.Mesh(
    geo,
    new THREE.MeshBasicMaterial({ color: cyanBright, wireframe: true, transparent: true, opacity: 0.85 })
  );
  group.add(wireMesh);

  var solidMesh = new THREE.Mesh(
    geo,
    new THREE.MeshBasicMaterial({ color: cyan, transparent: true, opacity: 0.05 })
  );
  solidMesh.scale.setScalar(0.985);
  group.add(solidMesh);

  /* Orbiting particle shell — a loose ring of points around the core shape */
  var particleCount = 130;
  var positions = new Float32Array(particleCount * 3);
  for (var i = 0; i < particleCount; i++) {
    var r     = 3.05 + Math.random() * 0.55;
    var theta = Math.random() * Math.PI * 2;
    var phi   = Math.acos((Math.random() * 2) - 1);
    positions[i * 3]     = r * Math.sin(phi) * Math.cos(theta);
    positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
    positions[i * 3 + 2] = r * Math.cos(phi);
  }
  var particleGeo = new THREE.BufferGeometry();
  particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  particles = new THREE.Points(
    particleGeo,
    new THREE.PointsMaterial({ color: cyanBright, size: 0.035, transparent: true, opacity: 0.55 })
  );
  group.add(particles);

  /* Subtle mouse-parallax tilt, tracked across the whole branding panel */
  var targetTiltX = 0, targetTiltY = 0, curTiltX = 0, curTiltY = 0;
  var panel = container.closest('.auth-panel');
  if (panel) {
    panel.addEventListener('mousemove', function (e) {
      var rect = panel.getBoundingClientRect();
      var nx = ((e.clientX - rect.left) / rect.width)  * 2 - 1;
      var ny = ((e.clientY - rect.top)  / rect.height) * 2 - 1;
      targetTiltY = nx * 0.35;
      targetTiltX = ny * 0.22;
    });
  }

  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var autoX = 0, autoY = 0;

  function animate() {
    requestAnimationFrame(animate);
    if (!reduceMotion) {
      autoY += 0.0035;
      autoX += 0.0009;
      particles.rotation.y -= 0.0012;
    }
    curTiltX += (targetTiltX - curTiltX) * 0.05;
    curTiltY += (targetTiltY - curTiltY) * 0.05;
    group.rotation.x = autoX + curTiltX;
    group.rotation.y = autoY + curTiltY;
    renderer.render(scene, camera);
  }
  animate();

  window.addEventListener('resize', function () {
    if (window.innerWidth <= 1024) return;
    var w = container.clientWidth, h = container.clientHeight;
    if (!w || !h) return;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
  });
})();
