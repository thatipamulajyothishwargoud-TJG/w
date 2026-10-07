/* Shared ambient workspace. Decorative only; all interactions remain in HTML. */
(function () {
  'use strict';
  if (!window.THREE || document.getElementById('workspace-background')) return;
  const host = document.createElement('div');
  host.id = 'workspace-background';
  host.setAttribute('aria-hidden', 'true');
  document.body.prepend(host);
  const motionPreference = matchMedia('(prefers-reduced-motion: reduce)');
  let paused = false;
  try {
    if (localStorage.getItem('hr-night-version') !== '1') {
      localStorage.setItem('hr-background-paused', 'false');
      localStorage.setItem('hr-scene-mode','full');
      localStorage.setItem('hr-scene-palette','aurora');
      localStorage.setItem('hr-night-version','1');
    }
    if (localStorage.getItem('hr-vivid-version') !== '1') {
      localStorage.setItem('hr-background-paused', 'false');
      localStorage.setItem('hr-vivid-version', '1');
    }
    paused = localStorage.getItem('hr-background-paused') === 'true';
  } catch (_) {}
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ alpha: true, antialias: innerWidth > 700, powerPreference: 'low-power' });
  } catch (_) { host.remove(); return; }
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, innerWidth < 700 ? 1 : 1.5));
  renderer.outputEncoding = THREE.sRGBEncoding;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = .95;
  host.append(renderer.domElement);
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, innerWidth / innerHeight, .1, 80);
  camera.position.set(0, 0, 18);
  scene.fog = new THREE.FogExp2(0x0b1a30, .018);
  scene.add(new THREE.AmbientLight(0xb4d9ff, .55));
  const light = new THREE.DirectionalLight(0xffffff, .9);
  light.position.set(3, 7, 9);
  scene.add(light);
  const blueLight = new THREE.PointLight(0x768fff, .7, 35);
  blueLight.position.set(-7, 2, 4);
  scene.add(blueLight);
  const world = new THREE.Group();
  scene.add(world);
  const objects = [];
  const login = !!document.querySelector('.auth-shell');

  function crystal(x, y, z, scale, color, speed) {
    const group = new THREE.Group();
    const geometry = new THREE.IcosahedronGeometry(scale, 0);
    group.add(new THREE.Mesh(geometry, new THREE.MeshStandardMaterial({
      color, metalness: .15, roughness: .28, transparent: true, opacity: login ? .88 : .6,
      flatShading: true, depthWrite: false
    })));
    group.add(new THREE.LineSegments(new THREE.EdgesGeometry(geometry), new THREE.LineBasicMaterial({
      color, transparent: true, opacity: login ? .95 : .75
    })));
    group.position.set(x, y, z);
    world.add(group);
    objects.push({ group, y, speed, phase: objects.length * 1.7 });
    return group;
  }

  const centerpiece = crystal(login ? -4.7 : 6, login ? -.8 : .5, -1, login ? 2.6 : 2.3, 0x80dfca, .17);
  for (let i = 0; i < 3; i++) {
    const ring = new THREE.Mesh(new THREE.TorusGeometry(3.1 + i * .45, .055, 8, 100),
      new THREE.MeshStandardMaterial({ color: [0x4c8ae5,0xffab72,0x57c6b5][i],metalness:.3,roughness:.3,transparent: true, opacity: login ? .85 : .65 }));
    ring.rotation.set(.5 + i * .6, .3 + i * .7, i * .9);
    centerpiece.add(ring);
  }
  crystal(-8, 4, -4, 1.2, 0x91aaff, -.12);
  crystal(8, -4, -3, 1.6, 0x80dfca, -.14);
  crystal(2, 5, -6, .7, 0xadc5ff, .2);
  crystal(-3, -5, -5, .85, 0x80dfca, .12);

  const count = innerWidth < 700 ? 65 : 170;
  const positions = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    positions[i * 3] = (Math.random() - .5) * 34;
    positions[i * 3 + 1] = (Math.random() - .5) * 23;
    positions[i * 3 + 2] = -2 - Math.random() * 12;
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  const particles = new THREE.Points(geometry, new THREE.PointsMaterial({
    color: 0xb4efea, size: .055, transparent: true, opacity: login ? .65 : .38, depthWrite: false
  }));
  world.add(particles);
  // Floating architectural district creates depth across the whole viewport.
  const district = new THREE.Group();
  district.position.set(login ? -4 : 5, -3.5, -5);
  district.rotation.x = .16;
  district.rotation.z = -.08;
  world.add(district);
  const architectural = new THREE.MeshStandardMaterial({color:0xb6a2dc,metalness:.15,roughness:.45,transparent:true,opacity:.68});
  const whiteStone = new THREE.MeshStandardMaterial({color:0xf1e9fa,metalness:.12,roughness:.4,transparent:true,opacity:.82});
  const districtBase = new THREE.Mesh(new THREE.CylinderGeometry(4.2,4.2,.3,56), architectural);
  district.add(districtBase);
  const roofBand = new THREE.Mesh(new THREE.TorusGeometry(4.1,.035,6,72),whiteStone);
  roofBand.rotation.x=Math.PI/2; roofBand.position.y=.2; district.add(roofBand);
  for(let tower=0;tower<5;tower++){
    const angle=tower*Math.PI*.4;
    const x=Math.cos(angle)*2.3,z=Math.sin(angle)*2.3;
    const height=1.3+(tower%3)*.6;
    const building=new THREE.Mesh(new THREE.BoxGeometry(.85,height,.85),architectural);
    building.position.set(x,height/2+.2,z); building.rotation.y=angle; district.add(building);
    for(let floor=0;floor<height/.4;floor++){
      const slab=new THREE.Mesh(new THREE.BoxGeometry(1.02,.08,1.02),whiteStone);
      slab.position.set(x,.3+floor*.4,z);slab.rotation.y=angle;district.add(slab);
    }
    const connection=new THREE.Line(new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(x,.3,z),new THREE.Vector3(0,.3,0)
    ]),new THREE.LineBasicMaterial({color:0xa18dc6,transparent:true,opacity:.4}));district.add(connection);
  }
  const core=new THREE.Mesh(new THREE.SphereGeometry(.7,24,24),whiteStone);
  core.position.y=1.2;district.add(core);
  const grid = new THREE.GridHelper(55, 32, 0x477d8b, 0x223c53);
  grid.position.set(0, -6, -7);
  grid.material.transparent = true;
  grid.material.opacity = .24;
  scene.add(grid);

  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.className = 'background-motion-control';
  const controls = document.createElement('div');
  controls.className = 'scene-controls';
  controls.setAttribute('role','group');
  controls.setAttribute('aria-label','3D experience controls');
  const modeButton = document.createElement('button');
  modeButton.type = 'button'; modeButton.className = 'scene-mode';
  let fullMode = true;
  try { fullMode = localStorage.getItem('hr-scene-mode') !== 'focus'; } catch (_) {}
  function updateMode() {
    document.documentElement.dataset.sceneMode = fullMode ? 'full' : 'focus';
    modeButton.textContent = fullMode ? '◈ Full 3D · ON' : '◈ Focus view';
    modeButton.setAttribute('aria-pressed',String(fullMode));
    modeButton.setAttribute('aria-label','Full 3D mode');
  }
  modeButton.addEventListener('click',()=>{
    fullMode=!fullMode; updateMode();
    try { localStorage.setItem('hr-scene-mode',fullMode?'full':'focus'); } catch (_) {}
  });
  controls.append(modeButton,toggle);
  const palettes={aurora:[0x4285e8,0x4ac4ae,0xffa273],sunrise:[0xef9866,0xffd56f,0xd57f98],ocean:[0x24a9b9,0x6394d7,0x7ad7ca]};
  const paletteButtons=[];
  function setPalette(name) {
    const colors=palettes[name]||palettes.aurora;
    document.documentElement.dataset.palette=name;
    objects.forEach(({group},index)=>group.traverse(object=>{
      if(object.material?.color)object.material.color.setHex(colors[(index+group.children.indexOf(object))%3]);
    }));
    architectural.color.setHex(colors[0]);
    whiteStone.color.setHex(0xedf6ff);
    paletteButtons.forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.palette===name)));
    renderer.render(scene,camera);
    try { localStorage.setItem('hr-scene-palette',name); } catch (_) {}
  }
  Object.keys(palettes).forEach(name=>{
    const button=document.createElement('button');
    button.type='button';button.className='scene-palette';button.dataset.palette=name;
    button.title=name[0].toUpperCase()+name.slice(1)+' colors';
    button.setAttribute('aria-label',button.title);
    button.addEventListener('click',()=>setPalette(name));
    paletteButtons.push(button);controls.append(button);
  });
  document.body.append(controls);
  updateMode();
  let palette='aurora';try { const saved=localStorage.getItem('hr-scene-palette');if(palettes[saved])palette=saved; } catch (_) {}
  setPalette(palette);
  let frame = 0, previous = 0, elapsed = 0, lastRendered = 0, disposed = false;
  let pointerX = 0, pointerY = 0;
  function updateToggle() {
    toggle.textContent = motionPreference.matches ? 'Reduced motion' : (paused ? '▶ Play' : 'Ⅱ Pause');
    toggle.setAttribute('aria-label', paused ? 'Resume moving 3D background' : 'Pause moving 3D background');
    toggle.setAttribute('aria-pressed', String(paused));
    toggle.disabled = motionPreference.matches;
  }
  function render() { renderer.render(scene, camera); }
  function animate(now) {
    frame = 0;
    if (disposed || paused || motionPreference.matches || document.hidden) { previous = 0; return; }
    elapsed += previous ? Math.min((now - previous) / 1000, .1) * (fullMode ? 1.5 : .65) : 0;
    previous = now;
    if (now - lastRendered > 32) {
      objects.forEach(({ group, y, speed, phase }) => {
        group.rotation.y = elapsed * speed;
        group.rotation.x = Math.sin(elapsed * .19 + phase) * .25;
        group.position.y = y + Math.sin(elapsed * .55 + phase) * .5;
      });
      particles.rotation.y = elapsed * .025;
      district.rotation.y = elapsed * .075;
      district.position.y = -3.5 + Math.sin(elapsed * .35) * .35;
      world.rotation.y += (pointerX * .09 - world.rotation.y) * .025;
      world.rotation.x += (pointerY * .035 - world.rotation.x) * .025;
      render();
      lastRendered = now;
    }
    frame = requestAnimationFrame(animate);
  }
  function sync() {
    cancelAnimationFrame(frame); frame = 0; previous = 0;
    updateToggle();
    window.dispatchEvent(new CustomEvent('workspace-motion-change', { detail: { paused: paused || motionPreference.matches } }));
    if (!paused && !motionPreference.matches && !document.hidden && !disposed) frame = requestAnimationFrame(animate);
    else if (!disposed) render();
  }
  function resize() {
    renderer.setSize(innerWidth, innerHeight);
    camera.aspect = innerWidth / innerHeight;
    camera.updateProjectionMatrix();
    centerpiece.position.x = innerWidth < 700 ? 0 : (login ? -4.7 : 6);
    render();
  }
  function pointer(event) { if (event.pointerType !== 'touch') { pointerX = event.clientX / innerWidth * 2 - 1; pointerY = event.clientY / innerHeight * 2 - 1; } }
  toggle.addEventListener('click', () => {
    paused = !paused;
    try { localStorage.setItem('hr-background-paused', String(paused)); } catch (_) {}
    sync();
  });
  window.addEventListener('pointermove', pointer, { passive: true });
  window.addEventListener('resize', resize);
  document.addEventListener('visibilitychange', sync);
  motionPreference.addEventListener('change', sync);
  renderer.domElement.addEventListener('webglcontextlost', event => {
    event.preventDefault(); disposed = true; cancelAnimationFrame(frame); host.remove(); controls.remove();
  });
  window.addEventListener('pagehide', () => {
    disposed = true; cancelAnimationFrame(frame);
    window.removeEventListener('pointermove', pointer);
    window.removeEventListener('resize', resize);
    document.removeEventListener('visibilitychange', sync);
    motionPreference.removeEventListener('change', sync);
    scene.traverse(object => {
      object.geometry?.dispose();
      if (Array.isArray(object.material)) object.material.forEach(material => material.dispose());
      else object.material?.dispose();
    });
    renderer.dispose();
  }, { once: true });
  resize(); sync();
})();
