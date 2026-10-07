# Design System: HR Portal Template — immersive adaptation

## 1. Visual Theme & Atmosphere
The user's priority is a complete 3D HR workspace with moving backgrounds, physical depth and populated fictional profiles. Use a balanced software layout (density 5), asymmetric workspace/insight split (variance 6), and continuous ambient 3D motion (motion 7). Keep editable HR content in accessible HTML above the WebGL environment. This document describes the current implementation, not a claimed extraction of the inaccessible Stitch screens.

Reference project: HR Portal Template, `10883933005634230699`. Requested screens: `7bfbe9651ad54afbb92450e68ecf6f2b`, `32316a499f154eeeba36f2546085f0b0`, `6d03c4bae43a4ed0a4b4735f14bc4a5b`, `475ab0df369b402ca6da1f9355b4cf22`, `e44754c6dbf641be884ad88524b8fe8b`, `e7559cf6505b4f8e98a42080e74e106e`. Hosted image/HTML URLs or a usable project connection are needed for exact reference reconciliation. Do not invent source artwork, downloaded assets, colors, or screen contents.

## 2. Color Palette & Roles
- Cloud Canvas (#F5F4F9): environment background.
- Frosted White (#FFFFFF, 88–94% opacity): content panels and forms.
- Plum Ink (#40344C): headings and important values.
- Slate Violet (#726C86): body text and secondary information.
- Whisper Border (#E8E5F0): structural edges and dividers.
- Muted Orchid (#7858D6): one interaction accent, no neon glows.
The current orchid accent preserves the user's active redesign pending actual reference access. Exact Stitch tokens supersede provisional taste guidance once verified.

## 3. Typography Rules
Use the existing DM Sans/DM Mono assets until reference fonts are verified, keeping the working application dependency structure. Headlines 24–32px, tightly tracked; body 14px minimum; metadata may be smaller but never carries the only interactive label. Use clear sans-serif text and monospace for employee IDs/timestamps.

## 4. Component Stylings
Glass panels use 18px radius, a light top edge, tinted soft shadow, and a visible lower depth edge. Cards gently tilt up to 3 degrees with fine pointers; disable tilt on forms, active typing, touch and reduced-motion. Buttons have tactile 1px active translation. Inputs retain labels and visible focus. Profile dialogs use native keyboard/focus behavior. Fictional demo records remain labeled.

## 5. Layout Principles
Desktop uses an asymmetric overview with a wider main area and narrower right rail. The hero places text and the procedural 3D campus in separate spatial zones. Below 768px, charts/rails/directories collapse to one column. No horizontal overflow. Use CSS Grid, maximum content width 1650px and generous but efficient spacing. Interactive touch controls use at least 44px targets.

## 6. Motion & Interaction
Use a real Three.js background with particles, faceted solids, orbiting rings and a floating architectural campus. Render at a capped 30fps with low-power preference, limited pixel ratio, reduced mobile detail, hidden-tab pause and resource disposal. The persistent pause control governs both background and campus. Respect system reduced-motion preference. Animate transform/opacity rather than layout properties; accessible HTML always remains available after WebGL failure.

## 7. Anti-Patterns (Banned)
No unverified claims of template matching. No unlabeled fictional data, fabricated compliance documents or production sample accounts. No text/graphic overlap that harms reading, neon glow, saturated gradient text, custom cursors, generic marketing filler, unreadable low-contrast labels or empty controls. Never replace working backend authorization with frontend visibility.

## User-directed bright color update
The user explicitly requested bright combinations and Full 3D enabled. The vivid.css skin therefore supersedes the provisional single-accent palette guidance: Royal Blue (#365DE5), Turquoise (#45C4AF), Coral (#FF936D) and Gold (#FFC45A) distinguish interactive/data surfaces while dark ink maintains readable contrast. Aurora/Sunrise/Ocean presets and Full 3D/focus/pause controls are functional. Stitch matching is still unverified.


## Current video-reference direction
The newer user-supplied video supersedes the earlier provisional/night color direction. Current tokens: Ice Canvas #EAF4F9; White Frame #FFFFFF; Reflection Blue #92C7D8; Deep Ink #173549; Action Blue #1682BC. Use generous white frames, rounded corners, a clipped lower-left corner, translucent pill navigation, local glass/chrome sculpture geometry, ripple rings, and restrained section/drawer transitions. Keep business inputs in ordinary HTML and preserve role/owner-scoped server operations. The video's original model assets were not supplied, so the geometry is recreated rather than copied. Source visual samples remain outside the deliverable archive.