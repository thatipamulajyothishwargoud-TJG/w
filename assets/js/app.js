/**
 * CloudFen HR Portal — Enhanced App JS
 * Features: Toast notifications, real-time notif polling, upload progress,
 *           AJAX uploads, session timeout, mobile sidebar, animations.
 */
(function() {
  'use strict';

  var _notifPollTimer = null;

  /* ── TOAST SYSTEM ────────────────────────────────── */
  const Toast = (function() {
    let container;
    function getContainer() {
      if (!container) {
        container = document.getElementById('toast-container');
        if (!container) {
          container = document.createElement('div');
          container.id = 'toast-container';
          document.body.appendChild(container);
        }
      }
      return container;
    }

    const icons = { success:'✅', error:'❌', warn:'⚠️', info:'ℹ️' };

    function show(type, title, msg, duration) {
      duration = duration || 5000;
      const c = getContainer();
      const el = document.createElement('div');
      el.className = 'toast toast-' + type;
      el.innerHTML =
        '<span class="toast-icon">' + (icons[type] || '🔔') + '</span>' +
        '<div class="toast-body"><div class="toast-title">' + escHtml(title) + '</div>' +
        (msg ? '<div class="toast-msg">' + escHtml(msg) + '</div>' : '') +
        '</div><span class="toast-close">✕</span>' +
        '<div class="toast-progress" style="width:100%;"></div>';
      c.appendChild(el);

      // Progress bar countdown
      const prog = el.querySelector('.toast-progress');
      const start = Date.now();
      const tick = setInterval(function() {
        const pct = Math.max(0, 100 - (Date.now() - start) / duration * 100);
        prog.style.width = pct + '%';
        if (pct === 0) clearInterval(tick);
      }, 50);

      // Dismiss
      function dismiss() {
        clearInterval(tick);
        el.classList.add('toast-exit');
        setTimeout(function() { el && el.parentNode && el.parentNode.removeChild(el); }, 320);
      }
      el.querySelector('.toast-close').addEventListener('click', dismiss);
      el.addEventListener('click', dismiss);
      setTimeout(dismiss, duration);
      return el;
    }

    return {
      success: function(t, m, d) { return show('success', t, m, d); },
      error:   function(t, m, d) { return show('error',   t, m, d); },
      warn:    function(t, m, d) { return show('warn',    t, m, d); },
      info:    function(t, m, d) { return show('info',    t, m, d); },
    };
  })();

  window.Toast = Toast;

  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  /* ── REAL-TIME NOTIFICATION POLLING (AJAX) ───────── */
  var _lastNotifCount = -1;
  var _notifBells, _notifBadges;

  function updateNotifUI(count) {
    _notifBells  = document.querySelectorAll('.notif-bell');
    _notifBadges = document.querySelectorAll('.notif-bell .count, .nav-badge[data-notif]');

    _notifBells.forEach(function(bell) {
      var cnt = bell.querySelector('.count');
      if (count > 0) {
        if (!cnt) {
          cnt = document.createElement('span');
          cnt.className = 'count';
          bell.appendChild(cnt);
        }
        cnt.textContent = Math.min(count, 99);
        cnt.style.display = 'flex';
        // Add ping dot on new notif
        var ping = bell.querySelector('.notif-ping');
        if (!ping && count > _lastNotifCount && _lastNotifCount >= 0) {
          ping = document.createElement('span');
          ping.className = 'notif-ping';
          bell.appendChild(ping);
          setTimeout(function() { ping && ping.parentNode && ping.parentNode.removeChild(ping); }, 4000);
        }
      } else {
        if (cnt) {
          cnt.textContent = '';
          cnt.style.display = 'none';
        }
      }
    });

    // Sidebar badge
    var navBadge = document.querySelector('.nav-item[href*="notifications"] .nav-badge');
    if (navBadge) {
      if (count > 0) { navBadge.textContent = Math.min(count, 99); navBadge.style.display = ''; }
      else navBadge.style.display = 'none';
    }
  }

  /* ── SSE REAL-TIME NOTIFICATIONS ─────────────────── */
  // Uses Server-Sent Events for instant push; falls back to 30s polling
  // if SSE is unavailable (old browsers or proxy issues).

  function handleNotifData(count, newItems) {
    if (count !== _lastNotifCount) {
      if (newItems && newItems.length && _lastNotifCount >= 0) {
        newItems.forEach(function(n) {
          var icon = n.type && n.type.indexOf('approved') !== -1 ? '✅'
                   : n.type && n.type.indexOf('rejected') !== -1 ? '❌'
                   : n.type && n.type.indexOf('submitted') !== -1 ? '📤'
                   : '🔔';
          Toast.info(icon + ' ' + (n.title || 'New Notification'), n.message || '', 6000);
        });
      } else if (count > _lastNotifCount && _lastNotifCount >= 0 && count > 0) {
        Toast.info('🔔 New Notification', 'You have ' + count + ' unread notification(s).', 5000);
      }
      updateNotifUI(count);
      _lastNotifCount = count;
    }
  }

  function pollNotifications() {
    if (!document.querySelector('.notif-bell')) return;
    fetch('/api/notifications_count.php', { credentials: 'same-origin', headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(data) {
        if (!data) return;
        handleNotifData(parseInt(data.count, 10) || 0, []);
      })
      .catch(function() {});
  }

  /* ── DASHBOARD LIVE UPDATE ────────────────────────── */
  var _docLabels = {
    drivers_license:"Driver's License", i9:'Form I-9', passport:'Passport',
    work_authorization:'Work Auth / EAD', h1b_i797:'H-1B (I-797)',
    social_security:'SSN Card', education:'Education Certs', direct_deposit:'Direct Deposit'
  };

  // ── HR / Super Admin dashboard live update ─────────────────
  function updateAdminDashboard(d) {
    setStatCard('[data-stat="pending_docs"]',       d.pending_docs);
    setStatCard('[data-stat="pending_timesheets"]', d.pending_timesheets);
    setStatCard('[data-stat="overtime_pending"]',   d.overtime_pending);
    setStatCard('[data-stat="active_employees"]',   d.active_employees);

    var dq = document.querySelector('[data-queue="docs"]');
    if (dq) {
      if (!d.doc_queue || !d.doc_queue.length) {
        dq.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text-3);">🎉 No pending documents!</div>';
      } else {
        dq.innerHTML = d.doc_queue.map(function(doc) {
          var label = _docLabels[doc.doc_type] || doc.doc_type;
          var dt = new Date(doc.uploaded_at.replace(' ','T'));
          var dateStr = dt.toLocaleDateString('en-US',{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});
          return '<div style="display:flex;align-items:center;gap:12px;padding:13px 20px;border-bottom:1px solid var(--gray-100);">' +
            '<div style="flex:1;min-width:0;">' +
              '<div style="font-weight:600;font-size:.88rem;color:var(--text-1);">' + escHtml(doc.full_name) + '</div>' +
              '<div style="font-size:.78rem;color:var(--text-3);">' + escHtml(label) + ' &bull; ' + escHtml(dateStr) + '</div>' +
            '</div>' +
            '<a href="/admin/documents.php?doc_id=' + parseInt(doc.id) + '" class="btn btn-primary btn-sm">Review</a>' +
          '</div>';
        }).join('');
      }
    }

    var tq = document.querySelector('[data-queue="timesheets"]');
    if (tq) {
      if (!d.ts_queue || !d.ts_queue.length) {
        tq.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text-3);">🎉 No pending timesheets!</div>';
      } else {
        tq.innerHTML = d.ts_queue.map(function(ts) {
          var wk = new Date(ts.week_start + 'T00:00:00');
          var wkStr = wk.toLocaleDateString('en-US',{month:'short',day:'numeric'});
          var hrs = parseFloat(ts.total_hours || 0).toFixed(1);
          var otBadge = ts.is_overtime ? '<span class="badge badge-pending" style="font-size:.68rem;margin-left:4px;">⚠️ OT</span>' : '';
          return '<div style="display:flex;align-items:center;gap:12px;padding:13px 20px;border-bottom:1px solid var(--gray-100);">' +
            '<div style="flex:1;min-width:0;">' +
              '<div style="font-weight:600;font-size:.88rem;color:var(--text-1);">' + escHtml(ts.full_name) + otBadge + '</div>' +
              '<div style="font-size:.78rem;color:var(--text-3);">Week of ' + escHtml(wkStr) + ' &bull; ' + hrs + ' hrs</div>' +
            '</div>' +
            '<a href="/admin/timesheets.php?ts_id=' + parseInt(ts.id) + '" class="btn btn-primary btn-sm">Review</a>' +
          '</div>';
        }).join('');
      }
    }
  }

  // ── Employee dashboard live update ───────────────────────
  function updateEmployeeDashboard(d) {
    // Stat cards
    setStatCard('[data-stat="docs_approved"]',  d.docs_approved);
    setStatCard('[data-stat="docs_pending"]',   d.docs_pending);
    setStatCard('[data-stat="ts_approved"]',    d.ts_approved);
    setStatCard('[data-stat="unread_notifs"]',  d.unread_notifs);

    // Notifications feed panel
    var feed = document.querySelector('[data-queue="notifications"]');
    if (feed) {
      if (!d.notif_feed || !d.notif_feed.length) {
        feed.innerHTML = '<div style="padding:32px;text-align:center;color:var(--text-3);">No notifications yet.</div>';
      } else {
        feed.innerHTML = d.notif_feed.map(function(n) {
          var isUnread = !parseInt(n.is_read);
          var dt = new Date(n.created_at.replace(' ','T'));
          var timeStr = dt.toLocaleDateString('en-US',{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});
          return '<div style="padding:12px 20px;border-bottom:1px solid var(--surface-3);display:flex;gap:12px;align-items:flex-start;' +
            (isUnread ? 'background:rgba(31,160,192,.06);' : '') + '">' +
            '<div style="flex:1;min-width:0;">' +
              '<div style="font-weight:' + (isUnread ? '700' : '500') + ';font-size:.88rem;color:var(--text-1);">' + escHtml(n.title) + '</div>' +
              '<div style="font-size:.78rem;color:var(--text-3);margin-top:2px;">' + escHtml(n.message) + '</div>' +
              '<div style="font-size:.72rem;color:var(--text-3);margin-top:4px;">' + escHtml(timeStr) + '</div>' +
            '</div>' +
            (isUnread ? '<div style="width:7px;height:7px;border-radius:50%;background:var(--cyan);flex-shrink:0;margin-top:5px;"></div>' : '') +
          '</div>';
        }).join('');
      }

      // Update the "X new" badge in the card header
      var badge = document.querySelector('[data-queue="notifications"]')
                    ?.closest('.card')
                    ?.querySelector('.card-header .badge');
      if (badge) {
        if (d.unread_notifs > 0) {
          badge.textContent = d.unread_notifs + ' new';
          badge.style.display = '';
        } else {
          badge.style.display = 'none';
        }
      }
    }

    // This week timesheet status badge
    var tsHeader = document.querySelector('[data-ts-header] .badge');
    if (tsHeader && d.current_ts) {
      var s = d.current_ts.status;
      var label = s.charAt(0).toUpperCase() + s.slice(1);
      tsHeader.className = 'badge badge-' + s;
      tsHeader.textContent = label;
    }
  }

  function setStatCard(selector, value) {
    var el = document.querySelector(selector + ' .stat-value');
    if (!el) return;
    var prev = parseInt(el.textContent, 10);
    if (prev !== value) {
      el.textContent = value;
      // Flash animation on change
      el.style.transition = 'color .3s';
      el.style.color = value > prev ? 'var(--rose)' : 'var(--cyan)';
      setTimeout(function() { el.style.color = ''; }, 1500);
    }
  }

  /* ── SSE CONNECTION ────────────────────────────────── */
  function startSSENotifications() {
    if (!document.querySelector('.notif-bell')) return; // not logged in
    if (!window.EventSource) { startPollingFallback(); return; }

    var sse = new EventSource('/api/notifications_stream.php');
    var reconnectDelay = 3000;

    sse.addEventListener('connected', function() {
      reconnectDelay = 3000;
    });

    sse.addEventListener('notification', function(e) {
      try {
        var d = JSON.parse(e.data);
        handleNotifData(parseInt(d.count, 10) || 0, d.new || []);
      } catch(ex) {}
    });

    // Live dashboard update — role-aware
    sse.addEventListener('dashboard', function(e) {
      try {
        var d = JSON.parse(e.data);
        if (d.role === 'admin')    updateAdminDashboard(d);
        if (d.role === 'employee') updateEmployeeDashboard(d);
      } catch(ex) {}
    });

    sse.addEventListener('reconnect', function() {
      sse.close();
      setTimeout(startSSENotifications, 1000);
    });

    sse.addEventListener('auth', function() {
      sse.close();
    });

    sse.onerror = function() {
      sse.close();
      reconnectDelay = Math.min(reconnectDelay * 2, 60000);
      setTimeout(startSSENotifications, reconnectDelay);
    };
  }

  function startPollingFallback() {
    if (_notifPollTimer) return;
    pollNotifications();
    _notifPollTimer = setInterval(pollNotifications, 5000);
  }

  document.addEventListener('visibilitychange', function() {
    if (!document.hidden) pollNotifications();
  });

  // Kick off: SSE is preferred; polling is a fallback only (startSSENotifications
  // calls startPollingFallback internally when EventSource is unavailable).
  // Do NOT call pollNotifications() here — that would fire alongside SSE and
  // produce duplicate toasts on every page load.
  startSSENotifications();

  /* ── UPLOAD PROGRESS (XHR with progress events) ───── */
  function attachUploadProgress(form) {
    if (!form) return;
    // Guard: if this form already has an upload listener attached (e.g. by
    // inline <script> in the page), skip — attaching twice causes every
    // submit event to fire two XHR requests and show two toast notifications.
    if (form.dataset.uploadBound === '1') return;
    form.dataset.uploadBound = '1';
    var input = form.querySelector('input[type=file]');
    var btn = form.querySelector('[type=submit]');
    var progressWrap = form.querySelector('.upload-progress-wrap');
    var progressFill = form.querySelector('.upload-progress-fill');
    var progressLabel = form.querySelector('.upload-progress-pct');
    var uploadZone = form.querySelector('.upload-zone');

    if (!input) return;

    form.addEventListener('submit', function(e) {
      if (!input.files || !input.files.length) return;
      e.preventDefault();

      var fd = new FormData(form);
      var xhr = new XMLHttpRequest();

      // Show progress UI
      if (progressWrap) progressWrap.classList.add('visible');
      if (uploadZone) uploadZone.classList.add('uploading');
      if (btn) { btn.disabled = true; btn.classList.add('btn-loading'); }

      xhr.upload.addEventListener('progress', function(ev) {
        if (ev.lengthComputable && progressFill) {
          var pct = Math.round(ev.loaded / ev.total * 100);
          progressFill.style.width = pct + '%';
          if (progressLabel) progressLabel.textContent = pct + '%';
        }
      });

      xhr.addEventListener('load', function() {
        if (progressFill) { progressFill.style.width = '100%'; progressFill.classList.add('complete'); }
        if (btn) { btn.disabled = false; btn.classList.remove('btn-loading'); }
        if (uploadZone) uploadZone.classList.remove('uploading');

        try {
          var resp = JSON.parse(xhr.responseText);
          if (resp.success) {
            Toast.success('Upload Successful', resp.message || 'Document submitted for review.');
            setTimeout(function() { window.location.reload(); }, 1500);
          } else {
            Toast.error('Upload Failed', resp.message || 'Please try again.');
            if (progressWrap) progressWrap.classList.remove('visible');
          }
        } catch(ex) {
          // Non-JSON response — page reload (traditional form)
          window.location.reload();
        }
      });

      xhr.addEventListener('error', function() {
        Toast.error('Upload Failed', 'Network error. Please check your connection.');
        if (btn) { btn.disabled = false; btn.classList.remove('btn-loading'); }
        if (progressWrap) progressWrap.classList.remove('visible');
        if (uploadZone) uploadZone.classList.remove('uploading');
      });

      xhr.open('POST', form.action || window.location.href);
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
      xhr.send(fd);
    });
  }

  // Attach to all upload forms
  document.querySelectorAll('form[data-upload]').forEach(attachUploadProgress);

  /* ── DRAG & DROP UPLOAD ZONE ─────────────────────── */
  document.querySelectorAll('.upload-zone').forEach(function(zone) {
    var input = zone.querySelector('input[type=file]');
    var nameEl = zone.querySelector('.selected-filename');

    zone.addEventListener('click', function(e) {
      // Guard: if the click came from the file input itself, a button, or any
      // anchor inside the zone, do nothing — the browser already handled it.
      // Without this the click bubbles up to the zone listener, which then
      // calls input.click() a second time and opens the file-picker twice.
      if (e.target === input) return;
      if (e.target.closest('a, button, input')) return;
      if (zone.classList.contains('uploading')) return;
      if (input) input.click();
    });
    zone.addEventListener('dragover', function(e) { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', function() { zone.classList.remove('drag-over'); });
    zone.addEventListener('drop', function(e) {
      e.preventDefault();
      zone.classList.remove('drag-over');
      if (input && e.dataTransfer.files.length) {
        // Transfer files to input
        var dt = new DataTransfer();
        dt.items.add(e.dataTransfer.files[0]);
        input.files = dt.files;
        if (nameEl) nameEl.textContent = e.dataTransfer.files[0].name;
        zone.querySelector('h4') && (zone.querySelector('h4').textContent = '✅ ' + e.dataTransfer.files[0].name);
      }
    });

    if (input) {
      input.addEventListener('change', function() {
        if (input.files.length && nameEl) {
          nameEl.textContent = input.files[0].name;
          var h4 = zone.querySelector('h4');
          if (h4) h4.textContent = '✅ ' + input.files[0].name;
        }
      });
    }
  });

  /* ── FORM SUBMIT LOADING STATE ─────────────────────── */
  document.querySelectorAll('form[data-loading]').forEach(function(form) {
    form.addEventListener('submit', function() {
      var btn = form.querySelector('[type=submit]');
      if (btn) { btn.disabled = true; btn.classList.add('btn-loading'); }
    });
  });

  /* ── AUTO-DISMISS PHP FLASH ALERTS ─────────────────── */
  document.querySelectorAll('.alert[data-auto-dismiss]').forEach(function(a) {
    var delay = parseInt(a.dataset.autoDismiss, 10) || 5000;
    setTimeout(function() {
      a.style.transition = 'opacity .4s';
      a.style.opacity = '0';
      setTimeout(function() { a && a.parentNode && a.parentNode.removeChild(a); }, 420);
    }, delay);
  });

  /* ── MOBILE SIDEBAR TOGGLE ───────────────────────── */
  var toggleBtn = document.getElementById('menu-toggle');
  var sidebar = document.getElementById('sidebar');
  var sidebarClose = document.getElementById('sidebar-close');
  var sidebarBackdrop = document.getElementById('sidebar-backdrop');

  function openSidebar() {
    sidebar.classList.add('open');
    if (sidebarBackdrop) sidebarBackdrop.classList.add('open');
  }
  function closeSidebar() {
    sidebar.classList.remove('open');
    if (sidebarBackdrop) sidebarBackdrop.classList.remove('open');
  }

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', function() {
      if (sidebar.classList.contains('open')) closeSidebar(); else openSidebar();
    });
    if (sidebarClose) sidebarClose.addEventListener('click', closeSidebar);
    if (sidebarBackdrop) sidebarBackdrop.addEventListener('click', closeSidebar);
    // Close on outside click
    document.addEventListener('click', function(e) {
      if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && e.target !== toggleBtn && !toggleBtn.contains(e.target)) {
        closeSidebar();
      }
    });
    // Close whenever a nav link is tapped (mobile — sidebar sits on top of content)
    sidebar.querySelectorAll('.nav-item').forEach(function(link) {
      link.addEventListener('click', closeSidebar);
    });
  }

  /* ── SESSION TIMEOUT WARNING ────────────────────── */
  var sessionLifetime = window.SESSION_LIFETIME || 1800; // seconds
  var warnBefore = 120; // warn 2 min before expiry
  var warnTime = (sessionLifetime - warnBefore) * 1000;
  var sessionWarn = document.getElementById('session-warn');

  if (sessionWarn) {
    setTimeout(function() {
      sessionWarn.style.display = 'flex';
    }, warnTime);
  }

  /* ── TIMESHEET TOTAL CALCULATOR ─────────────────── */
  var tsInputs = document.querySelectorAll('.ts-day input[type=number]');
  var totalEl = document.querySelector('.ts-total-num');

  if (tsInputs.length && totalEl) {
    function calcTotal() {
      var total = 0;
      tsInputs.forEach(function(inp) { total += parseFloat(inp.value) || 0; });
      total = Math.round(total * 10) / 10;
      totalEl.textContent = total.toFixed(1);
      if (total > 40) {
        totalEl.classList.add('ts-overtime');
        totalEl.title = 'Overtime!';
      } else {
        totalEl.classList.remove('ts-overtime');
        totalEl.title = '';
      }
    }
    tsInputs.forEach(function(inp) { inp.addEventListener('input', calcTotal); });
    calcTotal();
  }

  /* ── CONFIRM DIALOGS (data-confirm) ─────────────── */
  document.querySelectorAll('[data-confirm]').forEach(function(el) {
    el.addEventListener('click', function(e) {
      if (!confirm(el.dataset.confirm || 'Are you sure?')) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    });
  });

  /* ── MODAL HELPERS ───────────────────────────────── */
  document.querySelectorAll('[data-modal-open]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var m = document.getElementById(btn.dataset.modalOpen);
      if (m) m.classList.remove('hidden');
    });
  });
  document.querySelectorAll('[data-modal-close]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var m = btn.closest('.modal-overlay');
      if (m) m.classList.add('hidden');
    });
  });
  document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) overlay.classList.add('hidden');
    });
  });

  /* ── AUTO FLASH TOAST FROM PHP META ─────────────── */
  var flashMeta = document.querySelector('meta[name="flash-toast"]');
  if (flashMeta) {
    var fType  = flashMeta.dataset.type  || 'info';
    var fTitle = flashMeta.dataset.title || 'Notice';
    var fMsg   = flashMeta.dataset.msg   || '';
    setTimeout(function() { Toast[fType] && Toast[fType](fTitle, fMsg); }, 300);
  }

  /* ── TIMESHEETS NAV GROUP TOGGLE ─────────────────── */
  var tsToggle = document.getElementById('ts-group-toggle');
  if (tsToggle) {
    var navGroup = tsToggle.closest('.nav-group') || tsToggle.parentElement;
    // Open on load if active page is a timesheet sub-page
    if (tsToggle.classList.contains('open')) {
      navGroup.classList.add('open');
    }
    tsToggle.addEventListener('click', function() {
      navGroup.classList.toggle('open');
      tsToggle.classList.toggle('open');
    });
  }

  /* ── PASSWORD FIELD SHOW/HIDE TOGGLE ─────────────── */
  var EYE_OPEN   = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
  var EYE_CLOSED = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20.3 20.3 0 0 1 4.22-5.94M9.9 4.24A9.13 9.13 0 0 1 12 4c7 0 11 8 11 8a20.4 20.4 0 0 1-2.16 3.19M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

  document.querySelectorAll('input[type="password"]').forEach(function(input) {
    if (input.closest('.pw-field-wrap')) return;

    var wrap = document.createElement('div');
    wrap.className = 'pw-field-wrap';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pw-toggle-btn';
    btn.setAttribute('aria-label', 'Show password');
    btn.innerHTML = EYE_OPEN;
    wrap.appendChild(btn);

    btn.addEventListener('click', function() {
      var hidden = input.type === 'password';
      input.type = hidden ? 'text' : 'password';
      btn.innerHTML = hidden ? EYE_CLOSED : EYE_OPEN;
      btn.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
    });
  });

  console.log('%cCloudFen HR Portal v2 — Enhanced', 'color:#2b8fd4;font-weight:700;font-size:14px;');
})();
