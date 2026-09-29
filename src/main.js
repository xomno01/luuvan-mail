import confetti from 'canvas-confetti';
import DOMPurify from 'dompurify';
import { defaultEmails } from './data/mockEmails.js';
import { domainsData } from './data/domains.js';
import { initAuth, loginUser, registerUser, getSession, clearSession, fetchCloudEmails, getAuthToken, switchActiveDomain } from './services/auth.js';

// State
let emails = defaultEmails;
let currentUser = null;
let currentFolder = 'inbox';
let currentFilter = 'all';
let searchQuery = '';
let activeEmailId = null;

// Selected registration domain data (Default: luuvan.online)
let regChosenDomain = 'luuvan.online';
let regChosenMascotName = 'Mèo Luna (Tri thức & Dev)';
let regChosenMascotAvatar = '/assets/mascot_luuvan.webp';

function getStorageKey(email) {
  return `pastelmail_emails_${email ? email.toLowerCase().replace(/[^a-z0-9]/g, '_') : 'guest'}`;
}

function saveEmails() {
  if (currentUser?.email) {
    localStorage.setItem(getStorageKey(currentUser.email), JSON.stringify(emails));
  }
}

// Escape plain text for HTML interpolation
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Enterprise DOMPurify Sanitizer against XSS (OWASP Grade)
function sanitizeEmailHtml(dirty) {
  if (!dirty) return '';
  return DOMPurify.sanitize(dirty, {
    ADD_ATTR: ['target', 'rel'],
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover']
  });
}

// Toast
function showToast(message) {
  const toast = document.getElementById('toast-notice');
  const text = document.getElementById('toast-text');
  text.textContent = message;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 3200);
}

// Apply Domain Theme
function applyTheme(domainKey) {
  const data = domainsData[domainKey] || domainsData['luuvan.online'] || domainsData['aadidass.tokyo'];
  const root = document.documentElement;

  root.style.setProperty('--theme-primary', data.colors.primary);
  root.style.setProperty('--theme-primary-light', data.colors.primaryLight);
  root.style.setProperty('--theme-accent', data.colors.accent);
  root.style.setProperty('--theme-glow', data.colors.glow);
  root.style.setProperty('--theme-bg-tint', data.colors.accentBg);

  // Topbar
  document.getElementById('app-logo').src = data.mascot.avatar;
  document.getElementById('active-domain-badge').textContent = domainKey;

  // Account
  document.getElementById('account-avatar').src = currentUser?.avatar || data.mascot.avatar;
  document.getElementById('account-display-name').textContent = currentUser?.email || `user@${domainKey}`;
  document.getElementById('account-mascot-label').textContent = currentUser?.mascot || data.mascot.name;

  // Sidebar Mascot Card
  document.getElementById('sidebar-mascot-img').src = data.mascot.avatar;
  document.getElementById('sidebar-mascot-name').textContent = data.mascot.name;
  document.getElementById('sidebar-mascot-quote').textContent = data.mascot.greeting;

  // Compose from email
  document.getElementById('compose-from-email').textContent = currentUser?.email || `user@${domainKey}`;
}

// Web Audio API Sparkling Chime Synthesizer
let audioCtx = null;
function playCuteNotificationChime() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    if (!audioCtx) {
      audioCtx = new AudioCtx();
    }
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }

    const now = audioCtx.currentTime;
    // Sparkling bell arpeggio: C6 (1046.5Hz) -> E6 (1318.5Hz) -> G6 (1567.98Hz) -> C7 (2093Hz)
    const chimeNotes = [
      { freq: 1046.5, time: 0.00, dur: 0.35, gain: 0.16 },
      { freq: 1318.5, time: 0.09, dur: 0.40, gain: 0.19 },
      { freq: 1567.98, time: 0.18, dur: 0.45, gain: 0.22 },
      { freq: 2093.00, time: 0.27, dur: 0.65, gain: 0.25 }
    ];

    chimeNotes.forEach(n => {
      const osc = audioCtx.createOscillator();
      const gainNode = audioCtx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(n.freq, now + n.time);

      gainNode.gain.setValueAtTime(0.0001, now + n.time);
      gainNode.gain.exponentialRampToValueAtTime(n.gain, now + n.time + 0.02);
      gainNode.gain.exponentialRampToValueAtTime(0.0001, now + n.time + n.dur);

      osc.connect(gainNode);
      gainNode.connect(audioCtx.destination);

      osc.start(now + n.time);
      osc.stop(now + n.time + n.dur);
    });
  } catch (err) {
    console.warn('Audio chime playback note:', err);
  }
}

// Cute Notification Popup Modal
let pendingPopupMail = null;

function showCuteNewMailModal(mail) {
  pendingPopupMail = mail;
  const overlay = document.getElementById('new-mail-modal-overlay');
  const mascotImg = document.getElementById('popup-mascot-img');
  const mascotBadge = document.getElementById('popup-mascot-badge');
  const senderName = document.getElementById('popup-sender-name');
  const senderEmail = document.getElementById('popup-sender-email');
  const subjectEl = document.getElementById('popup-subject');
  const snippetEl = document.getElementById('popup-snippet');

  const domainData = domainsData[mail.domain] || domainsData[currentUser?.domain] || domainsData['luuvan.online'];

  if (mascotImg) mascotImg.src = domainData.mascot.avatar;
  if (mascotBadge) mascotBadge.textContent = `${mail.domain || domainData.domain} 💌`;
  if (senderName) senderName.textContent = mail.senderName || 'Người gửi';
  if (senderEmail) senderEmail.textContent = mail.senderEmail ? `<${mail.senderEmail}>` : '';
  if (subjectEl) subjectEl.textContent = mail.subject || '(Không có tiêu đề)';
  if (snippetEl) snippetEl.textContent = mail.snippet || 'Nhấp vào để đọc toàn bộ nội dung thư...';

  if (overlay) overlay.classList.add('open');

  // Play sparkling chime sound
  playCuteNotificationChime();

  // Burst cute pastel confetti
  try {
    confetti({
      particleCount: 75,
      spread: 85,
      origin: { y: 0.38 },
      colors: ['#f472b6', '#c084fc', '#38bdf8', '#fbbf24', '#34d399']
    });
  } catch (err) {
    // Ignore if not supported
  }
}

function initNewMailPopup() {
  const overlay = document.getElementById('new-mail-modal-overlay');
  const closeBtn = document.getElementById('popup-close-x');
  const dismissBtn = document.getElementById('btn-popup-dismiss');
  const viewBtn = document.getElementById('btn-popup-view');

  function closePopup() {
    if (overlay) overlay.classList.remove('open');
    pendingPopupMail = null;
  }

  if (closeBtn) closeBtn.addEventListener('click', closePopup);
  if (dismissBtn) dismissBtn.addEventListener('click', closePopup);
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closePopup();
    });
  }

  if (viewBtn) {
    viewBtn.addEventListener('click', () => {
      if (!pendingPopupMail) {
        closePopup();
        return;
      }
      const mailToOpen = pendingPopupMail;
      closePopup();

      // If email belongs to another domain in the ecosystem, switch to that domain first
      if (currentUser && mailToOpen.domain && mailToOpen.domain !== currentUser.domain) {
        const updated = switchActiveDomain(mailToOpen.domain);
        if (updated) {
          currentUser = updated;
          emails = JSON.parse(localStorage.getItem(getStorageKey(currentUser.email))) || defaultEmails;
          applyTheme(currentUser.domain);
        }
      }

      currentFolder = 'inbox';
      currentFilter = 'all';
      renderMailList();
      openReaderView(mailToOpen.id);
    });
  }
}

// Inbound Poller & Seen Tracker
const seenMailIds = new Set();
let isInitialSyncDone = false;
let pollingIntervalTimer = null;

// Sync Cloud Emails with Real-time Inbound Detection
async function syncCloudData(notifyNew = false) {
  if (!currentUser?.email) return;
  try {
    const cloudMails = await fetchCloudEmails(currentUser.email);
    if (!cloudMails || cloudMails.length === 0) return;

    // Seed seenMailIds on first sync so existing emails don't trigger false alerts
    if (!isInitialSyncDone) {
      emails.forEach(m => seenMailIds.add(m.id));
      cloudMails.forEach(cm => seenMailIds.add(cm.id));
      isInitialSyncDone = true;
    }

    const existingIds = new Set(emails.map(m => m.id));
    let newlyArrivedInboxMails = [];
    let addedCount = 0;

    for (const cm of cloudMails) {
      const isBrandNew = !existingIds.has(cm.id) && !seenMailIds.has(cm.id);
      if (!existingIds.has(cm.id)) {
        emails.unshift(cm);
        existingIds.add(cm.id);
        addedCount++;
      }

      if (isBrandNew) {
        seenMailIds.add(cm.id);
        if (cm.folder === 'inbox' && !cm.read) {
          newlyArrivedInboxMails.push(cm);
        }
      }
    }

    if (addedCount > 0) {
      saveEmails();
      renderMailList();
    }

    // Trigger popup + chime if new unread mail arrived
    if (notifyNew && newlyArrivedInboxMails.length > 0) {
      const latestMail = newlyArrivedInboxMails[0];
      showCuteNewMailModal(latestMail);
      showToast(`💌 Bạn nhận được thư mới từ ${latestMail.senderName || 'Người gửi'}!`);
    }
  } catch (err) {
    console.warn('Sync cloud error:', err);
  }
}

function startInboundMailPoller() {
  if (pollingIntervalTimer) clearInterval(pollingIntervalTimer);
  // Poll every 7 seconds
  pollingIntervalTimer = setInterval(() => {
    if (currentUser?.email) {
      syncCloudData(true);
    }
  }, 7000);
}

function stopInboundMailPoller() {
  if (pollingIntervalTimer) {
    clearInterval(pollingIntervalTimer);
    pollingIntervalTimer = null;
  }
}

// Switch between Auth Gate and Webmail App
async function setAuthState(user) {
  currentUser = user;
  const authGate = document.getElementById('auth-gate-container');
  const webmailApp = document.getElementById('webmail-app');

  if (user) {
    emails = JSON.parse(localStorage.getItem(getStorageKey(user.email))) || defaultEmails;
    authGate.style.display = 'none';
    webmailApp.classList.add('active');
    applyTheme(user.domain);
    closeReaderView();
    renderMailList();
    seenMailIds.clear();
    isInitialSyncDone = false;
    await syncCloudData(false);
    startInboundMailPoller();
  } else {
    stopInboundMailPoller();
    seenMailIds.clear();
    isInitialSyncDone = false;
    authGate.style.display = 'flex';
    webmailApp.classList.remove('active');
  }
}

// Calculate unread counts
function updateBadges() {
  if (!currentUser) return;
  const unreadCount = emails.filter(m => m.folder === 'inbox' && !m.read && m.domain === currentUser.domain).length;
  const unreadBadge = document.getElementById('inbox-unread-badge');
  unreadBadge.textContent = unreadCount;
  unreadBadge.style.display = unreadCount > 0 ? 'inline-block' : 'none';

  const starredCount = emails.filter(m => m.starred && m.domain === currentUser.domain).length;
  document.getElementById('starred-badge').textContent = starredCount > 0 ? `★ ${starredCount}` : '';
}

// Render Mail List
function renderMailList() {
  if (!currentUser) return;
  const container = document.getElementById('mail-list-container');
  const countLabel = document.getElementById('mail-count-label');

  // Filter emails for current user's domain
  let list = emails.filter(m => {
    if (m.domain !== currentUser.domain) return false;
    if (currentFolder === 'starred') {
      if (!m.starred || m.folder === 'trash') return false;
    } else {
      if (m.folder !== currentFolder) return false;
    }
    if (currentFilter === 'unread' && m.read) return false;
    if (currentFilter === 'starred' && !m.starred) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const match = m.subject.toLowerCase().includes(q) ||
                    m.senderName.toLowerCase().includes(q) ||
                    m.snippet.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  countLabel.textContent = `${list.length} thư`;
  updateBadges();

  if (list.length === 0) {
    const data = domainsData[currentUser.domain] || domainsData['luuvan.online'];
    container.innerHTML = `
      <div class="empty-state">
        <img src="${data.mascot.avatar}" alt="${escapeHtml(data.mascot.name)}" />
        <h3>Hộp thư trống trải!</h3>
        <p>Không có email nào trong mục này. Bấm "Soạn thư" để bắt đầu gửi thư nhé!</p>
      </div>
    `;
    return;
  }

  // Render with strict HTML escaping on user-provided strings
  container.innerHTML = list.map(m => {
    const isSent = m.folder === 'sent';
    const displaySender = isSent
      ? `Tới: ${m.recipientEmail || 'Người nhận'}`
      : (m.senderName || 'Người gửi');
    const displayAvatar = m.senderAvatar || (isSent ? '📤' : '✉️');

    return `
      <div class="mail-item-row ${m.read ? '' : 'unread'}" data-id="${escapeHtml(m.id)}">
        <button class="mail-star-btn ${m.starred ? 'starred' : ''}" data-star-id="${escapeHtml(m.id)}" title="Gắn dấu sao">★</button>
        <div class="mail-avatar">${escapeHtml(displayAvatar)}</div>
        <div class="mail-sender" title="${escapeHtml(displaySender)}">${escapeHtml(displaySender)}</div>
        <div class="mail-content-preview">
          <span class="mail-subject">${escapeHtml(m.subject)}</span>
          <span class="mail-snippet"> — ${escapeHtml(m.snippet)}</span>
        </div>
        <span class="mail-tag-badge" style="background: ${escapeHtml(m.tagColor)}15; color: ${escapeHtml(m.tagColor)};">${escapeHtml(m.tag)}</span>
        <div class="mail-date">${escapeHtml(m.date)}</div>
      </div>
    `;
  }).join('');

  container.querySelectorAll('.mail-item-row').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.closest('.mail-star-btn')) return;
      openReaderView(row.dataset.id);
    });
  });

  container.querySelectorAll('.mail-star-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const mailId = btn.dataset.starId;
      const mail = emails.find(x => x.id === mailId);
      if (mail) {
        mail.starred = !mail.starred;
        saveEmails();
        renderMailList();
      }
    });
  });
}

// Open Email Reader View (Secured)
function openReaderView(emailId) {
  const mail = emails.find(x => x.id === emailId);
  if (!mail) return;

  mail.read = true;
  activeEmailId = emailId;
  saveEmails();
  updateBadges();

  document.getElementById('mail-list-container').style.display = 'none';
  const readerView = document.getElementById('mail-reader-view');
  readerView.classList.add('active');

  // Dynamic back button text based on folder
  const folderNames = {
    inbox: 'Hộp thư đến',
    starred: 'Thư có sao',
    sent: 'Thư đã gửi',
    trash: 'Thùng rác'
  };
  const backTextEl = document.getElementById('reader-back-btn-text');
  if (backTextEl) {
    backTextEl.textContent = `Quay lại ${folderNames[currentFolder] || 'Hộp thư'}`;
  }

  // Text content prevents any XSS in header details
  document.getElementById('reader-subject').textContent = mail.subject;
  document.getElementById('reader-tag-badge').textContent = mail.tag;
  document.getElementById('reader-tag-badge').style.background = `${mail.tagColor}20`;
  document.getElementById('reader-tag-badge').style.color = mail.tagColor;

  document.getElementById('reader-sender-avatar').textContent = mail.senderAvatar || (mail.folder === 'sent' ? '📤' : '✉️');

  // Display From & To clearly
  const senderNameEl = document.getElementById('reader-sender-name');
  const senderEmailEl = document.getElementById('reader-sender-email');
  const toPrefixEl = document.getElementById('reader-to-prefix');
  const recipientEmailEl = document.getElementById('reader-recipient-email');

  if (mail.folder === 'sent') {
    senderNameEl.textContent = mail.senderName || currentUser?.username || 'Tôi';
    senderEmailEl.textContent = `<${mail.senderEmail || currentUser?.email || ''}>`;
    if (toPrefixEl) toPrefixEl.textContent = 'Tới:';
    if (recipientEmailEl) recipientEmailEl.textContent = mail.recipientEmail || 'Chưa xác định';
  } else {
    senderNameEl.textContent = mail.senderName || 'Người gửi';
    senderEmailEl.textContent = mail.senderEmail ? `<${mail.senderEmail}>` : '';
    if (toPrefixEl) toPrefixEl.textContent = 'Tới:';
    if (recipientEmailEl) recipientEmailEl.textContent = mail.recipientEmail || currentUser?.email || 'Tôi';
  }

  document.getElementById('reader-date').textContent = mail.date;

  const starBtn = document.getElementById('reader-star-btn');
  starBtn.classList.toggle('starred', mail.starred);

  // Body content passed through DOMPurify HTML Sanitizer
  const sanitizedBody = sanitizeEmailHtml(mail.body || `<p>${escapeHtml(mail.snippet)}</p>`);
  document.getElementById('reader-body-content').innerHTML = sanitizedBody;
}

// Close Reader View
function closeReaderView() {
  activeEmailId = null;
  document.getElementById('mail-reader-view').classList.remove('active');
  document.getElementById('mail-list-container').style.display = 'block';
  renderMailList();
}

// Floating Compose Modal
function initCompose() {
  const windowEl = document.getElementById('compose-window');
  const openBtn = document.getElementById('btn-compose-main');
  const closeBtn = document.getElementById('compose-close-btn');
  const minBtn = document.getElementById('compose-min-btn');
  const form = document.getElementById('compose-form');
  const trashBtn = document.getElementById('compose-trash-btn');

  openBtn.addEventListener('click', () => {
    windowEl.classList.remove('minimized');
    windowEl.classList.add('open');
    document.getElementById('compose-to').focus();
  });

  closeBtn.addEventListener('click', () => windowEl.classList.remove('open'));
  trashBtn.addEventListener('click', () => {
    form.reset();
    windowEl.classList.remove('open');
    showToast('Đã hủy thư nháp');
  });

  minBtn.addEventListener('click', () => {
    windowEl.classList.toggle('minimized');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const rawTo = document.getElementById('compose-to').value.trim();
    const subject = document.getElementById('compose-subject').value.trim();
    const body = document.getElementById('compose-body').value.trim();

    // Smart recipient parsing: regex extracts any valid email address, handling quotes, spaces, commas, semicolons
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const recipients = Array.from(new Set((rawTo.match(emailRegex) || []).map(r => r.toLowerCase().trim())));

    if (recipients.length === 0) {
      alert('Vui lòng nhập ít nhất một địa chỉ email hợp lệ (ví dụ: loc@gmail.com)!');
      return;
    }

    if (!subject) {
      alert('Vui lòng nhập tiêu đề email!');
      return;
    }

    const toDisplay = recipients.join(', ');

    // Send via Cloudflare API if token exists
    const token = getAuthToken();
    let apiFeedback = null;
    if (token) {
      try {
        const apiRes = await fetch('/api/emails/send', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            to: toDisplay,
            recipients,
            subject,
            content: body,
            fromEmail: currentUser?.email
          })
        });
        if (apiRes.ok) {
          apiFeedback = await apiRes.json();
        }
      } catch (err) {
        console.warn('Backend send email notice:', err);
      }
    }

    const newMail = {
      id: 'sent-' + Date.now(),
      domain: currentUser.domain,
      folder: 'sent',
      starred: false,
      read: true,
      senderName: currentUser.username,
      senderEmail: currentUser.email,
      recipientEmail: toDisplay,
      senderAvatar: '📤',
      subject: subject,
      snippet: body.substring(0, 80) + '...',
      tag: 'Đã gửi',
      tagColor: '#6366f1',
      date: 'Vừa xong',
      timestamp: Date.now(),
      body: `<div style="padding: 16px; font-family: sans-serif; line-height: 1.6;">
        <div style="background: #f8fafc; padding: 10px 14px; border-radius: 10px; margin-bottom: 14px; font-size: 0.85rem; color: #475569; border: 1px solid #e2e8f0;">
          <strong>Gửi đến (${recipients.length} người nhận):</strong> ${escapeHtml(toDisplay)}
        </div>
        <div>${escapeHtml(body).replace(/\n/g, '<br>')}</div>
      </div>`
    };

    emails.unshift(newMail);
    saveEmails();

    form.reset();
    windowEl.classList.remove('open');

    confetti({
      particleCount: 50,
      spread: 70,
      origin: { y: 0.6 },
      colors: ['#fbcfe8', '#e0e7ff', '#fef3c7', '#d1fae5']
    });

    let finalToastMsg = recipients.length > 1
      ? `Đã gửi thư tới ${recipients.length} người nhận! 🚀`
      : `Đã gửi email tới ${recipients[0]}! 🚀`;

    if (apiFeedback?.externalRecipientsCount > 0) {
      if (apiFeedback.externalRelaySuccess) {
        finalToastMsg += ' ✨ (Đã chuyển tiếp tới Gmail thật)';
      } else {
        const detail = apiFeedback.notice ? `: ${apiFeedback.notice}` : '';
        finalToastMsg += ` ⚠️ (Đã lưu hộp thư Đã gửi. Gửi ra internet${detail})`;
      }
    }

    showToast(finalToastMsg);
    renderMailList();
  });
}

// Auth Gate (Login & Register Handling)
function initAuthGate() {
  const tabLogin = document.getElementById('tab-login-btn');
  const tabRegister = document.getElementById('tab-register-btn');
  const formLogin = document.getElementById('form-login');
  const formRegister = document.getElementById('form-register');
  const linkToRegister = document.getElementById('link-to-register');
  const linkToLogin = document.getElementById('link-to-login');
  const regSuffix = document.getElementById('reg-domain-suffix');

  function showLoginTab() {
    tabLogin.classList.add('active');
    tabRegister.classList.remove('active');
    formLogin.style.display = 'block';
    formRegister.style.display = 'none';
  }

  function showRegisterTab() {
    tabRegister.classList.add('active');
    tabLogin.classList.remove('active');
    formRegister.style.display = 'block';
    formLogin.style.display = 'none';
  }

  tabLogin.addEventListener('click', showLoginTab);
  tabRegister.addEventListener('click', showRegisterTab);
  linkToRegister.addEventListener('click', (e) => { e.preventDefault(); showRegisterTab(); });
  linkToLogin.addEventListener('click', (e) => { e.preventDefault(); showLoginTab(); });

  // Domain selection cards in register form
  document.querySelectorAll('.auth-domain-card').forEach(card => {
    card.addEventListener('click', () => {
      document.querySelectorAll('.auth-domain-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      regChosenDomain = card.dataset.domain;
      regChosenMascotName = card.dataset.mascotName;
      regChosenMascotAvatar = card.dataset.mascotAvatar;
      regSuffix.textContent = `@${regChosenDomain}`;
    });
  });

  // Login submission
  formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const pass = document.getElementById('login-password').value;

    try {
      const user = await loginUser(email, pass);
      showToast(`Đăng nhập thành công! Chào mừng ${user.username} ✨`);
      confetti({ particleCount: 40, spread: 60, origin: { y: 0.6 } });
      setAuthState(user);
    } catch (err) {
      alert(err.message);
    }
  });

  // Register submission
  formRegister.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('reg-username').value.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
    const pass = document.getElementById('reg-password').value;

    if (!username) {
      alert('Tên tài khoản không hợp lệ!');
      return;
    }

    try {
      const user = await registerUser({
        username,
        domain: regChosenDomain,
        password: pass,
        mascotName: regChosenMascotName,
        mascotAvatar: regChosenMascotAvatar
      });

      emails = JSON.parse(localStorage.getItem('pastelmail_emails_v1')) || emails;
      showToast(`Khởi tạo hòm thư ${user.email} thành công! 🎉`);
      confetti({ particleCount: 70, spread: 90, origin: { y: 0.5 } });
      setAuthState(user);
    } catch (err) {
      alert(err.message);
    }
  });

  // Sign out button
  document.getElementById('btn-signout').addEventListener('click', () => {
    clearSession();
    showToast('Đã đăng xuất khỏi hòm thư an toàn!');
    setAuthState(null);
  });
}

// Setup Event Listeners for Webmail
function setupEvents() {
  // Folder navigation
  document.querySelectorAll('.folder-item').forEach(item => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.folder-item').forEach(f => f.classList.remove('active'));
      item.classList.add('active');
      currentFolder = item.dataset.folder;
      closeReaderView();
    });
  });

  // Filter tabs
  document.querySelectorAll('.filter-tab-btn').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.filter-tab-btn').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentFilter = tab.dataset.filter;
      renderMailList();
    });
  });

  // Search input
  const searchInput = document.getElementById('search-input');
  searchInput.addEventListener('input', (e) => {
    searchQuery = e.target.value.trim();
    renderMailList();
  });

  // Refresh
  document.getElementById('btn-refresh').addEventListener('click', async () => {
    await syncCloudData();
    if (currentUser?.email) {
      emails = JSON.parse(localStorage.getItem(getStorageKey(currentUser.email))) || defaultEmails;
    }
    renderMailList();
    showToast('Đã đồng bộ hòm thư từ Cloudflare!');
  });

  // Mark all read
  document.getElementById('btn-mark-all-read').addEventListener('click', () => {
    emails.forEach(m => {
      if (m.domain === currentUser?.domain && m.folder === currentFolder) {
        m.read = true;
      }
    });
    saveEmails();
    renderMailList();
    showToast('Đã đánh dấu tất cả thư là đã đọc');
  });

  // Reader back button
  document.getElementById('reader-back-btn').addEventListener('click', closeReaderView);

  // Reader delete button
  document.getElementById('reader-delete-btn').addEventListener('click', () => {
    if (activeEmailId) {
      const mail = emails.find(x => x.id === activeEmailId);
      if (mail) {
        if (mail.folder === 'trash') {
          emails = emails.filter(x => x.id !== activeEmailId);
          showToast('Đã xóa vĩnh viễn thư!');
        } else {
          mail.folder = 'trash';
          showToast('Đã chuyển thư vào Thùng rác 🗑️');
        }
        saveEmails();
        closeReaderView();
      }
    }
  });

  // Reader Reply button
  document.getElementById('reader-reply-btn').addEventListener('click', () => {
    if (activeEmailId) {
      const mail = emails.find(x => x.id === activeEmailId);
      if (mail) {
        document.getElementById('compose-to').value = mail.senderEmail;
        document.getElementById('compose-subject').value = `Re: ${mail.subject}`;
        document.getElementById('compose-window').classList.remove('minimized');
        document.getElementById('compose-window').classList.add('open');
        document.getElementById('compose-body').focus();
      }
    }
  });

  // Reader Star button
  document.getElementById('reader-star-btn').addEventListener('click', () => {
    if (activeEmailId) {
      const mail = emails.find(x => x.id === activeEmailId);
      if (mail) {
        mail.starred = !mail.starred;
        document.getElementById('reader-star-btn').classList.toggle('starred', mail.starred);
        saveEmails();
        updateBadges();
      }
    }
  });

  // Sidebar mascot speech click
  document.getElementById('sidebar-mascot-card').addEventListener('click', () => {
    if (!currentUser) return;
    const data = domainsData[currentUser.domain] || domainsData['luuvan.online'];
    const quotes = data.mascot.quotes;
    const randomQuote = quotes[Math.floor(Math.random() * quotes.length)];
    document.getElementById('sidebar-mascot-quote').textContent = randomQuote;
    confetti({ particleCount: 25, spread: 50, origin: { x: 0.1, y: 0.8 } });
  });
}

// Interactive 4-Domain Ecosystem Switcher
function initDomainSwitcher() {
  const pillBtn = document.getElementById('account-pill-btn');
  const dropdown = document.getElementById('domain-switcher-dropdown');
  const optionsList = document.getElementById('switcher-options-list');

  if (!pillBtn || !dropdown || !optionsList) return;

  function renderSwitcherOptions() {
    if (!currentUser) return;
    const currentDomain = currentUser.domain || 'luuvan.online';
    const cleanUsername = currentUser.username || currentUser.email.split('@')[0];

    const ecosystemDomains = [
      {
        domain: 'luuvan.online',
        title: 'Lưu Vân Thư Quán',
        category: 'Tri thức & Lập trình',
        mascot: 'Mèo Luna',
        avatar: '/assets/mascot_luuvan.webp',
        badge: 'Học tập & Dev'
      },
      {
        domain: 'aetherix.site',
        title: 'Aetherix Studio',
        category: 'AI & Cloud Edge',
        mascot: 'Mèo Aether',
        avatar: '/assets/mascot_aetherix.webp',
        badge: 'AI & Cloud'
      },
      {
        domain: 'chotroi.site',
        title: 'Chợ Trời Bazaar',
        category: 'Thương mại & Tài nguyên MMO',
        mascot: 'Gấu Kuma',
        avatar: '/assets/mascot_chotroi.webp',
        badge: 'Giao dịch MMO'
      },
      {
        domain: 'aadidass.tokyo',
        title: 'Tokyo Harajuku',
        category: 'Gaming & Giải trí',
        mascot: 'Thỏ Midori',
        avatar: '/assets/mascot_bunny.webp',
        badge: 'Game & Play'
      }
    ];

    optionsList.innerHTML = ecosystemDomains.map(item => {
      const isActive = item.domain === currentDomain;
      const emailForDomain = `${cleanUsername}@${item.domain}`;

      return `
        <div class="switcher-option-card ${isActive ? 'active' : ''}" data-domain="${item.domain}">
          <img src="${item.avatar}" alt="${escapeHtml(item.mascot)}" class="switcher-card-avatar" />
          <div class="switcher-card-info">
            <strong>${item.domain}</strong>
            <span>${emailForDomain}</span>
            <small style="color: #64748b; font-size: 0.72rem;">${item.category}</small>
          </div>
          <span class="switcher-card-badge ${isActive ? 'active-indicator' : ''}">
            ${isActive ? '✓ Đang dùng' : item.badge}
          </span>
        </div>
      `;
    }).join('');

    optionsList.querySelectorAll('.switcher-option-card').forEach(card => {
      card.addEventListener('click', async (e) => {
        e.stopPropagation();
        const targetDomain = card.dataset.domain;
        if (targetDomain === currentUser.domain) {
          closeDropdown();
          return;
        }

        // Switch Domain
        const updated = switchActiveDomain(targetDomain);
        if (updated) {
          currentUser = updated;
          emails = JSON.parse(localStorage.getItem(getStorageKey(currentUser.email))) || defaultEmails;
          applyTheme(currentUser.domain);
          renderMailList();
          closeReaderView();
          closeDropdown();

          confetti({
            particleCount: 60,
            spread: 80,
            origin: { y: 0.2 },
            colors: ['#fbcfe8', '#e0e7ff', '#fef3c7', '#d1fae5']
          });

          showToast(`Đã chuyển sang không gian ${currentUser.mascot} (${currentUser.domain})! ✨`);
          await syncCloudData();
        }
      });
    });
  }

  function toggleDropdown() {
    const isOpen = dropdown.classList.contains('open');
    if (isOpen) {
      closeDropdown();
    } else {
      openDropdown();
    }
  }

  function openDropdown() {
    renderSwitcherOptions();
    dropdown.classList.add('open');
    pillBtn.classList.add('open');
  }

  function closeDropdown() {
    dropdown.classList.remove('open');
    pillBtn.classList.remove('open');
  }

  pillBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleDropdown();
  });

  document.addEventListener('click', (e) => {
    if (!pillBtn.contains(e.target) && !dropdown.contains(e.target)) {
      closeDropdown();
    }
  });
}

// Bootstrap
document.addEventListener('DOMContentLoaded', async () => {
  await initAuth();
  initAuthGate();
  initCompose();
  initDomainSwitcher();
  initNewMailPopup();
  setupEvents();

  // Instant check when switching tabs back to the webmail app
  window.addEventListener('focus', () => {
    if (currentUser?.email) {
      syncCloudData(true);
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && currentUser?.email) {
      syncCloudData(true);
    }
  });

  // Check existing session
  const session = getSession();
  setAuthState(session);
});
