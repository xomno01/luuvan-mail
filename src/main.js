import confetti from 'canvas-confetti';
import DOMPurify from 'dompurify';
import { defaultEmails } from './data/mockEmails.js';
import { domainsData } from './data/domains.js';
import { initAuth, loginUser, registerUser, getSession, clearSession, fetchCloudEmails, getAuthToken } from './services/auth.js';

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

// Sync Cloud Emails
async function syncCloudData() {
  if (!currentUser?.email) return;
  try {
    const cloudMails = await fetchCloudEmails(currentUser.email);
    if (cloudMails && cloudMails.length > 0) {
      // Merge unique cloud emails with local emails
      const existingIds = new Set(emails.map(m => m.id));
      let added = 0;
      for (const cm of cloudMails) {
        if (!existingIds.has(cm.id)) {
          emails.unshift(cm);
          existingIds.add(cm.id);
          added++;
        }
      }
      if (added > 0) {
        saveEmails();
        renderMailList();
      }
    }
  } catch (err) {
    console.warn('Sync cloud error:', err);
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
    await syncCloudData();
  } else {
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
  container.innerHTML = list.map(m => `
    <div class="mail-item-row ${m.read ? '' : 'unread'}" data-id="${escapeHtml(m.id)}">
      <button class="mail-star-btn ${m.starred ? 'starred' : ''}" data-star-id="${escapeHtml(m.id)}" title="Gắn dấu sao">★</button>
      <div class="mail-avatar">${escapeHtml(m.senderAvatar || '✉️')}</div>
      <div class="mail-sender">${escapeHtml(m.senderName)}</div>
      <div class="mail-content-preview">
        <span class="mail-subject">${escapeHtml(m.subject)}</span>
        <span class="mail-snippet"> — ${escapeHtml(m.snippet)}</span>
      </div>
      <span class="mail-tag-badge" style="background: ${escapeHtml(m.tagColor)}15; color: ${escapeHtml(m.tagColor)};">${escapeHtml(m.tag)}</span>
      <div class="mail-date">${escapeHtml(m.date)}</div>
    </div>
  `).join('');

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

  // Text content prevents any XSS in header details
  document.getElementById('reader-subject').textContent = mail.subject;
  document.getElementById('reader-tag-badge').textContent = mail.tag;
  document.getElementById('reader-tag-badge').style.background = `${mail.tagColor}20`;
  document.getElementById('reader-tag-badge').style.color = mail.tagColor;

  document.getElementById('reader-sender-avatar').textContent = mail.senderAvatar || '✉️';
  if (mail.folder === 'sent' && mail.recipientEmail) {
    document.getElementById('reader-sender-name').textContent = `Tới: ${mail.recipientEmail}`;
    document.getElementById('reader-sender-email').textContent = `Từ: <${mail.senderEmail}>`;
  } else {
    document.getElementById('reader-sender-name').textContent = mail.senderName;
    document.getElementById('reader-sender-email').textContent = `<${mail.senderEmail}>`;
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
          body: JSON.stringify({ to: toDisplay, recipients, subject, content: body })
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
    emails = JSON.parse(localStorage.getItem('pastelmail_emails_v1')) || defaultEmails;
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

// Bootstrap
document.addEventListener('DOMContentLoaded', async () => {
  await initAuth();
  initAuthGate();
  initCompose();
  setupEvents();

  // Check existing session
  const session = getSession();
  setAuthState(session);
});
