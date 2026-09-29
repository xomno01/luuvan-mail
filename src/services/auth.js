// PastelMail Authentication & Session Service (Security Hardened)
import { defaultEmails } from '../data/mockEmails.js';

const USERS_STORAGE_KEY = 'pastelmail_users_db_v1';
const SESSION_KEY = 'pastelmail_active_session_v1';
const TOKEN_KEY = 'pastelmail_jwt_token_v1';
const APP_PASSWORD_SALT = 'luuvan_pastelmail_security_salt_2026';

// Cryptographic Salted SHA-256 Hash
export async function hashPassword(plainText, salt = APP_PASSWORD_SALT) {
  const enc = new TextEncoder();
  // Hash combining input with application salt
  const msgUint8 = enc.encode(`${plainText}:${salt}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Legacy hash without salt (to keep default seed test accounts functional)
export async function hashPasswordLegacy(plainText) {
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(plainText));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Token Storage
export function getAuthToken() {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function setAuthToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuthToken() {
  localStorage.removeItem(TOKEN_KEY);
}

// Initialize seed users locally
export async function initAuth() {
  let users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY));
  if (!users || users.length === 0) {
    const legacyPassHash = await hashPasswordLegacy('123456');
    users = [
      {
        id: 'user-0',
        email: 'loc@luuvan.online',
        username: 'loc',
        domain: 'luuvan.online',
        passwordHash: legacyPassHash,
        mascot: 'Mèo Luna (Tri thức & Dev)',
        avatar: '/assets/mascot_luuvan.webp',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-1',
        email: 'vinhloc@aadidass.tokyo',
        username: 'vinhloc',
        domain: 'aadidass.tokyo',
        passwordHash: legacyPassHash,
        mascot: 'Thỏ Midori (Game & Giải trí)',
        avatar: '/assets/mascot_bunny.webp',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-2',
        email: 'admin@aetherix.site',
        username: 'admin',
        domain: 'aetherix.site',
        passwordHash: legacyPassHash,
        mascot: 'Mèo Aether (AI & Cloud)',
        avatar: '/assets/mascot_aetherix.webp',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-3',
        email: 'shop@chotroi.site',
        username: 'shop',
        domain: 'chotroi.site',
        passwordHash: legacyPassHash,
        mascot: 'Gấu Kuma (MMO & Bazaar)',
        avatar: '/assets/mascot_chotroi.webp',
        createdAt: new Date().toISOString()
      }
    ];
    localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
  }
  return users;
}

// Register a new user (Cloud D1 sync + Local fallback)
export async function registerUser({ username, domain, password, mascotName, mascotAvatar }) {
  const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY)) || [];
  const cleanUsername = username.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
  const fullEmail = `${cleanUsername}@${domain}`;
  const userId = 'user-' + Date.now();

  // Try salted hash first
  const passwordHash = await hashPassword(password);
  const newUser = {
    id: userId,
    email: fullEmail,
    username: cleanUsername,
    domain,
    passwordHash,
    mascot: mascotName,
    avatar: mascotAvatar,
    createdAt: new Date().toISOString()
  };

  // 1. Call Backend API if available
  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: userId,
        email: fullEmail,
        username: cleanUsername,
        domain,
        passwordHash,
        mascotName,
        mascotAvatar
      })
    });

    if (res.ok) {
      const data = await res.json();
      if (data.token) setAuthToken(data.token);
    } else {
      const errData = await res.json().catch(() => ({}));
      if (errData.error && errData.error.includes('đã tồn tại')) {
        throw new Error(errData.error);
      }
    }
  } catch (apiErr) {
    if (apiErr.message && apiErr.message.includes('đã tồn tại')) {
      throw apiErr;
    }
    console.warn('Backend sync warning (offline/local fallback):', apiErr);
  }

  // 2. Save locally
  if (users.some(u => u.email.toLowerCase() === fullEmail.toLowerCase())) {
    throw new Error(`Email "${fullEmail}" đã được đăng ký bởi người dùng khác. Vui lòng chọn tên khác!`);
  }
  users.unshift(newUser);
  localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));

  // Seed welcome email
  const emails = JSON.parse(localStorage.getItem('pastelmail_emails_v1')) || defaultEmails;
  emails.unshift({
    id: 'welcome-' + Date.now(),
    domain: domain,
    folder: 'inbox',
    starred: true,
    read: false,
    senderName: 'Ban Quản Trị Lưu Vân Mail',
    senderEmail: `admin@${domain}`,
    senderAvatar: '🌸',
    subject: `Chào mừng ${cleanUsername} đến với hòm thư ${fullEmail}! ✨`,
    snippet: 'Hộp thư của bạn đã được kích hoạt thành công trên hạ tầng bảo mật Cloudflare...',
    tag: 'Chào Mừng',
    tagColor: '#db2777',
    date: 'Vừa xong',
    timestamp: Date.now(),
    body: `
      <div style="background: #fdf2f8; padding: 24px; border-radius: 16px; border: 1px solid #fbcfe8; font-family: sans-serif;">
        <h3 style="color: #be185d; margin-bottom: 12px;">Chúc mừng bạn đã tạo hòm thư thành công! 🎉</h3>
        <p style="color: #831843; line-height: 1.6; margin-bottom: 16px;">
          Xin chào <strong>${cleanUsername}</strong>! Địa chỉ email <strong>${fullEmail}</strong> của bạn đã sẵn sàng để gửi nhận thư, đăng ký tài khoản game, giao dịch và làm việc.
        </p>
        <div style="background: white; padding: 16px; border-radius: 12px; border: 1px dashed #f472b6; margin-bottom: 16px;">
          ✨ <strong>Linh vật hộ mệnh:</strong> ${mascotName}<br>
          🛡️ <strong>Bảo mật:</strong> Đã kích hoạt HMAC-SHA256 Token, chống XSS và mã hóa Cloudflare Edge.
        </div>
        <p style="color: #9d174d; font-size: 0.9rem;">Chúc bạn có những trải nghiệm thật tuyệt vời cùng Lưu Vân Mail!</p>
      </div>
    `
  });
  localStorage.setItem('pastelmail_emails_v1', JSON.stringify(emails));

  setSession(newUser);
  return newUser;
}

// Login
export async function loginUser(email, password) {
  const cleanEmail = email.trim().toLowerCase();
  const hashSalted = await hashPassword(password);
  const hashLegacy = await hashPasswordLegacy(password);

  // 1. Try Cloud API first
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: cleanEmail, passwordHash: hashSalted })
    });

    if (res.ok) {
      const data = await res.json();
      if (data.token) setAuthToken(data.token);
      const user = {
        id: data.user.id,
        email: data.user.email,
        username: data.user.username,
        domain: data.user.domain,
        mascot: data.user.mascotName || 'Linh vật',
        avatar: data.user.mascotAvatar || '/assets/mascot_luuvan.webp'
      };
      setSession(user);
      return user;
    } else {
      // Try legacy hash on server
      const resLegacy = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanEmail, passwordHash: hashLegacy })
      });
      if (resLegacy.ok) {
        const data = await resLegacy.json();
        if (data.token) setAuthToken(data.token);
        const user = {
          id: data.user.id,
          email: data.user.email,
          username: data.user.username,
          domain: data.user.domain,
          mascot: data.user.mascotName || 'Linh vật',
          avatar: data.user.mascotAvatar || '/assets/mascot_luuvan.webp'
        };
        setSession(user);
        return user;
      }
    }
  } catch (apiErr) {
    console.warn('API login check failed, falling back to local storage:', apiErr);
  }

  // 2. Fallback to Local Storage
  const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY)) || [];
  const user = users.find(u => u.email.toLowerCase() === cleanEmail);

  if (!user) {
    throw new Error('Email này chưa được đăng ký trong hệ thống. Vui lòng bấm Đăng Ký!');
  }

  if (user.passwordHash !== hashSalted && user.passwordHash !== hashLegacy) {
    throw new Error('Mật khẩu không chính xác. Vui lòng kiểm tra lại!');
  }

  setSession(user);
  return user;
}

// Fetch Cloud Emails from Cloudflare D1
export async function fetchCloudEmails(email) {
  const token = getAuthToken();
  if (!token) return [];

  try {
    const res = await fetch(`/api/emails?email=${encodeURIComponent(email)}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (res.ok) {
      const data = await res.json();
      return (data.emails || []).map(row => {
        let mailDomain = 'luuvan.online';
        if (row.folder === 'sent' && row.sender_email && row.sender_email.includes('@')) {
          mailDomain = row.sender_email.split('@')[1];
        } else if (row.recipient_email && row.recipient_email.includes('@')) {
          mailDomain = row.recipient_email.split('@')[1];
        }

        const decodeMime = (str) => {
          if (!str || typeof str !== 'string') return '';
          let s = str;
          if (s.includes('=3D') || s.includes('=20') || s.includes('=C3=') || s.includes('=\r\n') || s.includes('=\n')) {
            try {
              const stripped = s.replace(/=[\r\n]+/g, '');
              const bytes = [];
              for (let i = 0; i < stripped.length; i++) {
                if (stripped[i] === '=' && i + 2 < stripped.length) {
                  const hex = stripped.substring(i + 1, i + 3);
                  if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
                    bytes.push(parseInt(hex, 16));
                    i += 2;
                    continue;
                  }
                }
                bytes.push(stripped.charCodeAt(i));
              }
              s = new TextDecoder('utf-8').decode(new Uint8Array(bytes));
            } catch {}
          }
          const normalized = s.replace(/(\?=\s+(?==\?))/g, '?=');
          return normalized.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (match, charset, encoding, text) => {
            try {
              const enc = encoding.toUpperCase();
              if (enc === 'B') {
                const binStr = atob(text);
                const bytes = Uint8Array.from(binStr, c => c.charCodeAt(0));
                return new TextDecoder(charset).decode(bytes);
              } else if (enc === 'Q') {
                const unescaped = text.replace(/_/g, ' ').replace(/=([A-Fa-f0-9]{2})/g, (_, hex) => {
                  return String.fromCharCode(parseInt(hex, 16));
                });
                const bytes = Uint8Array.from(unescaped, c => c.charCodeAt(0));
                return new TextDecoder(charset).decode(bytes);
              }
            } catch {
              return match;
            }
            return match;
          });
        };

        const rawSubject = row.subject || '(Không có tiêu đề)';
        const cleanSubject = decodeMime(rawSubject);
        const rawSender = row.sender_name || 'Người gửi';
        const cleanSender = decodeMime(rawSender);
        let cleanBody = row.body_html || `<p>${row.snippet}</p>`;
        if (cleanBody.includes('=3D') || cleanBody.includes('=20') || cleanBody.includes('=C3=')) {
          cleanBody = decodeMime(cleanBody);
        }

        return {
          id: row.id,
          domain: mailDomain,
          folder: row.folder || 'inbox',
          starred: Boolean(row.is_starred),
          read: Boolean(row.is_read),
          senderName: cleanSender,
          senderEmail: row.sender_email || '',
          recipientEmail: row.recipient_email || '',
          senderAvatar: row.sender_avatar || (row.folder === 'sent' ? '📤' : '✉️'),
          subject: cleanSubject,
          snippet: decodeMime(row.snippet || ''),
          tag: row.tag || (row.folder === 'sent' ? 'Đã gửi' : 'Hộp thư'),
          tagColor: row.tag_color || (row.folder === 'sent' ? '#6366f1' : '#ec4899'),
          date: new Date(row.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          timestamp: new Date(row.created_at).getTime(),
          body: cleanBody
        };
      });
    }
  } catch (err) {
    console.warn('Could not fetch cloud emails:', err);
  }
  return [];
}

// Session Helpers
export function setSession(user) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(user));
}

export function getSession() {
  const data = localStorage.getItem(SESSION_KEY);
  return data ? JSON.parse(data) : null;
}

export function clearSession() {
  localStorage.removeItem(SESSION_KEY);
  clearAuthToken();
}

// Switch User Domain in the Ecosystem
export function switchActiveDomain(targetDomain) {
  const user = getSession();
  if (!user) return null;

  const username = user.username || user.email.split('@')[0];
  const mascotMap = {
    'luuvan.online': { name: 'Mèo Luna (Tri thức & Dev)', avatar: '/assets/mascot_luuvan.webp' },
    'aetherix.site': { name: 'Mèo Aether (AI & Cloud)', avatar: '/assets/mascot_aetherix.webp' },
    'chotroi.site': { name: 'Gấu Kuma (MMO & Bazaar)', avatar: '/assets/mascot_chotroi.webp' },
    'aadidass.tokyo': { name: 'Thỏ Midori (Game & Giải trí)', avatar: '/assets/mascot_bunny.webp' }
  };

  const mascot = mascotMap[targetDomain] || mascotMap['luuvan.online'];
  const updatedUser = {
    ...user,
    domain: targetDomain,
    email: `${username}@${targetDomain}`,
    mascot: mascot.name,
    avatar: mascot.avatar
  };

  setSession(updatedUser);
  return updatedUser;
}
