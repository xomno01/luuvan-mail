// PastelMail Authentication & Session Service
import { defaultEmails } from '../data/mockEmails.js';

const USERS_STORAGE_KEY = 'pastelmail_users_db_v1';
const SESSION_KEY = 'pastelmail_active_session_v1';

// Hash password with Web Crypto SHA-256
export async function hashPassword(plainText) {
  const msgUint8 = new TextEncoder().encode(plainText);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Initialize seed users if empty
export async function initAuth() {
  let users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY));
  if (!users || users.length === 0) {
    const defaultPasswordHash = await hashPassword('123456');
    users = [
      {
        id: 'user-1',
        email: 'vinhloc@aadidass.tokyo',
        username: 'vinhloc',
        domain: 'aadidass.tokyo',
        passwordHash: defaultPasswordHash,
        mascot: 'Thỏ Midori (Game)',
        avatar: '/assets/mascot_bunny.webp',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-2',
        email: 'admin@aetherix.site',
        username: 'admin',
        domain: 'aetherix.site',
        passwordHash: defaultPasswordHash,
        mascot: 'Mèo Aether (AI & Cloud)',
        avatar: '/assets/mascot_aetherix.webp',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-3',
        email: 'shop@chotroi.site',
        username: 'shop',
        domain: 'chotroi.site',
        passwordHash: defaultPasswordHash,
        mascot: 'Gấu Kuma (MMO)',
        avatar: '/assets/mascot_chotroi.webp',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-4',
        email: 'reader@luuvan.online',
        username: 'reader',
        domain: 'luuvan.online',
        passwordHash: defaultPasswordHash,
        mascot: 'Mèo Luna (Tri thức)',
        avatar: '/assets/mascot_luuvan.webp',
        createdAt: new Date().toISOString()
      }
    ];
    localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
  }
  return users;
}

// Register a new user
export async function registerUser({ username, domain, password, mascotName, mascotAvatar }) {
  const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY)) || [];
  const fullEmail = `${username.toLowerCase()}@${domain}`;

  // Check duplicate
  if (users.some(u => u.email.toLowerCase() === fullEmail.toLowerCase())) {
    throw new Error(`Email "${fullEmail}" đã được đăng ký bởi người dùng khác. Vui lòng chọn tên khác!`);
  }

  const passwordHash = await hashPassword(password);
  const newUser = {
    id: 'user-' + Date.now(),
    email: fullEmail,
    username,
    domain,
    passwordHash,
    mascot: mascotName,
    avatar: mascotAvatar,
    createdAt: new Date().toISOString()
  };

  users.unshift(newUser);
  localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));

  // Seed a welcome email for this new user
  const emails = JSON.parse(localStorage.getItem('pastelmail_emails_v1')) || defaultEmails;
  emails.unshift({
    id: 'welcome-' + Date.now(),
    domain: domain,
    folder: 'inbox',
    starred: true,
    read: false,
    senderName: 'Ban Quản Trị PastelMail',
    senderEmail: `admin@${domain}`,
    senderAvatar: '🌸',
    subject: `Chào mừng ${username} đến với hòm thư ${fullEmail}!`,
    snippet: 'Hộp thư của bạn đã được kích hoạt thành công trên hạ tầng bảo mật Cloudflare...',
    tag: 'Chào Mừng',
    tagColor: '#db2777',
    date: 'Vừa xong',
    timestamp: Date.now(),
    body: `
      <div style="background: #fdf2f8; padding: 24px; border-radius: 16px; border: 1px solid #fbcfe8; font-family: sans-serif;">
        <h3 style="color: #be185d; margin-bottom: 12px;">Chúc mừng bạn đã tạo hòm thư thành công! 🎉</h3>
        <p style="color: #831843; line-height: 1.6; margin-bottom: 16px;">
          Xin chào <strong>${username}</strong>! Địa chỉ email <strong>${fullEmail}</strong> của bạn đã sẵn sàng để gửi nhận thư, đăng ký tài khoản game, giao dịch và làm việc.
        </p>
        <div style="background: white; padding: 16px; border-radius: 12px; border: 1px dashed #f472b6; margin-bottom: 16px;">
          ✨ <strong>Linh vật hộ mệnh:</strong> ${mascotName}<br>
          🛡️ <strong>Bảo mật:</strong> Đã kích hoạt bảo vệ chống thư rác và mã hóa phiên.
        </div>
        <p style="color: #9d174d; font-size: 0.9rem;">Chúc bạn có những trải nghiệm thật tuyệt vời cùng PastelMail!</p>
      </div>
    `
  });
  localStorage.setItem('pastelmail_emails_v1', JSON.stringify(emails));

  // Auto login
  setSession(newUser);
  return newUser;
}

// Login
export async function loginUser(email, password) {
  const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY)) || [];
  const cleanEmail = email.trim().toLowerCase();
  const user = users.find(u => u.email.toLowerCase() === cleanEmail);

  if (!user) {
    throw new Error('Email này chưa được đăng ký trong hệ thống. Vui lòng bấm Đăng Ký!');
  }

  const hash = await hashPassword(password);
  if (user.passwordHash !== hash) {
    throw new Error('Mật khẩu không chính xác. Vui lòng kiểm tra lại!');
  }

  setSession(user);
  return user;
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
}
