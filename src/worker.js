// PastelMail Cloudflare Worker Backend (Security Hardened & Enterprise Grade)
// Handles API requests, Authentication Tokens, Rate Limiting & Inbound Cloudflare Email Routing

const ALLOWED_DOMAINS = ['luuvan.online', 'aetherix.site', 'chotroi.site', 'aadidass.tokyo'];
const rateLimitMap = new Map();

// In-memory sliding rate limiter per client IP
function checkRateLimit(ip, limit = 20, windowMs = 60000) {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + windowMs;
  } else {
    record.count++;
  }
  rateLimitMap.set(ip, record);

  // Periodic cleanup if map grows
  if (rateLimitMap.size > 2000) {
    for (const [k, v] of rateLimitMap.entries()) {
      if (now > v.resetAt) rateLimitMap.delete(k);
    }
  }

  return record.count <= limit;
}

// Cryptographic HMAC-SHA256 Token Helpers
async function signToken(payload, secret) {
  const enc = new TextEncoder();
  const headerStr = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
  const payloadStr = JSON.stringify(payload);

  const b64Header = btoa(headerStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64Payload = btoa(payloadStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const data = `${b64Header}.${b64Payload}`;

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sigBuffer = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return `${data}.${sigB64}`;
}

async function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const [b64Header, b64Payload, sigB64] = parts;
  const data = `${b64Header}.${b64Payload}`;
  const enc = new TextEncoder();

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    let rawSig = sigB64.replace(/-/g, '+').replace(/_/g, '/');
    while (rawSig.length % 4) rawSig += '=';
    const sigBytes = Uint8Array.from(atob(rawSig), c => c.charCodeAt(0));

    const isValid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(data));
    if (!isValid) return null;

    let rawPayload = b64Payload.replace(/-/g, '+').replace(/_/g, '/');
    while (rawPayload.length % 4) rawPayload += '=';
    const payload = JSON.parse(atob(rawPayload));

    if (payload.exp && Date.now() > payload.exp) return null; // Expired
    return payload;
  } catch (e) {
    return null;
  }
}

// Sanitize plain string against HTML injection
function escapeHtml(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Decode RFC 2047 MIME encoded-word headers (UTF-8 Q/B encoding)
function decodeMimeWord(str) {
  if (!str || typeof str !== 'string') return '';
  const normalized = str.replace(/(\?=\s+(?==\?))/g, '?=');
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
}

// Clean MIME body extraction for incoming Cloudflare emails
function extractCleanEmailContent(raw) {
  if (!raw) return { snippet: '', html: '' };
  
  // Try to extract HTML body
  const htmlMatch = raw.match(/Content-Type:\s*text\/html[^;]*;?[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n([\s\S]*?)(?=(?:\r?\n--[^\r\n]+|\r?\n\.\r?\n|$))/i);
  if (htmlMatch && htmlMatch[1]) {
    const cleanHtml = htmlMatch[1].trim();
    const plainText = cleanHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    return {
      snippet: plainText.substring(0, 100) + '...',
      html: cleanHtml
    };
  }

  // Try to extract plain text body
  const textMatch = raw.match(/Content-Type:\s*text\/plain[^;]*;?[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n([\s\S]*?)(?=(?:\r?\n--[^\r\n]+|\r?\n\.\r?\n|$))/i);
  if (textMatch && textMatch[1]) {
    const cleanText = textMatch[1].trim();
    return {
      snippet: cleanText.substring(0, 100).replace(/\r?\n/g, ' ') + '...',
      html: `<div style="padding: 16px; font-family: sans-serif; line-height: 1.6; color: #1e293b;">${escapeHtml(cleanText).replace(/\n/g, '<br>')}</div>`
    };
  }

  // Fallback: strip headers after double newline
  const headerSplit = raw.split(/\r?\n\r?\n/);
  const bodyContent = headerSplit.length > 1 ? headerSplit.slice(1).join('\n\n') : raw;
  const cleanSnippet = bodyContent.substring(0, 100).replace(/\r?\n/g, ' ');
  return {
    snippet: cleanSnippet + '...',
    html: `<div style="padding: 16px; font-family: sans-serif; line-height: 1.6; color: #1e293b;"><pre style="white-space: pre-wrap; font-family: sans-serif;">${escapeHtml(bodyContent.trim())}</pre></div>`
  };
}

export default {
  // 1. HTTP API Handler
  async fetch(request, env) {
    const url = new URL(request.url);
    const clientIp = request.headers.get('cf-connecting-ip') || 'unknown-client';
    const secretKey = env.JWT_SECRET || 'pastelmail_cloudflare_edge_secret_key_2026';

    // Security & CORS Headers
    const responseHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'X-XSS-Protection': '1; mode=block',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: responseHeaders });
    }

    try {
      // Health check endpoint
      if (url.pathname === '/api/health') {
        return new Response(JSON.stringify({
          status: 'ok',
          service: 'PastelMail Secure API',
          timestamp: new Date().toISOString()
        }), { headers: responseHeaders });
      }

      // Check D1 binding
      if (!env.DB) {
        return new Response(JSON.stringify({ error: 'Cơ sở dữ liệu D1 chưa được liên kết' }), {
          status: 500,
          headers: responseHeaders
        });
      }

      // -----------------------------------------------------------------------
      // Route: Register
      // -----------------------------------------------------------------------
      if (url.pathname === '/api/auth/register' && request.method === 'POST') {
        if (!checkRateLimit(clientIp, 15, 60000)) {
          return new Response(JSON.stringify({ error: 'Bạn thao tác quá nhanh. Vui lòng chờ 1 phút!' }), {
            status: 429,
            headers: responseHeaders
          });
        }

        const body = await request.json();
        const { id, email, username, domain, passwordHash, mascotName, mascotAvatar } = body;

        // Strict input validation
        if (!email || !username || !domain || !passwordHash) {
          return new Response(JSON.stringify({ error: 'Thông tin đăng ký không hợp lệ hoặc bị thiếu' }), {
            status: 400,
            headers: responseHeaders
          });
        }

        const cleanUsername = String(username).toLowerCase().replace(/[^a-z0-9._-]/g, '');
        if (cleanUsername.length < 2 || cleanUsername.length > 30) {
          return new Response(JSON.stringify({ error: 'Tên người dùng phải từ 2-30 ký tự hợp lệ' }), {
            status: 400,
            headers: responseHeaders
          });
        }

        if (!ALLOWED_DOMAINS.includes(domain)) {
          return new Response(JSON.stringify({ error: 'Tên miền không thuộc hệ thống PastelMail' }), {
            status: 400,
            headers: responseHeaders
          });
        }

        const fullEmail = `${cleanUsername}@${domain}`.toLowerCase();

        // Check duplicate
        const existing = await env.DB.prepare(`
          SELECT id FROM users WHERE LOWER(email) = ?
        `).bind(fullEmail).first();

        if (existing) {
          return new Response(JSON.stringify({ error: 'Email này đã tồn tại trên hệ thống. Vui lòng chọn tên khác!' }), {
            status: 409,
            headers: responseHeaders
          });
        }

        const userId = id || 'user-' + Date.now();
        await env.DB.prepare(`
          INSERT INTO users (id, email, username, domain, password_hash, mascot_name, mascot_avatar)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          userId,
          fullEmail,
          cleanUsername,
          domain,
          passwordHash,
          mascotName || 'Mascot',
          mascotAvatar || '/assets/mascot_luuvan.webp'
        ).run();

        // Generate Signed Token (Valid for 7 days)
        const exp = Date.now() + 7 * 24 * 3600 * 1000;
        const token = await signToken({ userId, email: fullEmail, username: cleanUsername, exp }, secretKey);

        const safeUser = {
          id: userId,
          email: fullEmail,
          username: cleanUsername,
          domain,
          mascotName: mascotName || 'Mascot',
          mascotAvatar: mascotAvatar || '/assets/mascot_luuvan.webp'
        };

        return new Response(JSON.stringify({ success: true, user: safeUser, token }), {
          headers: responseHeaders
        });
      }

      // -----------------------------------------------------------------------
      // Route: Login
      // -----------------------------------------------------------------------
      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        if (!checkRateLimit(clientIp, 20, 60000)) {
          return new Response(JSON.stringify({ error: 'Quá nhiều lần đăng nhập sai. Vui lòng chờ 1 phút!' }), {
            status: 429,
            headers: responseHeaders
          });
        }

        const { email, passwordHash } = await request.json();
        if (!email || !passwordHash) {
          return new Response(JSON.stringify({ error: 'Vui lòng cung cấp email và mật khẩu' }), {
            status: 400,
            headers: responseHeaders
          });
        }

        const user = await env.DB.prepare(`
          SELECT id, email, username, domain, password_hash, mascot_name, mascot_avatar, created_at
          FROM users WHERE LOWER(email) = LOWER(?)
        `).bind(email.trim()).first();

        if (!user || user.password_hash !== passwordHash) {
          return new Response(JSON.stringify({ error: 'Email hoặc mật khẩu không chính xác' }), {
            status: 401,
            headers: responseHeaders
          });
        }

        // Generate Signed Token
        const exp = Date.now() + 7 * 24 * 3600 * 1000;
        const token = await signToken({ userId: user.id, email: user.email, username: user.username, exp }, secretKey);

        // Sanitize output (never leak password_hash)
        const safeUser = {
          id: user.id,
          email: user.email,
          username: user.username,
          domain: user.domain,
          mascotName: user.mascot_name,
          mascotAvatar: user.mascot_avatar,
          createdAt: user.created_at
        };

        return new Response(JSON.stringify({ success: true, user: safeUser, token }), {
          headers: responseHeaders
        });
      }

      // -----------------------------------------------------------------------
      // Route: Get emails (Strict Token Authorization Required)
      // -----------------------------------------------------------------------
      if (url.pathname === '/api/emails' && request.method === 'GET') {
        const email = url.searchParams.get('email');
        if (!email) {
          return new Response(JSON.stringify({ error: 'Thiếu thông số email' }), {
            status: 400,
            headers: responseHeaders
          });
        }

        // Verify Bearer Token
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();
        const payload = await verifyToken(token, secretKey);

        const payloadUsername = payload?.username || (payload?.email ? payload.email.split('@')[0] : '');
        const reqUsername = email.trim().toLowerCase().split('@')[0];
        const reqDomain = email.trim().toLowerCase().split('@')[1];

        // Authorized if exact match OR matching username across any ecosystem domain
        const isAuthorized = payload && (
          payload.email.toLowerCase() === email.trim().toLowerCase() ||
          (payloadUsername.toLowerCase() === reqUsername.toLowerCase() && ALLOWED_DOMAINS.includes(reqDomain))
        );

        if (!isAuthorized) {
          return new Response(JSON.stringify({ error: 'Phiên làm việc không hợp lệ hoặc đã hết hạn. Vui lòng đăng nhập lại!' }), {
            status: 401,
            headers: responseHeaders
          });
        }

        const usernamePrefix = reqUsername + '@%';
        const results = await env.DB.prepare(`
          SELECT id, user_id, recipient_email, sender_name, sender_email, sender_avatar, subject, snippet, body_html, folder, is_read, is_starred, tag, tag_color, created_at
          FROM emails 
          WHERE (user_id = ? AND user_id IS NOT NULL AND user_id != '')
             OR LOWER(recipient_email) = LOWER(?)
             OR (LOWER(sender_email) = LOWER(?) AND folder = 'sent')
             OR (LOWER(recipient_email) LIKE LOWER(?))
          ORDER BY created_at DESC
        `).bind(payload.id || '', email.trim(), email.trim(), usernamePrefix).all();

        return new Response(JSON.stringify({ emails: results.results || [] }), {
          headers: responseHeaders
        });
      }

      // -----------------------------------------------------------------------
      // Route: Send / Create email (Single or Multi-Recipient)
      // -----------------------------------------------------------------------
      if (url.pathname === '/api/emails/send' && request.method === 'POST') {
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.replace(/^Bearer\s+/i, '').trim();
        const payload = await verifyToken(token, secretKey);

        if (!payload) {
          return new Response(JSON.stringify({ error: 'Chưa đăng nhập hoặc phiên hết hạn' }), {
            status: 401,
            headers: responseHeaders
          });
        }

        const body = await request.json();
        const { to, recipients, subject, content, fromEmail } = body;

        const payloadUsername = payload.username || (payload.email ? payload.email.split('@')[0] : '');
        let activeSenderEmail = payload.email;
        if (fromEmail && typeof fromEmail === 'string' && fromEmail.includes('@')) {
          const fDomain = fromEmail.split('@')[1].toLowerCase();
          const fUser = fromEmail.split('@')[0].toLowerCase();
          if (ALLOWED_DOMAINS.includes(fDomain) && fUser === payloadUsername.toLowerCase()) {
            activeSenderEmail = fromEmail.toLowerCase();
          }
        }

        // Parse and deduplicate all recipients
        let targetList = [];
        if (Array.isArray(recipients) && recipients.length > 0) {
          targetList = recipients.map(r => String(r).toLowerCase().trim());
        } else if (typeof to === 'string') {
          const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
          targetList = (to.match(emailRegex) || []).map(r => r.toLowerCase().trim());
        }
        targetList = Array.from(new Set(targetList));

        if (targetList.length === 0 || !subject) {
          return new Response(JSON.stringify({ error: 'Vui lòng cung cấp ít nhất một địa chỉ email người nhận hợp lệ và tiêu đề thư' }), {
            status: 400,
            headers: responseHeaders
          });
        }

        const mailId = 'outbound-' + Date.now();
        const safeSubject = escapeHtml(subject);
        const safeSnippet = escapeHtml(content ? content.substring(0, 80) : '') + '...';
        const safeBody = `<div style="padding: 16px; font-family: sans-serif; line-height: 1.6;">${escapeHtml(content).replace(/\n/g, '<br>')}</div>`;
        const toDisplay = targetList.join(', ');

        // 1. Record sent email in sender's Outbox
        await env.DB.prepare(`
          INSERT INTO emails (id, user_id, recipient_email, sender_name, sender_email, subject, snippet, body_html, folder, is_read)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sent', 1)
        `).bind(
          mailId,
          payload.userId,
          toDisplay,
          payloadUsername,
          activeSenderEmail,
          safeSubject,
          safeSnippet,
          safeBody
        ).run();

        // 2. Direct internal delivery: If recipient exists in D1, drop mail directly into their inbox
        let internalDeliveredCount = 0;
        for (const rcpt of targetList) {
          const destUser = await env.DB.prepare(`
            SELECT id FROM users WHERE LOWER(email) = ?
          `).bind(rcpt).first();

          if (destUser) {
            const inboundId = 'inbound-internal-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
            await env.DB.prepare(`
              INSERT INTO emails (id, user_id, recipient_email, sender_name, sender_email, subject, snippet, body_html, folder, is_read)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'inbox', 0)
            `).bind(
              inboundId,
              destUser.id,
              rcpt,
              payload.email.split('@')[0],
              payload.email,
              safeSubject,
              safeSnippet,
              safeBody
            ).run();
            internalDeliveredCount++;
          }
        }

        // 3. Outbound Internet Relay (to external Gmail, Outlook, Yahoo, etc.)
        let externalRelaySuccess = false;
        let externalNotice = '';
        const externalRecipients = targetList.filter(rcpt => !ALLOWED_DOMAINS.some(d => rcpt.endsWith('@' + d)));

        if (externalRecipients.length > 0) {
          const rawKeys = env.RESEND_API_KEYS || env.RESEND_API_KEY || '';
          let keyMap = {};
          try {
            if (rawKeys.trim().startsWith('{')) {
              keyMap = JSON.parse(rawKeys);
            }
          } catch {}

          const allKeyList = rawKeys.split(/["',;\s]+/).map(k => k.trim()).filter(k => k.startsWith('re_'));
          const senderDomain = activeSenderEmail.split('@')[1]?.toLowerCase() || '';
          const dedicatedKey = keyMap[senderDomain];

          // Prioritize dedicated domain key, then fall back to remaining keys
          const candidateKeys = dedicatedKey
            ? [dedicatedKey, ...allKeyList.filter(k => k !== dedicatedKey)]
            : allKeyList;

          if (candidateKeys.length > 0) {
            const senderDisplayName = payload.username || payload.email.split('@')[0];
            let lastErrorMsg = '';

            for (const apiKey of candidateKeys) {
              try {
                const res = await fetch('https://api.resend.com/emails', {
                  method: 'POST',
                  headers: {
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Type': 'application/json'
                  },
                  body: JSON.stringify({
                    from: `${senderDisplayName} <${activeSenderEmail}>`,
                    to: externalRecipients,
                    subject: safeSubject,
                    html: safeBody
                  })
                });

                if (res.ok) {
                  externalRelaySuccess = true;
                  externalNotice = `Đã chuyển tiếp thư thật tới ${externalRecipients.length} hòm thư ngoài internet!`;
                  break; // Succeeded with this key, stop pool iteration
                } else {
                  const resendErr = await res.text();
                  console.warn(`Resend key ${apiKey.substring(0, 8)}... error:`, resendErr);
                  try {
                    const errJson = JSON.parse(resendErr);
                    lastErrorMsg = errJson.message || 'Lỗi gửi từ Resend';
                  } catch {
                    lastErrorMsg = 'Lỗi gửi từ Resend';
                  }
                  // Continue to next backup key if available
                }
              } catch (rErr) {
                console.warn(`Outbound relay exception on key ${apiKey.substring(0, 8)}...:`, rErr);
                lastErrorMsg = rErr.message;
              }
            }

            if (!externalRelaySuccess) {
              externalNotice = lastErrorMsg || 'Chưa chuyển tiếp được tới hòm thư ngoài do cấu hình Resend.';
            }
          } else {
            externalNotice = 'Thư đã lưu trong mục Đã gửi. Để gửi thật tới Gmail người ngoài, cần gắn RESEND_API_KEY trên Cloudflare.';
          }
        }

        return new Response(JSON.stringify({
          success: true,
          id: mailId,
          recipientsCount: targetList.length,
          internalDelivered: internalDeliveredCount,
          externalRecipientsCount: externalRecipients.length,
          externalRelaySuccess,
          notice: externalNotice,
          recipients: targetList
        }), {
          headers: responseHeaders
        });
      }

      return new Response(JSON.stringify({ error: 'Đường dẫn không tồn tại' }), {
        status: 404,
        headers: responseHeaders
      });
    } catch (err) {
      console.error('API Server Error:', err);
      return new Response(JSON.stringify({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau!' }), {
        status: 500,
        headers: responseHeaders
      });
    }
  },

  // 2. Cloudflare Inbound Email Routing Handler
  async email(message, env, ctx) {
    try {
      const recipient = message.to.toLowerCase();
      const sender = message.from;
      const subject = message.headers.get('subject') || '(Không có tiêu đề)';
      
      // Read raw email stream
      const rawBody = await new Response(message.raw).text();
      const parsed = extractCleanEmailContent(rawBody);

      const recipientUserPart = recipient.split('@')[0].toLowerCase();
      const recipientDomain = recipient.split('@')[1].toLowerCase();

      // Find recipient user by full email or username
      let user = await env.DB.prepare(`
        SELECT id, email, username FROM users WHERE LOWER(email) = ?
      `).bind(recipient).first();

      if (!user && ALLOWED_DOMAINS.includes(recipientDomain)) {
        user = await env.DB.prepare(`
          SELECT id, email, username FROM users WHERE LOWER(username) = ?
        `).bind(recipientUserPart).first();
      }

      // If user not specifically registered yet, fallback to primary admin or first registered user
      // so no incoming email is ever lost!
      if (!user) {
        user = await env.DB.prepare(`SELECT id, email, username FROM users ORDER BY created_at ASC LIMIT 1`).first();
      }

      const userId = user ? user.id : 'inbound-guest';
      const mailId = 'inbound-' + Date.now() + '-' + Math.random().toString(36).substring(2, 6);
      const decodedSubject = decodeMimeWord(subject);
      const safeSubject = escapeHtml(decodedSubject);
      const rawSenderName = sender.split('<')[0].trim().replace(/^"/, '').replace(/"$/, '') || sender;
      const decodedSenderName = decodeMimeWord(rawSenderName);
      const senderDisplayName = escapeHtml(decodedSenderName);

      await env.DB.prepare(`
        INSERT INTO emails (id, user_id, recipient_email, sender_name, sender_email, subject, snippet, body_html, folder, is_read, tag, tag_color)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'inbox', 0, 'Hộp thư đến', '#ec4899')
      `).bind(
        mailId,
        userId,
        recipient,
        senderDisplayName,
        sender,
        safeSubject,
        parsed.snippet,
        parsed.html
      ).run();

      console.log(`Inbound email received successfully: to=${recipient}, id=${mailId}`);
    } catch (err) {
      console.error('Email handling error:', err);
    }
  }
};
