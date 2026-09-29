// PastelMail Cloudflare Worker Backend
// Handles API requests & Inbound Cloudflare Email Routing events

export default {
  // 1. HTTP API Handler
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Health check
      if (url.pathname === '/api/health') {
        return new Response(JSON.stringify({ status: 'ok', service: 'PastelMail API' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Check D1 binding
      if (!env.DB) {
        return new Response(JSON.stringify({ error: 'D1 Database not bound' }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Route: Register
      if (url.pathname === '/api/auth/register' && request.method === 'POST') {
        const body = await request.json();
        const { id, email, username, domain, passwordHash, mascotName, mascotAvatar } = body;

        await env.DB.prepare(`
          INSERT INTO users (id, email, username, domain, password_hash, mascot_name, mascot_avatar)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(id, email, username, domain, passwordHash, mascotName, mascotAvatar).run();

        return new Response(JSON.stringify({ success: true, user: { id, email, username, domain } }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Route: Login
      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        const { email, passwordHash } = await request.json();
        const user = await env.DB.prepare(`
          SELECT * FROM users WHERE LOWER(email) = LOWER(?)
        `).bind(email).first();

        if (!user || user.password_hash !== passwordHash) {
          return new Response(JSON.stringify({ error: 'Email hoặc mật khẩu không chính xác' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }

        return new Response(JSON.stringify({ success: true, user }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // Route: Get emails
      if (url.pathname === '/api/emails' && request.method === 'GET') {
        const email = url.searchParams.get('email');
        const results = await env.DB.prepare(`
          SELECT * FROM emails WHERE recipient_email = ? ORDER BY created_at DESC
        `).bind(email).all();

        return new Response(JSON.stringify({ emails: results.results }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      return new Response('Not Found', { status: 404, headers: corsHeaders });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  },

  // 2. Cloudflare Inbound Email Routing Handler
  async email(message, env, ctx) {
    try {
      const recipient = message.to.toLowerCase();
      const sender = message.from;
      const subject = message.headers.get('subject') || '(Không có tiêu đề)';
      
      // Read raw text
      const rawBody = await new Response(message.raw).text();
      
      // Check if recipient exists in D1
      const user = await env.DB.prepare(`
        SELECT id FROM users WHERE LOWER(email) = ?
      `).bind(recipient).first();

      if (user) {
        const mailId = 'inbound-' + Date.now();
        await env.DB.prepare(`
          INSERT INTO emails (id, user_id, recipient_email, sender_name, sender_email, subject, snippet, body_html, folder, is_read)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'inbox', 0)
        `).bind(
          mailId,
          user.id,
          recipient,
          sender.split('<')[0].trim() || sender,
          sender,
          subject,
          rawBody.substring(0, 100).replace(/\r?\n|\r/g, ' '),
          `<pre style="white-space: pre-wrap; font-family: sans-serif;">${rawBody}</pre>`
        ).run();
      }
    } catch (err) {
      console.error('Email handling error:', err);
    }
  }
};
