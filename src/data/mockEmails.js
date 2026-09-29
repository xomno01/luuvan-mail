export const defaultEmails = [
  // Emails for @aadidass.tokyo (Game & Entertainment)
  {
    id: 'mail-1',
    domain: 'aadidass.tokyo',
    folder: 'inbox',
    starred: true,
    read: false,
    senderName: 'Steam Support',
    senderEmail: 'noreply@steampowered.com',
    senderAvatar: '🎮',
    subject: 'Mã xác thực Steam Guard cho tài khoản của bạn',
    snippet: 'Mã đăng nhập Steam Guard của bạn là 84920. Nếu bạn không yêu cầu mã này...',
    tag: 'Game',
    tagColor: '#10b981',
    date: '10:42 AM',
    timestamp: Date.now() - 1000 * 60 * 15,
    body: `
      <div style="background: #f8fafc; padding: 24px; border-radius: 16px; border: 1px solid #e2e8f0; font-family: sans-serif;">
        <h3 style="color: #0f172a; margin-bottom: 12px; font-size: 1.2rem;">Yêu cầu đăng nhập từ Steam</h3>
        <p style="color: #475569; line-height: 1.6; margin-bottom: 20px;">
          Xin chào! Chúng tôi nhận được yêu cầu đăng nhập vào tài khoản Steam của bạn bằng địa chỉ email này.
        </p>
        <div style="background: #e0f2fe; padding: 18px; border-radius: 12px; text-align: center; margin-bottom: 20px;">
          <span style="font-size: 0.85rem; color: #0369a1; text-transform: uppercase; letter-spacing: 1px; font-weight: 700;">Mã xác thực Steam Guard</span>
          <div style="font-size: 2.2rem; font-weight: 800; color: #0284c7; letter-spacing: 6px; margin-top: 6px;">84920</div>
        </div>
        <p style="color: #64748b; font-size: 0.85rem;">
          Mã này có hiệu lực trong vòng 15 phút. Tuyệt đối không chia sẻ mã này cho bất kỳ ai.
        </p>
      </div>
    `
  },
  {
    id: 'mail-2',
    domain: 'aadidass.tokyo',
    folder: 'inbox',
    starred: false,
    read: true,
    senderName: 'Riot Games',
    senderEmail: 'riotgames@account.riotgames.com',
    senderAvatar: '⚔️',
    subject: 'Chào mừng tân binh đến với vũ trụ VALORANT & LMHT!',
    snippet: 'Tài khoản Riot ID của bạn đã kích hoạt thành công. Đăng nhập ngay nhận quà...',
    tag: 'Game',
    tagColor: '#10b981',
    date: 'Hôm qua',
    timestamp: Date.now() - 1000 * 60 * 60 * 20,
    body: `
      <div style="background: #fff1f2; padding: 24px; border-radius: 16px; border: 1px solid #fecdd3; font-family: sans-serif;">
        <h3 style="color: #9f1239; margin-bottom: 12px;">Chào mừng bạn đến với Riot Games!</h3>
        <p style="color: #4c0519; line-height: 1.6; margin-bottom: 16px;">
          Cảm ơn bạn đã lựa chọn email phong cách Tokyo để đồng hành trên mọi chiến trường xếp hạng.
        </p>
        <div style="padding: 16px; background: white; border-radius: 12px; border: 1px dashed #f43f5e; margin-bottom: 16px;">
          🎁 <strong>Quà tân thủ:</strong> Gói thẻ mở khóa Đặc Vụ cấp tốc + 1 Khung Avatar Tokyo Harajuku.
        </div>
        <p style="color: #881337; font-size: 0.88rem;">Hẹn gặp lại bạn trên Đấu Trường Công Lý!</p>
      </div>
    `
  },

  // Emails for @chotroi.site (MMO & Trading)
  {
    id: 'mail-3',
    domain: 'chotroi.site',
    folder: 'inbox',
    starred: true,
    read: false,
    senderName: 'Hệ Thống Chợ Trời Escrow',
    senderEmail: 'trunggian@chotroi.site',
    senderAvatar: '🍯',
    subject: 'Xác nhận khớp lệnh giao dịch an toàn #CT-99823',
    snippet: 'Tiền đã vào ví bảo lãnh trung gian thành công. Bên bán vui lòng bàn giao tài nguyên...',
    tag: 'Giao dịch',
    tagColor: '#d97706',
    date: '09:15 AM',
    timestamp: Date.now() - 1000 * 60 * 90,
    body: `
      <div style="background: #fffbeb; padding: 24px; border-radius: 16px; border: 1px solid #fde68a; font-family: sans-serif;">
        <h3 style="color: #92400e; margin-bottom: 12px;">Thông Báo Giao Dịch Trung Gian #CT-99823</h3>
        <p style="color: #78350f; line-height: 1.6; margin-bottom: 16px;">
          Bác Gấu Kuma thông báo: Người mua đã nạp đủ <strong>2.500.000 VNĐ</strong> vào quỹ bảo chứng Chợ Trời.
        </p>
        <ul style="color: #92400e; margin-bottom: 20px; line-height: 1.8; padding-left: 20px;">
          <li><strong>Sản phẩm:</strong> Trọn bộ 50 Profile tài khoản MMO sạch.</li>
          <li><strong>Thời hạn nghiệm thu:</strong> 24 giờ kể từ khi bàn giao.</li>
          <li><strong>Bảo lãnh:</strong> Hoàn tiền 100% nếu có lỗi từ người bán.</li>
        </ul>
        <button style="background: #d97706; color: white; border: none; padding: 12px 24px; border-radius: 8px; font-weight: 700; cursor: pointer;">
          Bàn Giao Sản Phẩm Ngay
        </button>
      </div>
    `
  },
  {
    id: 'mail-4',
    domain: 'chotroi.site',
    folder: 'inbox',
    starred: false,
    read: true,
    senderName: 'Khách Hàng Hoàng Nam',
    senderEmail: 'namhoang.mmo@gmail.com',
    senderAvatar: '💼',
    subject: 'Hỏi mua thêm proxy và tool automation đợt 2',
    snippet: 'Đợt trước mua lô tài khoản dùng rất ổn định, đợt này bên shop còn slot proxy dân cư không?',
    tag: 'Khách hàng',
    tagColor: '#d97706',
    date: '28 Th09',
    timestamp: Date.now() - 1000 * 60 * 60 * 28,
    body: `
      <div style="padding: 20px; font-family: sans-serif; line-height: 1.6; color: #334155;">
        <p>Chào shop,</p>
        <p>Hôm trước mình có mua thử lô acc bên shop trên Chợ Trời dùng nuôi kênh rất mượt, trust tốt không bị checkpoint.</p>
        <p>Đợt này mình cần nhập thêm tầm 100 acc và 20 port proxy IPv4 tĩnh sạch để chạy đa luồng. Shop có giá ưu đãi cho khách cũ không, báo mình sớm nhé!</p>
        <p style="margin-top: 20px;">Trân trọng,<br><strong>Hoàng Nam</strong></p>
      </div>
    `
  },

  // Emails for @aetherix.site (AI & Cloud)
  {
    id: 'mail-5',
    domain: 'aetherix.site',
    folder: 'inbox',
    starred: true,
    read: false,
    senderName: 'Cloudflare Notifications',
    senderEmail: 'no-reply@cloudflare.com',
    senderAvatar: '☁️',
    subject: '[Aetherix] Định tuyến Email Routing & DNS đã kích hoạt',
    snippet: 'Bản ghi SPF và MX của bạn đã hoàn tất kích hoạt trên mạng lưới toàn cầu...',
    tag: 'Cloudflare',
    tagColor: '#6366f1',
    date: '08:30 AM',
    timestamp: Date.now() - 1000 * 60 * 120,
    body: `
      <div style="background: #eef2ff; padding: 24px; border-radius: 16px; border: 1px solid #c7d2fe; font-family: sans-serif;">
        <h3 style="color: #3730a3; margin-bottom: 12px;">Dịch vụ Cloudflare Email Routing đã sẵn sàng</h3>
        <p style="color: #4338ca; line-height: 1.6; margin-bottom: 16px;">
          Tên miền <strong>aetherix.site</strong> đã được cấu hình hoàn tất với các bản ghi DNS tiêu chuẩn:
        </p>
        <div style="background: white; padding: 14px; border-radius: 10px; font-family: monospace; font-size: 0.85rem; color: #1e1b4b; margin-bottom: 16px;">
          MX ➔ route1.mx.cloudflare.net (Priority 10)<br>
          TXT ➔ v=spf1 include:_spf.mx.cloudflare.net include:_spf.google.com ~all
        </div>
        <p style="color: #4338ca; font-size: 0.9rem;">Toàn bộ thư gửi đến đều được mã hóa TLS và bảo vệ chống thư rác tự động.</p>
      </div>
    `
  },
  {
    id: 'mail-6',
    domain: 'aetherix.site',
    folder: 'inbox',
    starred: false,
    read: true,
    senderName: 'OpenAI Developer Platform',
    senderEmail: 'support@openai.com',
    senderAvatar: '🤖',
    subject: 'Nâng cấp hạn ngạch API Tier 2 thành công',
    snippet: 'Tổ chức Aetherix AI của bạn hiện đã có thể gọi tối đa 5.000 RPM...',
    tag: 'AI Platform',
    tagColor: '#6366f1',
    date: '27 Th09',
    timestamp: Date.now() - 1000 * 60 * 60 * 48,
    body: `
      <div style="padding: 20px; font-family: sans-serif; line-height: 1.6; color: #334155;">
        <h3 style="color: #1e293b;">Hạn ngạch API của bạn đã được nâng cấp!</h3>
        <p>Chúc mừng đội ngũ Aetherix! Hạn ngạch tài khoản của bạn đã được mở rộng lên <strong>Tier 2</strong>.</p>
        <ul style="line-height: 1.8; margin-top: 12px;">
          <li>Mô hình hỗ trợ: GPT-4o, GPT-4o mini, o1-preview</li>
          <li>Giới hạn: 5.000 Requests/phút & 2.000.000 Tokens/phút</li>
        </ul>
        <p style="margin-top: 20px;">Cảm ơn bạn đã đồng hành cùng OpenAI!</p>
      </div>
    `
  },

  // Emails for @luuvan.online (Knowledge & Library)
  {
    id: 'mail-7',
    domain: 'luuvan.online',
    folder: 'inbox',
    starred: true,
    read: false,
    senderName: 'Lưu Vân Thư Quán',
    senderEmail: 'bantin@luuvan.online',
    senderAvatar: '📖',
    subject: 'Bản tin số 48: Nghệ thuật tự động hóa quy trình với Playwright & Stealth',
    snippet: 'Luna chia sẻ trọn bộ kỹ thuật bypass bot detection 2 lớp và quản lý session an toàn...',
    tag: 'Tri thức',
    tagColor: '#8b5cf6',
    date: '07:00 AM',
    timestamp: Date.now() - 1000 * 60 * 200,
    body: `
      <div style="background: #faf5ff; padding: 24px; border-radius: 16px; border: 1px solid #e9d5ff; font-family: sans-serif;">
        <h3 style="color: #6b21a8; margin-bottom: 12px;">Kỹ thuật Bypass Bot Detection 2026</h3>
        <p style="color: #581c87; line-height: 1.6; margin-bottom: 14px;">
          Chào các bạn độc giả Lưu Vân! Trong bài nghiên cứu tuần này, Mèo Luna mang đến giải pháp 2 tầng:
        </p>
        <ol style="color: #6b21a8; line-height: 1.8; padding-left: 20px; margin-bottom: 16px;">
          <li><strong>Tầng 1 (Nền tảng):</strong> Sử dụng plugin Stealth chống các dấu vân tay cơ bản.</li>
          <li><strong>Tầng 2 (Tùy biến):</strong> Random hóa màn hình, timezone, font và WebGL canvas.</li>
        </ol>
        <p style="color: #7e22ce; font-style: italic;">"Học để tự do, code để sáng tạo!"</p>
      </div>
    `
  }
];
