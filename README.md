# Lưu Vân Mail (PastelMail) ✨

> Dịch vụ Webmail đa miền phong cách Pastel Kawaii 2026, hỗ trợ đăng ký, bảo mật tài khoản, soạn/nhận thư với 4 tên miền riêng và 5 linh vật biểu trưng.

## 🌐 Các Tên Miền Đang Hoạt Động (Production)
* 📖 **[luuvan.online](https://luuvan.online)** (Tên miền chính - Mèo Học Giả Luna)
* 💼 **[aetherix.site](https://aetherix.site)** (AI & Công nghệ - Mèo Hoàng Tử Aether)
* 💰 **[chotroi.site](https://chotroi.site)** (Sàn giao dịch MMO - Gấu Đầu Bếp Kuma)
* 🎮 **[aadidass.tokyo](https://aadidass.tokyo)** (Game & Giải trí - Thỏ Cà Rốt Midori)

## 🏛️ Kiến Trúc Hệ Thống
* **Frontend**: HTML5, Modern CSS (OKLCH, Bento Grid), Vanilla ES Modules, Vite, Canvas Confetti.
* **Cổng Xác Thực (Auth Gate)**: Đăng ký & Đăng nhập bắt buộc với mã hóa mật khẩu SHA-256 Web Crypto API.
* **Database**: Cloudflare D1 (SQLite Serverless) lưu trữ `users` và `emails`.
* **Backend**: Cloudflare Worker xử lý API và bắt sự kiện Cloudflare Email Routing.
* **CDN & Edge**: Cloudflare Pages / Workers Edge toàn cầu.

## 🚀 Hướng Dẫn Phát Triển Cục Bộ
```bash
# Cài đặt thư viện
npm install

# Khởi chạy dev server
npm run dev

# Đóng gói bản production
npm run build

# Triển khai lên Cloudflare
npx wrangler deploy
```

## 📄 Bản Quyền
Dự án được bảo chứng bởi hệ sinh thái Cloudflare Edge & D1.
Tài khoản quản trị: `phamnguyenvinhloc.2@gmail.com`
