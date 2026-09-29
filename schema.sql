-- PastelMail Cloudflare D1 Database Schema
-- Run via: wrangler d1 execute pastelmail-db --file=schema.sql

-- 1. Bảng Tài Khoản Người Dùng (Users)
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    domain TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    mascot_name TEXT NOT NULL,
    mascot_avatar TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. Bảng Hộp Thư Email (Emails)
CREATE TABLE IF NOT EXISTS emails (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    recipient_email TEXT NOT NULL,
    sender_name TEXT NOT NULL,
    sender_email TEXT NOT NULL,
    sender_avatar TEXT DEFAULT '✉️',
    subject TEXT NOT NULL,
    snippet TEXT,
    body_html TEXT NOT NULL,
    folder TEXT DEFAULT 'inbox', -- inbox, sent, drafts, trash
    is_read BOOLEAN DEFAULT 0,
    is_starred BOOLEAN DEFAULT 0,
    tag TEXT DEFAULT 'Chung',
    tag_color TEXT DEFAULT '#6366f1',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_emails_recipient ON emails(recipient_email);
CREATE INDEX IF NOT EXISTS idx_emails_folder ON emails(user_id, folder);
