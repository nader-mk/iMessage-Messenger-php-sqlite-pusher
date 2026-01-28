# iMessage-Messenger-php-sqlite-pusher
# Developed by Nader Mahbub Khan &copy;2026

A modern, secure, and real-time messaging application built with a single PHP file (`index.php`).

## Overview

Messages is a self-contained chat application designed for simplicity and security. It bundles the backend API (PHP), frontend (Vue.js), and database schema (SQLite) into a single file, making it incredibly easy to deploy.

## Features

- **Single File Architecture**: The entire application logic resides in `index.php`.
- **Real-Time Messaging**: Instant delivery and typing indicators powered by Pusher (see [PUSHER_GUIDE.md](PUSHER_GUIDE.md)).
- **Secure Encryption**: Messages are encrypted at rest using Sodium (preferred) or OpenSSL AES-256-GCM.
- **Modern UI**: A responsive, dark-mode interface built with Vue.js 3.
- **Admin Panel**: Comprehensive tools for user management, moderation, custom themes, and fonts.
- **Zero Heavy Dependencies**: Runs on standard PHP hosting without Composer (unless extending).

## Prerequisites

- PHP 8.0 or higher
- SQLite3 extension (`pdo_sqlite`)
- OpenSSL or Sodium extension
- Web server (Apache, Nginx) or PHP built-in server

## Setup

1. **Download**
   Clone the repository or download the files. Ensure `index.php`, `pusher.php`, and `.env.example` are present.

2. **Configuration**
   Copy the example configuration file:

   ```bash
   cp .env.example .env
   ```

   Edit `.env` to set your `JWT_SECRET` and optionally your Pusher credentials for real-time features.

   > **Note**: If Pusher is not configured, the app automatically falls back to HTTP polling.

3. **Start the Server**
   For local development:

   ```bash
   php -S localhost:8000
   ```

   Access the app at `http://localhost:8000`.

## Usage

### User Registration

Simply open the app and click "Register".

### Test Data (Development Only)

If `TEST_MODE=true` is set in your `.env`, you can seed the database with test users:

```bash
curl -X POST http://localhost:8000/api/_test/seed
```

This creates:

- `testuser1` / `password123`
- `testuser2` / `password123`
- `testadmin` / `admin123` (Admin Access)

## Admin Access

Admin users have access to a special panel for:

- Viewing and banning users
- Managing verification requests
- Customizing themes and fonts
- Moderating reports

To make a user an admin manually (if not using seed data), you will need to update the `is_admin` flag in the `users` table of `data/chat.sqlite`.

## Directory Structure

- `index.php`: The main application entry point (Backend + Frontend).
- `pusher.php`: Lightweight Pusher client library.
- `data/`: Directory where the SQLite database (`chat.sqlite`) and encryption keys are stored.
- `PUSHER_GUIDE.md`: Detailed documentation for real-time features.

## License

MIT

