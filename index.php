<?php

declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

$envFile = __DIR__ . '/.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (strpos($line, '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            if (preg_match('/^"(.*)"$/', $value, $m) || preg_match("/^'(.*)'$/", $value, $m)) {
                $value = $m[1];
            }
            putenv("$key=$value");
        }
    }
}

$jwtSecret = getenv('JWT_SECRET');
if (!$jwtSecret && getenv('APP_ENV') !== 'development') {
    if (strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false) {
        header('Content-Type: application/json');
        http_response_code(500);
        echo json_encode(['error' => 'Server configuration error: JWT_SECRET not set']);
        exit;
    }
}
define('JWT_SECRET', $jwtSecret ?: 'dev-only-jwt-secret-not-for-production');
define('APP_KEY', getenv('APP_KEY') ?: '');

define('DATA_DIR', __DIR__ . '/data');
if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0700, true);
define('DB_PATH', DATA_DIR . '/chat.sqlite');
define('KEY_FILE', DATA_DIR . '/.encryption_key');
define('KEY_LOCK_FILE', DATA_DIR . '/.encryption_key.lock');
define('ACCESS_TOKEN_LIFETIME', 900);
define('REFRESH_TOKEN_LIFETIME', 604800);
define('REFRESH_TOKEN_GRACE_PERIOD', 30);

$testMode = getenv('TEST_MODE') === 'true';
$rateLimitMultiplier = $testMode ? 10 : 1;
define('RATE_LIMIT_REQUESTS', 60 * $rateLimitMultiplier);
define('RATE_LIMIT_WINDOW', 60);
define('RATE_LIMIT_POLL_REQUESTS', 180 * $rateLimitMultiplier);
define('RATE_LIMIT_POLL_WINDOW', 60);
define('MAX_MESSAGE_LENGTH', 2000);
define('MAX_USERNAME_LENGTH', 30);
define('MIN_USERNAME_LENGTH', 3);
define('MIN_PASSWORD_LENGTH', 8);
define('INVITE_TOKEN_LIFETIME', 86400);
define('POLL_MAX_MESSAGES', 100);

define('MIN_FONT_SCALE', 0.85);
define('MAX_FONT_SCALE', 1.4);

$pusherEnabled = false;
$pusher = null;

if (getenv('PUSHER_APP_ID') && getenv('PUSHER_KEY') && getenv('PUSHER_SECRET')) {
    require_once __DIR__ . '/pusher.php';
    try {
        $pusher = new PusherClient(
            getenv('PUSHER_APP_ID'),
            getenv('PUSHER_KEY'),
            getenv('PUSHER_SECRET'),
            getenv('PUSHER_CLUSTER') ?: 'us2'
        );
        $pusherEnabled = true;
    } catch (Exception $e) {
        error_log("Pusher initialization failed: " . $e->getMessage());
    }
}

function getPusher()
{
    global $pusher, $pusherEnabled;
    return $pusherEnabled ? $pusher : null;
}

function triggerPusherEvent(string $channel, string $event, array $data, ?string $socketId = null): bool
{
    $pusher = getPusher();
    if (!$pusher) return false;

    try {
        $pusher->trigger($channel, $event, $data, $socketId);
        return true;
    } catch (Exception $e) {
        error_log("Pusher event failed: " . $e->getMessage());
        return false;
    }
}

function getDb(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_TIMEOUT => 5
        ]);
        $pdo->exec('PRAGMA journal_mode=WAL');
        $pdo->exec('PRAGMA synchronous=NORMAL');
        $pdo->exec('PRAGMA foreign_keys=ON');
        $pdo->exec('PRAGMA busy_timeout=5000');
        $pdo->exec('PRAGMA temp_store=MEMORY');
        $pdo->exec('PRAGMA mmap_size=268435456');
    }
    return $pdo;
}

function safeExecute(PDOStatement $stmt, array $params = []): bool
{
    for ($i = 0; $i < 5; $i++) {
        try {
            $stmt->execute($params);
            $stmt->closeCursor();
            return true;
        } catch (PDOException $e) {
            if (strpos($e->getMessage(), 'database is locked') !== false) {
                usleep(100000);
                continue;
            }
            throw $e;
        }
    }
    error_log('safeExecute: DB remained locked after 5 retries');
    return false;
}

function initDb(): void
{
    $db = getDb();
    $db->exec("CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL COLLATE NOCASE,
        pass_hash TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        is_blocked INTEGER DEFAULT 0,
        is_verified INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        mute_until TEXT,
        ban_until TEXT,
        font_scale REAL DEFAULT 1.0,
        theme_id INTEGER,
        font_id INTEGER DEFAULT 1,
        last_active_at TEXT
    )");
    try {
        $db->exec("ALTER TABLE users ADD COLUMN last_active_at TEXT");
    } catch (PDOException $e) {
    }
    $db->exec("CREATE TABLE IF NOT EXISTS convos(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT DEFAULT 'dm',
        created_at TEXT DEFAULT (datetime('now'))
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS convo_members(
        convo_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        joined_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY(convo_id, user_id),
        FOREIGN KEY(convo_id) REFERENCES convos(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        convo_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        body_enc BLOB NOT NULL,
        nonce BLOB NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        delivered_at TEXT,
        deleted INTEGER DEFAULT 0,
        FOREIGN KEY(convo_id) REFERENCES convos(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS message_reads(
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        read_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY(message_id, user_id),
        FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS message_reactions(
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        reaction TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY(message_id, user_id),
        FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS refresh_tokens(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        family_id TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        ip TEXT,
        ua TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS invite_jti(
        jti TEXT PRIMARY KEY,
        convo_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        used_at TEXT,
        FOREIGN KEY(convo_id) REFERENCES convos(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS rate_limits(
        key TEXT PRIMARY KEY,
        window_start INTEGER NOT NULL,
        count INTEGER NOT NULL DEFAULT 1
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_user_id INTEGER NOT NULL,
        reported_user_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(reporter_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(reported_user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS admin_actions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user_id INTEGER NOT NULL,
        target_user_id INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        action_note TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS banned_words(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        word TEXT UNIQUE NOT NULL COLLATE NOCASE,
        penalty_type TEXT NOT NULL,
        penalty_duration INTEGER,
        created_by_admin INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS themes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        definition_json TEXT NOT NULL,
        created_by_admin INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        is_active INTEGER DEFAULT 0
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS verification_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS support_messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        created_by_admin INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )");
    $db->exec("CREATE TABLE IF NOT EXISTS support_reads(
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        read_at TEXT DEFAULT (datetime('now')),
        PRIMARY KEY(message_id, user_id),
        FOREIGN KEY(message_id) REFERENCES support_messages(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_messages_convo ON messages(convo_id, created_at)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_convo_members_user ON convo_members(user_id)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id)");

    $db->exec("CREATE TABLE IF NOT EXISTS fonts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        css_value TEXT NOT NULL,
        import_url TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )");

    $fontCount = $db->query("SELECT COUNT(*) FROM fonts")->fetchColumn();
    if ($fontCount == 0) {
        $defaultFonts = [
            ['System UI', "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', system-ui, sans-serif", null],
            ['Inter', "'Inter', system-ui, sans-serif", "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap"],
            ['Poppins', "'Poppins', system-ui, sans-serif", "https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600&display=swap"],
            ['Roboto', "'Roboto', system-ui, sans-serif", "https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap"],
            ['Serif', "Georgia, 'Times New Roman', serif", null]
        ];
        $stmt = $db->prepare("INSERT INTO fonts(name, css_value, import_url) VALUES(?, ?, ?)");
        foreach ($defaultFonts as $f) $stmt->execute($f);
    }

    $columns = $db->query("PRAGMA table_info(users)")->fetchAll();
    $columnNames = array_column($columns, 'name');
    if (!in_array('font_scale', $columnNames)) {
        $db->exec("ALTER TABLE users ADD COLUMN font_scale REAL DEFAULT 1.0");
    }
    if (!in_array('theme_id', $columnNames)) {
        $db->exec("ALTER TABLE users ADD COLUMN theme_id INTEGER");
    }
    if (!in_array('font_id', $columnNames)) {
        $db->exec("ALTER TABLE users ADD COLUMN font_id INTEGER");
        $db->exec("UPDATE users SET font_id = 1");
    }
}

if (extension_loaded('sodium')) {
    define('USE_SODIUM', true);
    define('CRYPTO_KEY_BYTES', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    define('CRYPTO_NONCE_BYTES', SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
} else {
    define('USE_SODIUM', false);
    define('CRYPTO_KEY_BYTES', 32);
    define('CRYPTO_NONCE_BYTES', 12);
}

function getEncryptionKey(): string
{
    if (APP_KEY !== '') {
        $decoded = base64_decode(APP_KEY, true);
        if ($decoded !== false && strlen($decoded) === CRYPTO_KEY_BYTES) {
            return $decoded;
        }
    }
    if (file_exists(KEY_FILE)) {
        $key = file_get_contents(KEY_FILE);
        if ($key !== false && strlen($key) === CRYPTO_KEY_BYTES) {
            return $key;
        }
    }
    $lockFile = KEY_LOCK_FILE;
    $fp = fopen($lockFile, 'c+');
    if ($fp === false) {
        throw new RuntimeException('Cannot create encryption key lock file');
    }
    try {
        if (!flock($fp, LOCK_EX)) {
            throw new RuntimeException('Cannot acquire encryption key lock');
        }
        if (file_exists(KEY_FILE)) {
            $key = file_get_contents(KEY_FILE);
            if ($key !== false && strlen($key) === CRYPTO_KEY_BYTES) {
                return $key;
            }
        }
        if (USE_SODIUM) {
            $key = sodium_crypto_secretbox_keygen();
        } else {
            $key = random_bytes(CRYPTO_KEY_BYTES);
        }
        $tempFile = KEY_FILE . '.tmp.' . getmypid();
        if (file_put_contents($tempFile, $key) === false) {
            throw new RuntimeException('Cannot write encryption key');
        }
        chmod($tempFile, 0600);
        if (!rename($tempFile, KEY_FILE)) {
            @unlink($tempFile);
            throw new RuntimeException('Cannot finalize encryption key');
        }
        return $key;
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}

function encryptMessage(string $plaintext): array
{
    $key = getEncryptionKey();
    $nonce = random_bytes(CRYPTO_NONCE_BYTES);
    if (USE_SODIUM) {
        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);
    } else {
        $tag = '';
        $encrypted = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        $ciphertext = $tag . $encrypted;
    }
    if (function_exists('sodium_memzero')) {
        sodium_memzero($key);
    } else {
        $key = '';
    }
    return ['enc' => $ciphertext, 'nonce' => $nonce];
}

function decryptMessage(string $ciphertext, string $nonce): ?string
{
    if (empty($ciphertext) || empty($nonce) || strlen($nonce) !== CRYPTO_NONCE_BYTES) {
        return null;
    }
    $key = getEncryptionKey();
    if (USE_SODIUM) {
        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
    } else {
        $tagLength = 16;
        if (strlen($ciphertext) <= $tagLength) {
            $plaintext = false;
        } else {
            $tag = substr($ciphertext, 0, $tagLength);
            $rawCipher = substr($ciphertext, $tagLength);
            $plaintext = openssl_decrypt($rawCipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        }
    }
    if (function_exists('sodium_memzero')) {
        sodium_memzero($key);
    } else {
        $key = '';
    }
    return $plaintext !== false ? $plaintext : null;
}

function base64UrlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64UrlDecode(string $data): string
{
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

function createJwt(array $payload): string
{
    $header = base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload['iat'] = $payload['iat'] ?? time();
    $payload['jti'] = $payload['jti'] ?? bin2hex(random_bytes(16));
    $payloadEncoded = base64UrlEncode(json_encode($payload));
    $signature = base64UrlEncode(hash_hmac('sha256', "$header.$payloadEncoded", JWT_SECRET, true));
    return "$header.$payloadEncoded.$signature";
}

function verifyJwt(string $token): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$header, $payload, $signature] = $parts;
    $expectedSig = base64UrlEncode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
    if (!hash_equals($expectedSig, $signature)) return null;
    $data = json_decode(base64UrlDecode($payload), true);
    if (!is_array($data) || !isset($data['exp']) || $data['exp'] < time()) return null;
    return $data;
}

function checkRateLimit(string $key, int $maxRequests = RATE_LIMIT_REQUESTS, int $window = RATE_LIMIT_WINDOW): bool
{
    try {
        $db = getDb();
        $now = time();
        $windowStart = $now - $window;

        $db->exec("PRAGMA busy_timeout=250");

        $stmt = $db->prepare("SELECT window_start, count FROM rate_limits WHERE key = ?");
        $stmt->execute([$key]);
        $row = $stmt->fetch();

        $db->exec("PRAGMA busy_timeout=5000");

        if (!$row || $row['window_start'] < $windowStart) {
            $db->prepare("INSERT OR REPLACE INTO rate_limits(key, window_start, count) VALUES(?, ?, 1)")->execute([$key, $now]);
            header("X-RateLimit-Limit: $maxRequests");
            header("X-RateLimit-Remaining: " . ($maxRequests - 1));
            header("X-RateLimit-Reset: " . ($now + $window));
            return true;
        }

        $remaining = max(0, $maxRequests - $row['count'] - 1);
        header("X-RateLimit-Limit: $maxRequests");
        header("X-RateLimit-Remaining: $remaining");
        header("X-RateLimit-Reset: " . ($row['window_start'] + $window));

        if ($row['count'] >= $maxRequests) return false;
        $db->prepare("UPDATE rate_limits SET count = count + 1 WHERE key = ?")->execute([$key]);
        return true;
    } catch (PDOException $e) {
        error_log("Rate limit (Write) bypassed due to lock: " . $e->getMessage());
        return true;
    }
}

function checkRateLimitReadOnly(string $key, int $maxRequests = RATE_LIMIT_REQUESTS, int $window = RATE_LIMIT_WINDOW): bool
{
    try {
        $db = getDb();
        $now = time();
        $windowStart = $now - $window;

        $stmt = $db->prepare("SELECT window_start, count FROM rate_limits WHERE key = ?");
        $stmt->execute([$key]);
        $row = $stmt->fetch();

        if (!$row || $row['window_start'] < $windowStart) return true;
        return $row['count'] < $maxRequests;
    } catch (PDOException $e) {
        error_log("Rate limit (Read) bypassed due to lock: " . $e->getMessage());
        return true;
    }
}

function jsonResponse(array $data, int $code = 200): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function getClientIp(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function getAuthUser(): ?array
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/i', $header, $m)) return null;
    $payload = verifyJwt($m[1]);
    if (!$payload || ($payload['type'] ?? '') !== 'access') return null;
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([(int)$payload['sub']]);
    $user = $stmt->fetch();
    $stmt->closeCursor();
    if (!$user) return null;
    if ($user['ban_until'] && strtotime($user['ban_until']) > time()) return null;
    if ($user['is_blocked']) return null;

    try {
        $updateStmt = $db->prepare("UPDATE users SET last_active_at = datetime('now') WHERE id = ?");
        safeExecute($updateStmt, [$user['id']]);
    } catch (PDOException $e) {
        error_log('last_active_at update skipped due to lock: ' . $e->getMessage());
    }

    return $user;
}

function requireAuth(): array
{
    $user = getAuthUser();
    if (!$user) jsonResponse(['error' => 'Unauthorized'], 401);
    return $user;
}

function requireAdmin(): array
{
    $user = requireAuth();
    if (!$user['is_admin']) jsonResponse(['error' => 'Forbidden'], 403);
    return $user;
}

function checkBannedWords(string $text, int $userId): ?string
{
    $db = getDb();
    $userStmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
    $userStmt->execute([$userId]);
    $userData = $userStmt->fetch();
    if ($userData && $userData['is_admin']) {
        return null;
    }
    $words = $db->query("SELECT * FROM banned_words")->fetchAll();
    foreach ($words as $w) {
        $pattern = '/\b' . preg_quote($w['word'], '/') . '\b/iu';
        if (preg_match($pattern, $text)) {
            $penalty = $w['penalty_type'];
            $duration = (int)$w['penalty_duration'];
            $expiresAt = null;
            if ($penalty === 'mute' && $duration > 0) {
                $expiresAt = gmdate('Y-m-d H:i:s', time() + $duration);
                $db->prepare("UPDATE users SET mute_until = ? WHERE id = ?")->execute([$expiresAt, $userId]);
            } elseif ($penalty === 'temp_ban' && $duration > 0) {
                $expiresAt = gmdate('Y-m-d H:i:s', time() + $duration);
                $db->prepare("UPDATE users SET ban_until = ? WHERE id = ?")->execute([$expiresAt, $userId]);
            } elseif ($penalty === 'perma_ban') {
                $expiresAt = '2099-12-31 23:59:59';
                $db->prepare("UPDATE users SET ban_until = ? WHERE id = ?")->execute([$expiresAt, $userId]);
            }
            $db->prepare("INSERT INTO admin_actions(admin_user_id, target_user_id, action_type, action_note, expires_at) VALUES(0, ?, ?, ?, ?)")
                ->execute([$userId, $penalty, "Auto: banned word", $expiresAt]);
            return $penalty;
        }
    }
    return null;
}

function formatMessage(array $m, int $currentUserId): array
{
    $body = decryptMessage($m['body_enc'], $m['nonce']);
    return [
        'id' => (int)$m['id'],
        'convo_id' => (int)$m['convo_id'],
        'user_id' => (int)$m['user_id'],
        'username' => $m['username'] ?? '',
        'is_verified' => (bool)($m['is_verified'] ?? false),
        'body' => $body ?? '[Decryption failed]',
        'created_at' => $m['created_at'],
        'is_delivered' => !empty($m['delivered_at']),
        'is_read_by_other' => (bool)($m['is_read_by_other'] ?? false),
        'is_mine' => (int)$m['user_id'] === $currentUserId
    ];
}

function setRefreshTokenCookie(string $token, int $lifetime): void
{
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    setcookie('refresh_token', $token, [
        'expires' => time() + $lifetime,
        'path' => '/',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
}

function clearRefreshTokenCookie(): void
{
    setcookie('refresh_token', '', ['expires' => 1, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
}

function getUserTheme(int $themeId): ?array
{
    if (!$themeId) return null;
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM themes WHERE id = ? AND is_active = 1");
    $stmt->execute([$themeId]);
    return $stmt->fetch() ?: null;
}

function getUserFont(int $fontId): ?array
{
    if (!$fontId) return null;
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM fonts WHERE id = ?");
    $stmt->execute([$fontId]);
    return $stmt->fetch() ?: null;
}

function issueNewTokens(array $user, string $familyId, string $ip): array
{
    $db = getDb();
    $accessToken = createJwt([
        'type' => 'access',
        'sub' => (int)$user['id'],
        'username' => $user['username'],
        'exp' => time() + ACCESS_TOKEN_LIFETIME
    ]);
    $refreshToken = bin2hex(random_bytes(32));
    $refreshHash = hash('sha256', $refreshToken);
    $expiresAt = gmdate('Y-m-d H:i:s', time() + REFRESH_TOKEN_LIFETIME);
    $db->prepare("INSERT INTO refresh_tokens(user_id, token_hash, family_id, expires_at, ip, ua) VALUES(?, ?, ?, ?, ?, ?)")
        ->execute([$user['id'], $refreshHash, $familyId, $expiresAt, $ip, substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)]);
    setRefreshTokenCookie($refreshToken, REFRESH_TOKEN_LIFETIME);
    return ['access_token' => $accessToken, 'refresh_token' => $refreshToken];
}

function validateHttpMethod(string $actualMethod, array $allowedMethods): void
{
    if (!in_array($actualMethod, $allowedMethods)) {
        http_response_code(405);
        header('Allow: ' . implode(', ', $allowedMethods));
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Method Not Allowed', 'allowed_methods' => $allowedMethods]);
        exit;
    }
}

function attachReactionsToMessages(PDO $db, array $messages): array
{
    if (empty($messages)) return [];
    $msgIds = array_column($messages, 'id');
    $placeholders = implode(',', array_fill(0, count($msgIds), '?'));

    // Fetch all reactions for these messages
    $stmt = $db->prepare("SELECT * FROM message_reactions WHERE message_id IN ($placeholders)");
    $stmt->execute($msgIds);
    $allReactions = $stmt->fetchAll();

    // Group by message_id
    $grouped = [];
    foreach ($allReactions as $r) {
        $grouped[$r['message_id']][] = [
            'user_id' => (int)$r['user_id'],
            'reaction' => $r['reaction']
        ];
    }

    // Attach to messages
    foreach ($messages as &$m) {
        $m['reactions'] = $grouped[$m['id']] ?? [];
    }
    return $messages;
}

function handleApi(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    $allowedOrigins = [$_SERVER['HTTP_HOST'] ?? '', 'http://localhost:8080', 'https://' . ($_SERVER['HTTP_HOST'] ?? '')];
    if (in_array($origin, $allowedOrigins) || !$origin) {
        header('Access-Control-Allow-Origin: ' . ($origin ?: '*'));
    }
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204);
        exit;
    }

    $method = $_SERVER['REQUEST_METHOD'];
    $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $path = preg_replace('#^/index\.php#', '', $path);
    $input = [];
    $rawInput = file_get_contents('php://input');
    if ($rawInput !== '' && $rawInput !== false) {
        $input = json_decode($rawInput, true) ?? [];
    }
    $ip = getClientIp();

    if ($path === '/api/poll' && $method === 'GET') {
        if (!checkRateLimitReadOnly("poll:$ip", RATE_LIMIT_POLL_REQUESTS, RATE_LIMIT_POLL_WINDOW)) {
            jsonResponse(['error' => 'Rate limit exceeded'], 429);
        }
    } else {
        if (!checkRateLimit("ip:$ip", RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)) {
            jsonResponse(['error' => 'Rate limit exceeded'], 429);
        }
    }

    if ($path === '/api/auth/register') {
        validateHttpMethod($method, ['POST']);
        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';
        if (strlen($username) < MIN_USERNAME_LENGTH || strlen($username) > MAX_USERNAME_LENGTH) {
            jsonResponse(['error' => 'Username must be 3-30 characters'], 400);
        }
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            jsonResponse(['error' => 'Invalid username format'], 400);
        }
        if (strlen($password) < MIN_PASSWORD_LENGTH) {
            jsonResponse(['error' => 'Password must be at least 8 characters'], 400);
        }
        $db = getDb();
        $hash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
        $countStmt = $db->query("SELECT COUNT(*) as cnt FROM users");
        $userCount = (int)$countStmt->fetch()['cnt'];
        $isFirstUser = ($userCount === 0);
        $isAdmin = $isFirstUser ? 1 : 0;
        $isVerified = $isFirstUser ? 1 : 0;
        try {
            $stmt = $db->prepare("INSERT INTO users(username, pass_hash, is_admin, is_verified) VALUES(?, ?, ?, ?)");
            $stmt->execute([$username, $hash, $isAdmin, $isVerified]);
            $user = ['id' => $db->lastInsertId(), 'username' => $username, 'is_admin' => $isAdmin, 'is_verified' => $isVerified];
            jsonResponse(['message' => 'User created', 'user' => $user], 201);
        } catch (PDOException $e) {
            if (strpos($e->getMessage(), 'UNIQUE constraint') !== false) {
                jsonResponse(['error' => 'Username already exists'], 409);
            }
            throw $e;
        }
    }

    if ($path === '/api/auth/login') {
        validateHttpMethod($method, ['POST']);
        $username = trim($input['username'] ?? '');
        $password = $input['password'] ?? '';
        $db = getDb();
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        $valid = $user && password_verify($password, $user['pass_hash']);
        if (!$user) password_verify($password, '$2y$12$dummy.hash.to.prevent.timing');
        if (!$valid) jsonResponse(['error' => 'Invalid credentials'], 401);
        if ($user['ban_until'] && strtotime($user['ban_until']) > time()) {
            jsonResponse(['error' => 'Account banned until ' . $user['ban_until']], 403);
        }
        $familyId = bin2hex(random_bytes(16));
        $tokens = issueNewTokens($user, $familyId, $ip);
        $theme = getUserTheme((int)($user['theme_id'] ?? 0));
        $font = getUserFont((int)($user['font_id'] ?? 1));
        jsonResponse([
            'access_token' => $tokens['access_token'],
            'expires_in' => ACCESS_TOKEN_LIFETIME,
            'user' => [
                'id' => (int)$user['id'],
                'username' => $user['username'],
                'is_verified' => (bool)$user['is_verified'],
                'is_admin' => (bool)$user['is_admin'],
                'font_scale' => (float)($user['font_scale'] ?? 1.0),
                'font_id' => $user['font_id'] ? (int)$user['font_id'] : 1,
                'font' => $font,
                'theme_id' => $user['theme_id'] ? (int)$user['theme_id'] : null,
                'theme' => $theme ? json_decode($theme['definition_json'], true) : null
            ]
        ]);
    }

    if ($path === '/api/auth/refresh' && $method === 'POST') {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        if ($origin && parse_url($origin, PHP_URL_HOST) !== $host) {
            jsonResponse(['error' => 'Invalid origin'], 403);
        }
        $refreshToken = $_COOKIE['refresh_token'] ?? '';
        if (!$refreshToken) jsonResponse(['error' => 'No refresh token'], 401);
        $refreshHash = hash('sha256', $refreshToken);
        $db = getDb();
        $stmt = $db->prepare("SELECT rt.*, u.* FROM refresh_tokens rt JOIN users u ON rt.user_id = u.id WHERE rt.token_hash = ?");
        $stmt->execute([$refreshHash]);
        $row = $stmt->fetch();
        if (!$row) {
            clearRefreshTokenCookie();
            jsonResponse(['error' => 'Invalid refresh token'], 401);
        }
        if (strtotime($row['expires_at']) < time()) {
            clearRefreshTokenCookie();
            jsonResponse(['error' => 'Refresh token expired'], 401);
        }
        if ($row['revoked_at']) {
            $revokedTime = strtotime($row['revoked_at']);
            if (time() - $revokedTime < REFRESH_TOKEN_GRACE_PERIOD) {
                $activeStmt = $db->prepare("SELECT token_hash FROM refresh_tokens WHERE family_id = ? AND revoked_at IS NULL AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1");
                $activeStmt->execute([$row['family_id']]);
                $activeToken = $activeStmt->fetch();
                if ($activeToken) {
                    $accessToken = createJwt([
                        'type' => 'access',
                        'sub' => (int)$row['user_id'],
                        'username' => $row['username'],
                        'exp' => time() + ACCESS_TOKEN_LIFETIME
                    ]);
                    $theme = getUserTheme((int)($row['theme_id'] ?? 0));
                    $font = getUserFont((int)($row['font_id'] ?? 1));
                    jsonResponse([
                        'access_token' => $accessToken,
                        'expires_in' => ACCESS_TOKEN_LIFETIME,
                        'user' => [
                            'id' => (int)$row['user_id'],
                            'username' => $row['username'],
                            'is_verified' => (bool)$row['is_verified'],
                            'is_admin' => (bool)$row['is_admin'],
                            'font_scale' => (float)($row['font_scale'] ?? 1.0),
                            'font_id' => $row['font_id'] ? (int)$row['font_id'] : 1,
                            'font' => $font,
                            'theme_id' => $row['theme_id'] ? (int)$row['theme_id'] : null,
                            'theme' => $theme ? json_decode($theme['definition_json'], true) : null
                        ]
                    ]);
                }
            }
            $db->prepare("UPDATE refresh_tokens SET revoked_at = datetime('now') WHERE family_id = ? AND revoked_at IS NULL")
                ->execute([$row['family_id']]);
            clearRefreshTokenCookie();
            jsonResponse(['error' => 'Token reuse detected'], 401);
        }
        if ($row['ban_until'] && strtotime($row['ban_until']) > time()) {
            clearRefreshTokenCookie();
            jsonResponse(['error' => 'Account banned'], 403);
        }
        if ($row['is_blocked']) {
            clearRefreshTokenCookie();
            jsonResponse(['error' => 'Account blocked'], 403);
        }
        $db->prepare("UPDATE refresh_tokens SET revoked_at = datetime('now') WHERE id = ?")->execute([$row['id']]);
        $tokens = issueNewTokens($row, $row['family_id'], getClientIp());
        $theme = getUserTheme((int)($row['theme_id'] ?? 0));
        $font = getUserFont((int)($row['font_id'] ?? 1));
        jsonResponse([
            'access_token' => $tokens['access_token'],
            'expires_in' => ACCESS_TOKEN_LIFETIME,
            'user' => [
                'id' => (int)$row['user_id'],
                'username' => $row['username'],
                'is_verified' => (bool)$row['is_verified'],
                'is_admin' => (bool)$row['is_admin'],
                'font_scale' => (float)($row['font_scale'] ?? 1.0),
                'font_id' => $row['font_id'] ? (int)$row['font_id'] : 1,
                'font' => $font,
                'theme_id' => $row['theme_id'] ? (int)$row['theme_id'] : null,
                'theme' => $theme ? json_decode($theme['definition_json'], true) : null
            ]
        ]);
    }

    if ($path === '/api/auth/logout' && $method === 'POST') {
        $refreshToken = $_COOKIE['refresh_token'] ?? '';
        if ($refreshToken) {
            $refreshHash = hash('sha256', $refreshToken);
            $db = getDb();
            $stmt = $db->prepare("SELECT family_id FROM refresh_tokens WHERE token_hash = ?");
            $stmt->execute([$refreshHash]);
            $row = $stmt->fetch();
            if ($row) {
                $db->prepare("UPDATE refresh_tokens SET revoked_at = datetime('now') WHERE family_id = ? AND revoked_at IS NULL")
                    ->execute([$row['family_id']]);
            }
        }
        clearRefreshTokenCookie();
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/me' && $method === 'GET') {
        $user = requireAuth();
        $theme = getUserTheme((int)($user['theme_id'] ?? 0));
        jsonResponse([
            'id' => (int)$user['id'],
            'username' => $user['username'],
            'is_verified' => (bool)$user['is_verified'],
            'is_admin' => (bool)$user['is_admin'],
            'font_scale' => (float)($user['font_scale'] ?? 1.0),
            'font_family' => $user['font_family'] ?? 'system-ui',
            'theme_id' => $user['theme_id'] ? (int)$user['theme_id'] : null,
            'theme' => $theme ? json_decode($theme['definition_json'], true) : null
        ]);
    }

    if ($path === '/api/user/font_scale' && $method === 'POST') {
        $user = requireAuth();
        $scale = (float)($input['scale'] ?? 1.0);
        $scale = max(MIN_FONT_SCALE, min(MAX_FONT_SCALE, $scale));
        $db = getDb();
        $db->prepare("UPDATE users SET font_scale = ? WHERE id = ?")->execute([$scale, $user['id']]);
        jsonResponse(['success' => true, 'font_scale' => $scale]);
    }

    if ($path === '/api/user/theme' && $method === 'POST') {
        $user = requireAuth();
        $themeId = isset($input['theme_id']) ? (int)$input['theme_id'] : null;
        $db = getDb();
        if ($themeId) {
            $stmt = $db->prepare("SELECT id FROM themes WHERE id = ? AND is_active = 1");
            $stmt->execute([$themeId]);
            if (!$stmt->fetch()) {
                jsonResponse(['error' => 'Invalid or inactive theme'], 400);
            }
        }
        $db->prepare("UPDATE users SET theme_id = ? WHERE id = ?")->execute([$themeId, $user['id']]);
        $theme = $themeId ? getUserTheme($themeId) : null;
        jsonResponse(['success' => true, 'theme' => $theme ? json_decode($theme['definition_json'], true) : null]);
    }

    if ($path === '/api/user/font' && $method === 'POST') {
        $user = requireAuth();
        $fontId = (int)($input['font_id'] ?? 1);
        $db = getDb();

        $stmt = $db->prepare("SELECT id FROM fonts WHERE id = ?");
        $stmt->execute([$fontId]);
        if (!$stmt->fetch()) {
            jsonResponse(['error' => 'Invalid font'], 400);
        }

        $db->prepare("UPDATE users SET font_id = ? WHERE id = ?")->execute([$fontId, $user['id']]);
        $font = getUserFont($fontId);
        jsonResponse(['success' => true, 'font' => $font]);
    }

    if ($path === '/api/user/request_verification' && $method === 'POST') {
        $user = requireAuth();
        if ($user['is_verified']) {
            jsonResponse(['error' => 'Already verified'], 400);
        }
        $message = trim($input['message'] ?? '');
        if (!$message || strlen($message) > 1000) {
            jsonResponse(['error' => 'Message required (max 1000 chars)'], 400);
        }
        $db = getDb();
        $stmt = $db->prepare("SELECT id FROM verification_requests WHERE user_id = ? AND status = 'pending'");
        $stmt->execute([$user['id']]);
        if ($stmt->fetch()) {
            jsonResponse(['error' => 'You already have a pending request'], 400);
        }
        $db->prepare("INSERT INTO verification_requests(user_id, message) VALUES(?, ?)")->execute([$user['id'], $message]);
        jsonResponse(['success' => true], 201);
    }

    if ($path === '/api/themes' && $method === 'GET') {
        requireAuth();
        $themes = getDb()->query("SELECT id, name, definition_json FROM themes WHERE is_active = 1 ORDER BY name")->fetchAll();
        foreach ($themes as &$t) {
            $t['definition'] = json_decode($t['definition_json'], true);
            unset($t['definition_json']);
        }
        jsonResponse(['themes' => $themes]);
    }

    if ($path === '/api/fonts' && $method === 'GET') {
        requireAuth();
        jsonResponse(['fonts' => getDb()->query("SELECT * FROM fonts ORDER BY name")->fetchAll()]);
    }

    if ($path === '/api/support' && $method === 'GET') {
        $user = requireAuth();
        $db = getDb();
        $stmt = $db->prepare("
            SELECT sm.*, 
                   CASE WHEN sr.message_id IS NOT NULL THEN 1 ELSE 0 END as is_read
            FROM support_messages sm
            LEFT JOIN support_reads sr ON sm.id = sr.message_id AND sr.user_id = ?
            ORDER BY sm.created_at DESC
            LIMIT 100
        ");
        $stmt->execute([$user['id']]);
        $messages = $stmt->fetchAll();
        foreach ($messages as &$m) {
            $m['id'] = (int)$m['id'];
            $m['is_read'] = (bool)$m['is_read'];
        }
        jsonResponse(['messages' => $messages]);
    }

    if ($path === '/api/support/mark_read' && $method === 'POST') {
        $user = requireAuth();
        $messageId = (int)($input['message_id'] ?? 0);
        if ($messageId <= 0) jsonResponse(['error' => 'Invalid message ID'], 400);
        $db = getDb();
        $stmt = $db->prepare("SELECT id FROM support_messages WHERE id = ?");
        $stmt->execute([$messageId]);
        if (!$stmt->fetch()) jsonResponse(['error' => 'Message not found'], 404);
        $db->prepare("INSERT OR IGNORE INTO support_reads(message_id, user_id) VALUES(?, ?)")->execute([$messageId, $user['id']]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/support/unread_count' && $method === 'GET') {
        $user = requireAuth();
        $db = getDb();
        $stmt = $db->prepare("
            SELECT COUNT(*) as cnt FROM support_messages sm
            LEFT JOIN support_reads sr ON sm.id = sr.message_id AND sr.user_id = ?
            WHERE sr.message_id IS NULL
        ");
        $stmt->execute([$user['id']]);
        jsonResponse(['unread_count' => (int)$stmt->fetch()['cnt']]);
    }

    if ($path === '/api/invite/create' && $method === 'POST') {
        $user = requireAuth();
        $db = getDb();
        $db->beginTransaction();
        try {
            $db->prepare("INSERT INTO convos(type) VALUES('dm')")->execute();
            $convoId = (int)$db->lastInsertId();
            $db->prepare("INSERT INTO convo_members(convo_id, user_id) VALUES(?, ?)")->execute([$convoId, $user['id']]);
            $jti = bin2hex(random_bytes(16));
            $db->prepare("INSERT INTO invite_jti(jti, convo_id) VALUES(?, ?)")->execute([$jti, $convoId]);
            $db->commit();
        } catch (Exception $e) {
            $db->rollBack();
            jsonResponse(['error' => 'Failed to create invite'], 500);
        }
        $token = createJwt([
            'type' => 'invite',
            'convo_id' => $convoId,
            'inviter_user_id' => (int)$user['id'],
            'jti' => $jti,
            'exp' => time() + INVITE_TOKEN_LIFETIME
        ]);
        $scheme = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        jsonResponse(['invite_token' => $token, 'invite_url' => "$scheme://$host/?invite=" . urlencode($token), 'convo_id' => $convoId]);
    }

    if ($path === '/api/invite/redeem' && $method === 'POST') {
        $user = requireAuth();
        $token = $input['token'] ?? '';
        $payload = verifyJwt($token);
        if (!$payload || ($payload['type'] ?? '') !== 'invite') {
            jsonResponse(['error' => 'Invalid invite token'], 400);
        }
        if ((int)($payload['inviter_user_id'] ?? 0) === (int)$user['id']) {
            jsonResponse(['error' => 'Cannot accept own invite'], 400);
        }
        $convoId = (int)($payload['convo_id'] ?? 0);
        $jti = $payload['jti'] ?? '';
        $db = getDb();
        $db->beginTransaction();
        try {
            $stmt = $db->prepare("SELECT * FROM invite_jti WHERE jti = ?");
            $stmt->execute([$jti]);
            $jtiRow = $stmt->fetch();
            if (!$jtiRow || $jtiRow['used_at']) {
                $db->rollBack();
                jsonResponse(['error' => 'Invite already used'], 400);
            }
            $stmt = $db->prepare("SELECT 1 FROM convo_members cm JOIN users u ON cm.user_id = u.id WHERE cm.convo_id = ? AND cm.user_id = ?");
            $stmt->execute([$convoId, $payload['inviter_user_id'] ?? 0]);
            if (!$stmt->fetch()) {
                $db->rollBack();
                jsonResponse(['error' => 'Invite is no longer valid'], 400);
            }
            $stmt = $db->prepare("SELECT COUNT(*) as cnt FROM convo_members WHERE convo_id = ?");
            $stmt->execute([$convoId]);
            if ((int)$stmt->fetch()['cnt'] >= 2) {
                $db->rollBack();
                jsonResponse(['error' => 'Conversation full'], 400);
            }
            $stmt = $db->prepare("SELECT 1 FROM convo_members WHERE convo_id = ? AND user_id = ?");
            $stmt->execute([$convoId, $user['id']]);
            if ($stmt->fetch()) {
                $db->rollBack();
                jsonResponse(['error' => 'Already in conversation'], 400);
            }
            $db->prepare("INSERT INTO convo_members(convo_id, user_id) VALUES(?, ?)")->execute([$convoId, $user['id']]);
            $db->prepare("UPDATE invite_jti SET used_at = datetime('now') WHERE jti = ?")->execute([$jti]);
            $db->commit();
        } catch (Exception $e) {
            $db->rollBack();
            jsonResponse(['error' => 'Failed to redeem invite'], 500);
        }
        jsonResponse(['success' => true, 'convo_id' => $convoId]);
    }

    if ($path === '/api/convos' && $method === 'GET') {
        $user = requireAuth();
        $db = getDb();
        $stmt = $db->prepare("
            SELECT DISTINCT c.id, c.type, c.created_at
            FROM convos c
            JOIN convo_members cm ON c.id = cm.convo_id
            WHERE cm.user_id = ?
            ORDER BY c.created_at DESC
        ");
        $stmt->execute([$user['id']]);
        $convos = $stmt->fetchAll();
        foreach ($convos as &$c) {
            $stmt = $db->prepare("
                SELECT u.id, u.username, u.is_verified, u.last_active_at
                FROM convo_members cm
                JOIN users u ON cm.user_id = u.id
                WHERE cm.convo_id = ? AND cm.user_id != ?
                LIMIT 1
            ");
            $stmt->execute([$c['id'], $user['id']]);
            $other = $stmt->fetch();
            $c['other_user_id'] = $other ? (int)$other['id'] : null;
            $c['other_username'] = $other ? $other['username'] : null;
            $c['other_verified'] = $other ? (bool)$other['is_verified'] : false;
            $c['other_last_active'] = $other ? $other['last_active_at'] : null;
            $stmt = $db->prepare("SELECT COUNT(*) as cnt FROM messages m 
                LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id = ?
                WHERE m.convo_id = ? AND m.user_id != ? AND mr.message_id IS NULL AND m.deleted = 0");
            $stmt->execute([$user['id'], $c['id'], $user['id']]);
            $c['unread_count'] = (int)$stmt->fetch()['cnt'];
            $c['id'] = (int)$c['id'];
        }
        jsonResponse(['convos' => $convos]);
    }

    if ($path === '/api/messages' && $method === 'GET') {
        $user = requireAuth();
        $convoId = (int)($_GET['convo_id'] ?? 0);
        if ($convoId <= 0) jsonResponse(['error' => 'Invalid conversation ID'], 400);
        $db = getDb();
        $stmt = $db->prepare("SELECT 1 FROM convo_members WHERE convo_id = ? AND user_id = ?");
        $stmt->execute([$convoId, $user['id']]);
        if (!$stmt->fetch()) jsonResponse(['error' => 'Forbidden'], 403);
        $stmt = $db->prepare("
            SELECT m.id, m.convo_id, m.user_id, m.body_enc, m.nonce, m.created_at, m.delivered_at,
                   u.username, u.is_verified,
                   CASE WHEN mr.message_id IS NOT NULL THEN 1 ELSE 0 END as is_read_by_other
            FROM messages m
            JOIN users u ON m.user_id = u.id
            LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id != m.user_id
            WHERE m.convo_id = ? AND m.deleted = 0
            ORDER BY m.created_at ASC
            LIMIT 500
        ");
        $stmt->execute([$convoId]);
        $messages = $stmt->fetchAll();
        $result = [];
        $idsToMarkDelivered = [];
        foreach ($messages as $m) {
            if ((int)$m['user_id'] !== (int)$user['id'] && !$m['delivered_at']) {
                $idsToMarkDelivered[] = $m['id'];
                $m['delivered_at'] = gmdate('Y-m-d H:i:s');
            }
            $result[] = formatMessage($m, (int)$user['id']);
        }
        if ($idsToMarkDelivered) {
            $placeholders = implode(',', array_fill(0, count($idsToMarkDelivered), '?'));
            $db->prepare("UPDATE messages SET delivered_at = datetime('now') WHERE id IN ($placeholders)")->execute($idsToMarkDelivered);
        }
        $resultWithReactions = attachReactionsToMessages($db, $result);
        jsonResponse(['messages' => $resultWithReactions]);
    }

    if ($path === '/api/messages/send' && $method === 'POST') {
        $user = requireAuth();
        if ($user['mute_until'] && strtotime($user['mute_until']) > time()) {
            jsonResponse(['error' => 'You are muted until ' . $user['mute_until']], 403);
        }
        $convoId = (int)($input['convo_id'] ?? 0);
        $body = trim($input['body'] ?? '');
        $socketId = $input['socket_id'] ?? null;
        if ($convoId <= 0) jsonResponse(['error' => 'Invalid conversation ID'], 400);
        if (!$body) jsonResponse(['error' => 'Message empty'], 400);
        if (mb_strlen($body) > MAX_MESSAGE_LENGTH) jsonResponse(['error' => 'Message too long'], 400);
        $db = getDb();
        $stmt = $db->prepare("SELECT 1 FROM convo_members WHERE convo_id = ? AND user_id = ?");
        $stmt->execute([$convoId, $user['id']]);
        if (!$stmt->fetch()) jsonResponse(['error' => 'Forbidden'], 403);
        $penalty = checkBannedWords($body, (int)$user['id']);
        if ($penalty && $penalty !== 'warn') {
            jsonResponse(['error' => "Message blocked. Penalty: $penalty"], 400);
        }
        $enc = encryptMessage($body);
        $stmt = $db->prepare("INSERT INTO messages(convo_id, user_id, body_enc, nonce) VALUES(?, ?, ?, ?)");
        $stmt->execute([$convoId, $user['id'], $enc['enc'], $enc['nonce']]);
        $messageId = (int)$db->lastInsertId();

        triggerPusherEvent(
            "private-conversation-{$convoId}",
            'new-message',
            [
                'message' => [
                    'id' => $messageId,
                    'convo_id' => $convoId,
                    'user_id' => (int)$user['id'],
                    'username' => $user['username'],
                    'is_verified' => (bool)$user['is_verified'],
                    'body' => $body,
                    'created_at' => gmdate('Y-m-d H:i:s'),
                    'is_delivered' => false,
                    'is_read_by_other' => false,
                    'is_mine' => false
                ],
                'convo_id' => $convoId
            ],
            $socketId
        );
        jsonResponse(['success' => true, 'message_id' => $messageId], 201);
    }

    if ($path === '/api/messages/mark_read' && $method === 'POST') {
        $user = requireAuth();
        $convoId = (int)($input['convo_id'] ?? 0);
        $upToMessageId = (int)($input['up_to_message_id'] ?? 0);
        $socketId = $input['socket_id'] ?? null;
        if ($convoId <= 0 || $upToMessageId <= 0) jsonResponse(['error' => 'Invalid parameters'], 400);
        $db = getDb();
        $stmt = $db->prepare("SELECT 1 FROM convo_members WHERE convo_id = ? AND user_id = ?");
        $stmt->execute([$convoId, $user['id']]);
        if (!$stmt->fetch()) jsonResponse(['error' => 'Forbidden'], 403);
        $stmt = $db->prepare("
            INSERT OR IGNORE INTO message_reads(message_id, user_id)
            SELECT id, ? FROM messages WHERE convo_id = ? AND id <= ? AND user_id != ? AND deleted = 0
        ");
        $stmt->execute([$user['id'], $convoId, $upToMessageId, $user['id']]);

        triggerPusherEvent(
            "private-conversation-{$convoId}",
            'message-read',
            [
                'message_id' => $upToMessageId,
                'user_id' => $user['id'],
                'convo_id' => $convoId
            ],
            $socketId
        );
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/messages/react' && $method === 'POST') {
        $user = requireAuth();
        $messageId = (int)($input['message_id'] ?? 0);
        $reaction = $input['reaction'] ?? ''; // Emoji string

        if ($messageId <= 0) jsonResponse(['error' => 'Invalid message'], 400);

        $db = getDb();
        // Verify access to message via conversation membership
        $stmt = $db->prepare("
            SELECT m.convo_id FROM messages m 
            JOIN convo_members cm ON m.convo_id = cm.convo_id 
            WHERE m.id = ? AND cm.user_id = ?
        ");
        $stmt->execute([$messageId, $user['id']]);
        $row = $stmt->fetch();

        if (!$row) jsonResponse(['error' => 'Forbidden'], 403);
        $convoId = (int)$row['convo_id'];

        if (!$reaction) {
            // Remove reaction
            $db->prepare("DELETE FROM message_reactions WHERE message_id = ? AND user_id = ?")
                ->execute([$messageId, $user['id']]);
        } else {
            // Add/Update reaction
            $db->prepare("INSERT OR REPLACE INTO message_reactions(message_id, user_id, reaction) VALUES(?, ?, ?)")
                ->execute([$messageId, $user['id'], $reaction]);
        }

        // Trigger Pusher
        triggerPusherEvent(
            "private-conversation-{$convoId}",
            'message-reaction',
            [
                'message_id' => $messageId,
                'user_id' => (int)$user['id'],
                'reaction' => $reaction
            ]
        );

        jsonResponse(['success' => true]);
    }

    if ($path === '/api/poll' && $method === 'GET') {
        $user = requireAuth();
        $convoId = (int)($_GET['convo_id'] ?? 0);
        $lastId = (int)($_GET['last_id'] ?? 0);
        if ($convoId <= 0) jsonResponse(['error' => 'Invalid conversation ID'], 400);
        $db = getDb();
        $stmt = $db->prepare("SELECT 1 FROM convo_members WHERE convo_id = ? AND user_id = ?");
        $stmt->execute([$convoId, $user['id']]);
        if (!$stmt->fetch()) jsonResponse(['error' => 'Forbidden'], 403);
        $stmt = $db->prepare("
            SELECT m.id, m.convo_id, m.user_id, m.body_enc, m.nonce, m.created_at, m.delivered_at,
                   u.username, u.is_verified,
                   CASE WHEN mr.message_id IS NOT NULL THEN 1 ELSE 0 END as is_read_by_other
            FROM messages m
            JOIN users u ON m.user_id = u.id
            LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id != m.user_id
            WHERE m.convo_id = ? AND m.id > ? AND m.deleted = 0
            ORDER BY m.created_at ASC
            LIMIT ?
        ");
        $stmt->execute([$convoId, $lastId, POLL_MAX_MESSAGES]);
        $messages = $stmt->fetchAll();
        $result = [];
        $idsToMarkDelivered = [];
        foreach ($messages as $m) {
            if ((int)$m['user_id'] !== (int)$user['id'] && !$m['delivered_at']) {
                $idsToMarkDelivered[] = $m['id'];
                $m['delivered_at'] = gmdate('Y-m-d H:i:s');
            }
            $result[] = formatMessage($m, (int)$user['id']);
        }
        if ($idsToMarkDelivered) {
            $placeholders = implode(',', array_fill(0, count($idsToMarkDelivered), '?'));
            $db->prepare("UPDATE messages SET delivered_at = datetime('now') WHERE id IN ($placeholders)")->execute($idsToMarkDelivered);
        }
        $stmt = $db->prepare("
            SELECT m.id, 
                   CASE WHEN m.delivered_at IS NOT NULL THEN 1 ELSE 0 END as is_delivered,
                   CASE WHEN mr.message_id IS NOT NULL THEN 1 ELSE 0 END as is_read_by_other
            FROM messages m
            LEFT JOIN message_reads mr ON m.id = mr.message_id AND mr.user_id != m.user_id
            WHERE m.convo_id = ? AND m.user_id = ? AND m.deleted = 0
        ");
        $stmt->execute([$convoId, $user['id']]);
        $statusUpdates = [];
        foreach ($stmt->fetchAll() as $row) {
            $statusUpdates[] = ['id' => (int)$row['id'], 'is_delivered' => (bool)$row['is_delivered'], 'is_read_by_other' => (bool)$row['is_read_by_other']];
        }
        $stmt = $db->prepare("SELECT id FROM messages WHERE convo_id = ? AND deleted = 1 AND id > ? LIMIT 100");
        $stmt->execute([$convoId, $lastId]);
        $deletedIds = array_map('intval', array_column($stmt->fetchAll(), 'id'));

        $stmt = $db->prepare("SELECT u.last_active_at FROM convo_members cm JOIN users u ON cm.user_id = u.id WHERE cm.convo_id = ? AND cm.user_id != ? LIMIT 1");
        $stmt->execute([$convoId, $user['id']]);
        $partnerStatus = $stmt->fetch();
        $lastActive = $partnerStatus ? $partnerStatus['last_active_at'] : null;

        $resultWithReactions = attachReactionsToMessages($db, $result);
        jsonResponse([
            'messages' => $resultWithReactions,
            'status_updates' => $statusUpdates,
            'deleted_ids' => $deletedIds,
            'partner_last_active' => $lastActive
        ]);
    }

    if ($path === '/api/report' && $method === 'POST') {
        $user = requireAuth();
        $reportedUserId = (int)($input['reported_user_id'] ?? 0);
        $reason = trim($input['reason'] ?? '');
        if ($reportedUserId <= 0 || !$reason) jsonResponse(['error' => 'Missing fields'], 400);
        if ($reportedUserId === (int)$user['id']) jsonResponse(['error' => 'Cannot report yourself'], 400);
        $db = getDb();
        $db->prepare("INSERT INTO reports(reporter_user_id, reported_user_id, reason) VALUES(?, ?, ?)")
            ->execute([$user['id'], $reportedUserId, $reason]);
        jsonResponse(['success' => true], 201);
    }

    if ($path === '/api/admin/reports' && $method === 'GET') {
        requireAdmin();
        $reports = getDb()->query("
            SELECT r.*, u1.username as reporter_username, u2.username as reported_username
            FROM reports r
            JOIN users u1 ON r.reporter_user_id = u1.id
            JOIN users u2 ON r.reported_user_id = u2.id
            ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.created_at DESC
            LIMIT 100
        ")->fetchAll();
        jsonResponse(['reports' => $reports]);
    }

    if ($path === '/api/admin/reports/reject' && $method === 'POST') {
        requireAdmin();
        $reportId = (int)($input['report_id'] ?? 0);
        getDb()->prepare("UPDATE reports SET status = 'rejected' WHERE id = ? AND status = 'pending'")->execute([$reportId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/reports/action' && $method === 'POST') {
        $admin = requireAdmin();
        $reportId = (int)($input['report_id'] ?? 0);
        $action = $input['action'] ?? '';
        $duration = (int)($input['duration'] ?? 0);
        $db = getDb();
        $stmt = $db->prepare("SELECT * FROM reports WHERE id = ?");
        $stmt->execute([$reportId]);
        $report = $stmt->fetch();
        if (!$report) jsonResponse(['error' => 'Report not found'], 404);
        $targetStmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
        $targetStmt->execute([$report['reported_user_id']]);
        $targetUser = $targetStmt->fetch();
        if ($targetUser && $targetUser['is_admin']) {
            jsonResponse(['error' => 'Cannot take action against admin users'], 403);
        }
        $expiresAt = null;
        if ($action === 'mute' && $duration) {
            $expiresAt = gmdate('Y-m-d H:i:s', time() + $duration);
            $db->prepare("UPDATE users SET mute_until = ? WHERE id = ?")->execute([$expiresAt, $report['reported_user_id']]);
        } elseif ($action === 'temp_ban' && $duration) {
            $expiresAt = gmdate('Y-m-d H:i:s', time() + $duration);
            $db->prepare("UPDATE users SET ban_until = ? WHERE id = ?")->execute([$expiresAt, $report['reported_user_id']]);
        } elseif ($action === 'perma_ban') {
            $expiresAt = '2099-12-31 23:59:59';
            $db->prepare("UPDATE users SET ban_until = ? WHERE id = ?")->execute([$expiresAt, $report['reported_user_id']]);
        } elseif ($action === 'block') {
            $db->prepare("UPDATE users SET is_blocked = 1 WHERE id = ?")->execute([$report['reported_user_id']]);
        }
        $db->prepare("INSERT INTO admin_actions(admin_user_id, target_user_id, action_type, action_note, expires_at) VALUES(?, ?, ?, ?, ?)")
            ->execute([$admin['id'], $report['reported_user_id'], $action, "From report #$reportId", $expiresAt]);
        $db->prepare("UPDATE reports SET status = 'actioned' WHERE id = ?")->execute([$reportId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/set_verified' && $method === 'POST') {
        requireAdmin();
        $userId = (int)($input['user_id'] ?? 0);
        $value = $input['value'] ? 1 : 0;
        getDb()->prepare("UPDATE users SET is_verified = ? WHERE id = ?")->execute([$value, $userId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/banned_words' && $method === 'GET') {
        requireAdmin();
        jsonResponse(['banned_words' => getDb()->query("SELECT * FROM banned_words ORDER BY word")->fetchAll()]);
    }

    if ($path === '/api/admin/banned_words/add' && $method === 'POST') {
        $admin = requireAdmin();
        $word = mb_strtolower(trim($input['word'] ?? ''));
        $penaltyType = $input['penalty_type'] ?? 'warn';
        $penaltyDuration = (int)($input['penalty_duration'] ?? 0);
        if (!$word) jsonResponse(['error' => 'Word required'], 400);
        try {
            getDb()->prepare("INSERT INTO banned_words(word, penalty_type, penalty_duration, created_by_admin) VALUES(?, ?, ?, ?)")
                ->execute([$word, $penaltyType, $penaltyDuration ?: null, $admin['id']]);
            jsonResponse(['success' => true], 201);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Word already exists'], 409);
        }
    }

    if ($path === '/api/admin/banned_words/delete' && $method === 'POST') {
        requireAdmin();
        getDb()->prepare("DELETE FROM banned_words WHERE id = ?")->execute([(int)($input['id'] ?? 0)]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/delete_message' && $method === 'POST') {
        requireAdmin();
        $messageId = (int)($input['message_id'] ?? 0);
        $db = getDb();
        $stmt = $db->prepare("SELECT convo_id FROM messages WHERE id = ?");
        $stmt->execute([$messageId]);
        $msg = $stmt->fetch();
        if ($msg) {
            $db->prepare("UPDATE messages SET deleted = 1 WHERE id = ?")->execute([$messageId]);
            triggerPusherEvent(
                "private-conversation-{$msg['convo_id']}",
                'message-deleted',
                ['message_id' => $messageId, 'convo_id' => (int)$msg['convo_id']]
            );
        }
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/users' && $method === 'GET') {
        requireAdmin();
        jsonResponse(['users' => getDb()->query("SELECT id, username, is_verified, is_admin, is_blocked, mute_until, ban_until, created_at FROM users ORDER BY id LIMIT 1000")->fetchAll()]);
    }

    if ($path === '/api/admin/themes' && $method === 'GET') {
        requireAdmin();
        $themes = getDb()->query("SELECT * FROM themes ORDER BY name")->fetchAll();
        foreach ($themes as &$t) {
            $t['definition'] = json_decode($t['definition_json'], true);
        }
        jsonResponse(['themes' => $themes]);
    }

    if ($path === '/api/admin/themes/create' && $method === 'POST') {
        $admin = requireAdmin();
        $name = trim($input['name'] ?? '');
        $definitionJson = $input['definition_json'] ?? '';
        if (!$name) jsonResponse(['error' => 'Name required'], 400);
        $definition = json_decode($definitionJson, true);
        if (!$definition) jsonResponse(['error' => 'Invalid JSON'], 400);
        $required = ['background', 'incomingBubble', 'outgoingBubble', 'header', 'accent'];
        foreach ($required as $key) {
            if (!isset($definition[$key])) {
                jsonResponse(['error' => "Missing key: $key"], 400);
            }
        }
        try {
            getDb()->prepare("INSERT INTO themes(name, definition_json, created_by_admin) VALUES(?, ?, ?)")
                ->execute([$name, $definitionJson, $admin['id']]);
            jsonResponse(['success' => true, 'theme_id' => (int)getDb()->lastInsertId()], 201);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Theme name already exists'], 409);
        }
    }

    if ($path === '/api/admin/themes/activate' && $method === 'POST') {
        requireAdmin();
        $themeId = (int)($input['theme_id'] ?? 0);
        $db = getDb();
        $stmt = $db->prepare("SELECT id FROM themes WHERE id = ?");
        $stmt->execute([$themeId]);
        if (!$stmt->fetch()) jsonResponse(['error' => 'Theme not found'], 404);
        $db->prepare("UPDATE themes SET is_active = 1 WHERE id = ?")->execute([$themeId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/themes/deactivate' && $method === 'POST') {
        requireAdmin();
        $themeId = (int)($input['theme_id'] ?? 0);
        $db = getDb();
        $db->prepare("UPDATE themes SET is_active = 0 WHERE id = ?")->execute([$themeId]);
        $db->prepare("UPDATE users SET theme_id = NULL WHERE theme_id = ?")->execute([$themeId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/themes/delete' && $method === 'POST') {
        requireAdmin();
        $themeId = (int)($input['theme_id'] ?? 0);
        $db = getDb();
        $db->prepare("UPDATE users SET theme_id = NULL WHERE theme_id = ?")->execute([$themeId]);
        $db->prepare("DELETE FROM themes WHERE id = ?")->execute([$themeId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/fonts' && $method === 'GET') {
        requireAdmin();
        jsonResponse(['fonts' => getDb()->query("SELECT * FROM fonts ORDER BY id")->fetchAll()]);
    }

    if ($path === '/api/admin/fonts/add' && $method === 'POST') {
        requireAdmin();
        $name = trim($input['name'] ?? '');
        $cssValue = trim($input['css_value'] ?? '');
        $importUrl = trim($input['import_url'] ?? '');

        if (!$name || !$cssValue) {
            jsonResponse(['error' => 'Name and CSS value required'], 400);
        }

        try {
            getDb()->prepare("INSERT INTO fonts(name, css_value, import_url) VALUES(?, ?, ?)")
                ->execute([$name, $cssValue, $importUrl ?: null]);
            jsonResponse(['success' => true]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Font name already exists'], 409);
        }
    }

    if ($path === '/api/admin/fonts/delete' && $method === 'POST') {
        requireAdmin();
        $fontId = (int)($input['id'] ?? 0);
        if ($fontId <= 1) {
            jsonResponse(['error' => 'Cannot delete default system font'], 400);
        }

        $db = getDb();
        $db->prepare("UPDATE users SET font_id = 1 WHERE font_id = ?")->execute([$fontId]);
        $db->prepare("DELETE FROM fonts WHERE id = ?")->execute([$fontId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/verification_requests' && $method === 'GET') {
        requireAdmin();
        $requests = getDb()->query("
            SELECT vr.*, u.username
            FROM verification_requests vr
            JOIN users u ON vr.user_id = u.id
            ORDER BY CASE vr.status WHEN 'pending' THEN 0 ELSE 1 END, vr.created_at DESC
            LIMIT 100
        ")->fetchAll();
        jsonResponse(['requests' => $requests]);
    }

    if ($path === '/api/admin/verification_requests/approve' && $method === 'POST') {
        requireAdmin();
        $requestId = (int)($input['request_id'] ?? 0);
        $db = getDb();
        $stmt = $db->prepare("SELECT * FROM verification_requests WHERE id = ? AND status = 'pending'");
        $stmt->execute([$requestId]);
        $req = $stmt->fetch();
        if (!$req) jsonResponse(['error' => 'Request not found or already processed'], 404);
        $db->prepare("UPDATE users SET is_verified = 1 WHERE id = ?")->execute([$req['user_id']]);
        $db->prepare("UPDATE verification_requests SET status = 'approved' WHERE id = ?")->execute([$requestId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/verification_requests/reject' && $method === 'POST') {
        requireAdmin();
        $requestId = (int)($input['request_id'] ?? 0);
        $db = getDb();
        $db->prepare("UPDATE verification_requests SET status = 'rejected' WHERE id = ? AND status = 'pending'")->execute([$requestId]);
        jsonResponse(['success' => true]);
    }

    if ($path === '/api/admin/support/send' && $method === 'POST') {
        $admin = requireAdmin();
        $title = trim($input['title'] ?? '');
        $body = trim($input['body'] ?? '');
        if (!$title || !$body) jsonResponse(['error' => 'Title and body required'], 400);
        $db = getDb();
        $db->prepare("INSERT INTO support_messages(title, body, created_by_admin) VALUES(?, ?, ?)")
            ->execute([$title, $body, $admin['id']]);
        jsonResponse(['success' => true, 'message_id' => (int)$db->lastInsertId()], 201);
    }

    if ($path === '/api/admin/support/list' && $method === 'GET') {
        requireAdmin();
        $messages = getDb()->query("SELECT * FROM support_messages ORDER BY created_at DESC LIMIT 100")->fetchAll();
        jsonResponse(['messages' => $messages]);
    }

    if (getenv('TEST_MODE') === 'true' || getenv('APP_ENV') === 'development') {
        if ($path === '/api/_test/seed') {
            validateHttpMethod($method, ['POST']);
            $db = getDb();
            $users = [];

            $testUsers = [
                ['username' => 'testuser1', 'password' => 'password123', 'is_admin' => 0],
                ['username' => 'testuser2', 'password' => 'password123', 'is_admin' => 0],
                ['username' => 'testadmin', 'password' => 'admin123', 'is_admin' => 1],
                ['username' => 'banneduser', 'password' => 'password123', 'is_admin' => 0, 'banned' => true],
            ];

            foreach ($testUsers as $userData) {
                $hash = password_hash($userData['password'], PASSWORD_DEFAULT, ['cost' => 10]);
                try {
                    $stmt = $db->prepare("INSERT INTO users(username, pass_hash, is_admin) VALUES(?, ?, ?)");
                    $stmt->execute([$userData['username'], $hash, $userData['is_admin']]);
                    $userId = $db->lastInsertId();

                    if (isset($userData['banned']) && $userData['banned']) {
                        $banUntil = gmdate('Y-m-d H:i:s', time() + 86400);
                        $db->prepare("UPDATE users SET ban_until = ? WHERE id = ?")->execute([$banUntil, $userId]);
                    }

                    $users[] = [
                        'id' => $userId,
                        'username' => $userData['username'],
                        'is_admin' => (bool)$userData['is_admin']
                    ];
                } catch (PDOException $e) {
                }
            }

            jsonResponse([
                'message' => 'Test data seeded',
                'users' => $users,
                'note' => 'All test users have password: password123 (except testadmin: admin123)'
            ], 201);
        }

        if ($path === '/api/_test/reset') {
            validateHttpMethod($method, ['DELETE']);
            $db = getDb();

            $db->exec("DELETE FROM messages");
            $db->exec("DELETE FROM convo_members");
            $db->exec("DELETE FROM convos");
            $db->exec("DELETE FROM invite_jti");
            $db->exec("DELETE FROM reports");
            $db->exec("DELETE FROM banned_words");
            $db->exec("DELETE FROM support_messages");
            $db->exec("DELETE FROM support_reads");
            $db->exec("DELETE FROM verification_requests");
            $db->exec("DELETE FROM refresh_tokens");
            $db->exec("DELETE FROM rate_limits");
            $db->exec("DELETE FROM admin_actions");
            $db->exec("DELETE FROM message_reads");
            $db->exec("DELETE FROM users");
            $db->exec("DELETE FROM themes");

            jsonResponse(['message' => 'Database reset complete'], 200);
        }

        if ($path === '/api/_test/users') {
            validateHttpMethod($method, ['GET']);
            $users = getDb()->query("SELECT id, username, is_admin, is_verified, ban_until FROM users")->fetchAll();
            jsonResponse(['users' => $users]);
        }
    }

    if ($path === '/api/pusher/config') {
        validateHttpMethod($method, ['GET']);
        $pusherConfig = [];
        if (getenv('PUSHER_KEY')) {
            $pusherConfig = [
                'key' => getenv('PUSHER_KEY'),
                'cluster' => getenv('PUSHER_CLUSTER') ?: 'us2',
                'enabled' => true
            ];
        } else {
            $pusherConfig = ['enabled' => false];
        }
        jsonResponse($pusherConfig);
    }

    if ($path === '/api/pusher/auth') {
        validateHttpMethod($method, ['POST']);
        $user = requireAuth();

        $socketId = $_POST['socket_id'] ?? $input['socket_id'] ?? '';
        $channelName = $_POST['channel_name'] ?? $input['channel_name'] ?? '';

        if (!$socketId || !$channelName) {
            jsonResponse(['error' => 'Missing socket_id or channel_name'], 400);
        }

        if (!preg_match('/^private-conversation-(\d+)$/', $channelName, $matches)) {
            jsonResponse(['error' => 'Invalid channel name'], 403);
        }

        $conversationId = (int)$matches[1];

        $db = getDb();
        $stmt = $db->prepare("SELECT 1 FROM convo_members WHERE convo_id = ? AND user_id = ?");
        $stmt->execute([$conversationId, $user['id']]);

        if (!$stmt->fetch()) {
            jsonResponse(['error' => 'Unauthorized'], 403);
        }

        $pusher = getPusher();
        if (!$pusher) {
            jsonResponse(['error' => 'Pusher not configured'], 500);
        }

        $auth = $pusher->socketAuth($channelName, $socketId);

        header('Content-Type: application/json');
        echo $auth;
        exit;
    }

    if ($path === '/api/pusher/typing') {
        validateHttpMethod($method, ['POST']);
        $user = requireAuth();

        $conversationId = (int)($input['convo_id'] ?? $input['conversation_id'] ?? 0);
        if (!$conversationId) {
            jsonResponse(['error' => 'Missing conversation_id'], 400);
        }

        $db = getDb();
        $stmt = $db->prepare("SELECT 1 FROM convo_members WHERE convo_id = ? AND user_id = ?");
        $stmt->execute([$conversationId, $user['id']]);

        if (!$stmt->fetch()) {
            jsonResponse(['error' => 'Unauthorized'], 403);
        }

        triggerPusherEvent(
            "private-conversation-{$conversationId}",
            'user-typing',
            [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'convo_id' => $conversationId
            ]
        );

        jsonResponse(['success' => true]);
    }

    if ($path === '/api/pusher/debug' && $method === 'GET') {
        requireAuth();
        $pusher = getPusher();
        jsonResponse([
            'pusher_enabled' => $pusher !== null,
            'has_app_id' => !empty(getenv('PUSHER_APP_ID')),
            'has_key' => !empty(getenv('PUSHER_KEY')),
            'has_secret' => !empty(getenv('PUSHER_SECRET')),
            'cluster' => getenv('PUSHER_CLUSTER') ?: 'us2'
        ]);
    }

    if (strpos($path, '/api/') === 0) {
        jsonResponse(['error' => 'Not found'], 404);
    }
}

initDb();

$uri = $_SERVER['REQUEST_URI'] ?? '';
if (strpos($uri, '/api/') !== false) {
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    handleApi();
    exit;
}

$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-$nonce' 'unsafe-eval' https://cdn.jsdelivr.net https://js.pusher.com https://unpkg.com; style-src 'nonce-$nonce' 'unsafe-inline' https:; font-src https: data:; img-src 'self' data: https://unpkg.com https://twemoji.maxcdn.com; connect-src 'self' wss://*.pusher.com https://sockjs.pusher.com https://*.pusher.com; frame-ancestors 'none'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="format-detection" content="telephone=no">
    <title>Messenger</title>
    <style nonce="<?php echo $nonce; ?>">
        /* ========================================
   CSS RESET & BASE - ES5/Legacy Compatible
   ======================================== */
        *,
        *:before,
        *:after {
            -webkit-box-sizing: border-box;
            -moz-box-sizing: border-box;
            box-sizing: border-box;
        }

        html,
        body,
        div,
        span,
        h1,
        h2,
        h3,
        p,
        a,
        img,
        ul,
        li,
        form,
        label,
        input,
        textarea,
        button {
            margin: 0;
            padding: 0;
            border: 0;
            font-size: 100%;
            font: inherit;
            vertical-align: baseline;
        }

        ul {
            list-style: none;
        }

        a {
            text-decoration: none;
            color: inherit;
        }

        button {
            background: none;
            cursor: pointer;
        }

        input,
        textarea,
        button {
            outline: none;
            font-family: inherit;
        }

        /* ========================================
   CSS VARIABLES - Theme System Integration
   ======================================== */
        :root {
            /* Messenger Lite Default Colors */
            --bg: #FFFFFF;
            --bg-secondary: #F2F3F5;
            --text: #111827;
            --text-secondary: #6B7280;
            --text-tertiary: #9CA3AF;
            --accent: #1877F2;
            --accent-hover: #1664D9;
            --divider: #E5E7EB;
            --bubble-incoming: #F0F2F5;
            --bubble-outgoing: #1877F2;
            --online: #22C55E;
            --danger: #EF4444;
            --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            --font-scale: 1;

            /* Safe areas for notched devices */
            --safe-top: 0px;
            --safe-bottom: 0px;
        }

        @supports (padding-top: env(safe-area-inset-top)) {
            :root {
                --safe-top: env(safe-area-inset-top);
                --safe-bottom: env(safe-area-inset-bottom);
            }
        }

        /* Theme variable mapping from admin system */
        html.themed {
            --bg: var(--app-bg-color, #FFFFFF);
            --text: var(--app-text-color, #111827);
            --accent: var(--app-accent-color, #1877F2);
            --font: var(--app-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif);
        }

        /* Twemoji Styles */
        img.emoji {
            height: 1.2em;
            width: 1.2em;
            margin: 0 .05em 0 .1em;
            vertical-align: -0.2em;
            pointer-events: none;
        }

        /* Reaction Picker (Floating Pill) */
        .reaction-picker {
            position: absolute;
            bottom: 100%;
            right: 0;
            background: var(--bg);
            border: 1px solid var(--divider);
            border-radius: 50px;
            padding: 4px;
            display: flex;
            gap: 4px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 10;
            margin-bottom: 8px;
            animation: popIn 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }

        .incoming .reaction-picker {
            right: auto;
            left: 0;
        }

        .reaction-option {
            font-size: 20px;
            padding: 4px 8px;
            cursor: pointer;
            transition: transform 0.1s;
            user-select: none;
        }

        .reaction-option:hover {
            transform: scale(1.3);
        }

        @keyframes popIn {
            from {
                opacity: 0;
                transform: scale(0.8) translateY(10px);
            }

            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        /* ========================================
           BUBBLE FIXES & EMOJI STYLES
           ======================================== */

        /* Wrapper to stack Bubble + Time vertically */
        .bubble-group {
            display: flex;
            flex-direction: column;
            max-width: 100%;
            /* Ensure it doesn't overflow */
        }

        .incoming .bubble-group {
            align-items: flex-start;
        }

        .outgoing .bubble-group {
            align-items: flex-end;
        }

        .message-bubble {
            /* Fix for "width not content aware" */
            width: -webkit-fit-content;
            width: -moz-fit-content;
            width: fit-content !important;
            min-width: auto !important;
            /* Allow small bubbles */
            max-width: 100% !important;
            /* Let parent control max width */
            display: block;
            /* Ensure text wraps normally */

            /* Improve visual roundness */
            border-radius: 20px;
        }

        /* Time & Status outside the bubble */
        .message-meta {
            font-size: 11px;
            color: var(--text-tertiary);
            margin-top: 2px;
            margin-bottom: 2px;
            display: flex;
            align-items: center;
            gap: 4px;
            opacity: 0.7;
            /* Subtle look */
            padding: 0 4px;
        }

        /* Emoji-Only Message Styles */
        .message-bubble.emoji-msg {
            background: transparent !important;
            box-shadow: none !important;
            padding: 0 !important;
            margin-bottom: 0;
            /* FIX: Removed negative margin to prevent overlap */
            line-height: 1.2;
            /* Optional: Ensure line-height prevents clipping */
        }

        .message-bubble.emoji-msg .message-text {
            font-size: 40px !important;
            /* Large Emoji */
            line-height: 1.1;
        }

        /* Hide timestamp for emoji messages to keep it clean (Optional) */
        .message-bubble.emoji-msg .message-time {
            display: none;
        }

        /* Reaction Display on Message Bubble */
        .message-bubble {
            position: relative;
        }

        .message-reactions {
            position: absolute;
            bottom: -10px;
            right: 0;
            background: var(--bg);
            border: 1px solid var(--divider);
            border-radius: 10px;
            padding: 2px 6px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 2px;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
            z-index: 5;
            cursor: pointer;
        }

        .incoming .message-reactions {
            right: auto;
            left: 0;
        }

        .reaction-count {
            color: var(--text-secondary);
            font-size: 11px;
            margin-left: 2px;
        }

        /* Reaction Trigger Button */
        .reaction-trigger-btn {
            opacity: 0;
            transition: opacity 0.2s;
            padding: 8px;
            /* Increased padding */
            cursor: pointer;
            color: var(--text-tertiary);
            display: flex;
            align-items: center;
            z-index: 10;
            /* Ensure it's on top */
            margin-bottom: 22px;
            /* FIX: Lift the button up to offset the timestamp height */
        }

        .message-row:hover .reaction-trigger-btn,
        .message-row.reaction-active .reaction-trigger-btn {
            opacity: 1;
        }

        /* Always show on touch devices */
        @media (hover: none) {
            .reaction-trigger-btn {
                opacity: 1;
            }
        }

        .message-content-wrapper {
            display: flex;
            align-items: center;
            gap: 8px;
            position: relative;
        }

        .incoming .message-content-wrapper {
            flex-direction: row;
        }

        .outgoing .message-content-wrapper {
            flex-direction: row-reverse;
        }

        /* ========================================
   BASE STYLES
   ======================================== */
        html {
            height: 100%;
            -webkit-text-size-adjust: 100%;
            -ms-text-size-adjust: 100%;
        }

        body {
            height: 100%;
            font-family: var(--font);
            font-size: 16px;
            line-height: 1.4;
            color: var(--text);
            background-color: var(--bg);
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            overflow: hidden;
        }

        /* Hide app until Vue loads */
        [v-cloak] {
            display: none !important;
        }

        /* ========================================
   APP CONTAINER
   ======================================== */
        .app {
            height: 100%;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-orient: vertical;
            -webkit-flex-direction: column;
            -ms-flex-direction: column;
            flex-direction: column;
            position: relative;
            overflow: hidden;
        }

        /* ========================================
   LOADING SCREEN
   ======================================== */
        .loading-screen {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--bg);
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            z-index: 9999;
        }

        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--divider);
            border-top-color: var(--accent);
            border-radius: 50%;
            -webkit-animation: spin 0.8s linear infinite;
            animation: spin 0.8s linear infinite;
        }

        @-webkit-keyframes spin {
            to {
                -webkit-transform: rotate(360deg);
                transform: rotate(360deg);
            }
        }

        @keyframes spin {
            to {
                -webkit-transform: rotate(360deg);
                transform: rotate(360deg);
            }
        }

        /* ========================================
   HEADER - Messenger Lite Style
   ======================================== */
        .header {
            height: 52px;
            min-height: 52px;
            padding-top: var(--safe-top);
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: justify;
            -webkit-justify-content: space-between;
            -ms-flex-pack: justify;
            justify-content: space-between;
            padding-left: 16px;
            padding-right: 8px;
            background: var(--bg);
            border-bottom: 1px solid var(--divider);
            position: relative;
            z-index: 100;
        }

        .header-title {
            font-size: 20px;
            font-weight: 700;
            color: var(--text);
        }

        .header-actions {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            gap: 4px;
        }

        /* ========================================
   ICON BUTTON
   ======================================== */
        .icon-btn {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            color: var(--text);
            background: transparent;
            -webkit-transition: background 0.15s;
            transition: background 0.15s;
            position: relative;
        }

        .icon-btn:hover,
        .icon-btn:active {
            background: var(--bg-secondary);
        }

        .icon-btn svg {
            width: 22px;
            height: 22px;
            fill: currentColor;
        }

        .icon-btn .badge {
            position: absolute;
            top: 4px;
            right: 4px;
            min-width: 18px;
            height: 18px;
            padding: 0 5px;
            border-radius: 9px;
            background: var(--danger);
            color: #fff;
            font-size: 11px;
            font-weight: 600;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
        }

        /* ========================================
   SEARCH BAR
   ======================================== */
        .search-bar {
            padding: 8px 16px;
            background: var(--bg);
        }

        .search-input-wrap {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            height: 36px;
            padding: 0 12px;
            background: var(--bg-secondary);
            border-radius: 18px;
        }

        .search-input-wrap svg {
            width: 16px;
            height: 16px;
            fill: var(--text-secondary);
            margin-right: 8px;
            -webkit-flex-shrink: 0;
            -ms-flex-negative: 0;
            flex-shrink: 0;
        }

        .search-input {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            height: 100%;
            background: transparent;
            color: var(--text);
            font-size: 15px;
        }

        .search-input::-webkit-input-placeholder {
            color: var(--text-secondary);
        }

        .search-input::-moz-placeholder {
            color: var(--text-secondary);
        }

        .search-input:-ms-input-placeholder {
            color: var(--text-secondary);
        }

        .search-input::placeholder {
            color: var(--text-secondary);
        }

        /* ========================================
   ACTIVE NOW ROW
   ======================================== */
        .active-now {
            padding: 12px 0;
            border-bottom: 1px solid var(--divider);
        }

        .active-now-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            padding: 0 16px;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .active-now-scroll {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            overflow-x: auto;
            overflow-y: hidden;
            padding: 0 12px;
            -webkit-overflow-scrolling: touch;
            scrollbar-width: none;
            -ms-overflow-style: none;
        }

        .active-now-scroll::-webkit-scrollbar {
            display: none;
        }

        .active-user {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-orient: vertical;
            -webkit-flex-direction: column;
            -ms-flex-direction: column;
            flex-direction: column;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            margin: 0 4px;
            padding: 4px;
            min-width: 64px;
            cursor: pointer;
        }

        .active-user-avatar {
            position: relative;
            margin-bottom: 4px;
        }

        .active-user-name {
            font-size: 12px;
            color: var(--text-secondary);
            max-width: 60px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            text-align: center;
        }

        /* ========================================
   AVATAR
   ======================================== */
        .avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            color: #fff;
            font-size: 18px;
            font-weight: 600;
            text-transform: uppercase;
            -webkit-flex-shrink: 0;
            -ms-flex-negative: 0;
            flex-shrink: 0;
            position: relative;
        }

        .avatar-sm {
            width: 36px;
            height: 36px;
            font-size: 14px;
        }

        .avatar-md {
            width: 44px;
            height: 44px;
            font-size: 16px;
        }

        .avatar-lg {
            width: 56px;
            height: 56px;
            font-size: 20px;
        }

        .online-dot {
            position: absolute;
            bottom: 0;
            right: 0;
            width: 14px;
            height: 14px;
            background: var(--online);
            border: 2px solid var(--bg);
            border-radius: 50%;
        }

        .online-dot-sm {
            width: 12px;
            height: 12px;
        }

        /* ========================================
   CONTENT AREA
   ======================================== */
        .content {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            overflow: hidden;
            position: relative;
        }

        /* ========================================
   CHAT LIST
   ======================================== */
        .chat-list {
            height: 100%;
            overflow-y: auto;
            overflow-x: hidden;
            -webkit-overflow-scrolling: touch;
        }

        .chat-item {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            padding: 10px 16px;
            cursor: pointer;
            -webkit-transition: background 0.15s;
            transition: background 0.15s;
        }

        .chat-item:hover,
        .chat-item:active {
            background: var(--bg-secondary);
        }

        .chat-item.active {
            background: #E7F3FF;
        }

        .chat-item.unread .chat-name {
            font-weight: 700;
        }

        .chat-item.unread .chat-preview {
            color: var(--text);
            font-weight: 500;
        }

        .chat-avatar {
            margin-right: 12px;
        }

        .chat-info {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            min-width: 0;
            margin-right: 8px;
        }

        .chat-name-row {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            margin-bottom: 2px;
        }

        .chat-name {
            font-size: 15px;
            font-weight: 500;
            color: var(--text);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .verified-badge {
            margin-left: 4px;
            color: var(--accent);
            -webkit-flex-shrink: 0;
            -ms-flex-negative: 0;
            flex-shrink: 0;
        }

        .verified-badge svg {
            width: 14px;
            height: 14px;
            fill: currentColor;
        }

        .chat-preview {
            font-size: 14px;
            color: var(--text-secondary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .chat-meta {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-orient: vertical;
            -webkit-flex-direction: column;
            -ms-flex-direction: column;
            flex-direction: column;
            -webkit-box-align: end;
            -webkit-align-items: flex-end;
            -ms-flex-align: end;
            align-items: flex-end;
            -webkit-flex-shrink: 0;
            -ms-flex-negative: 0;
            flex-shrink: 0;
        }

        .chat-time {
            font-size: 12px;
            color: var(--text-tertiary);
            margin-bottom: 4px;
        }

        .unread-badge {
            min-width: 20px;
            height: 20px;
            padding: 0 6px;
            border-radius: 10px;
            background: var(--accent);
            color: #fff;
            font-size: 12px;
            font-weight: 600;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
        }

        /* ========================================
   EMPTY STATE
   ======================================== */
        .empty-state {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-orient: vertical;
            -webkit-flex-direction: column;
            -ms-flex-direction: column;
            flex-direction: column;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            height: 100%;
            padding: 40px 24px;
            text-align: center;
        }

        .empty-state svg {
            width: 64px;
            height: 64px;
            fill: var(--text-tertiary);
            margin-bottom: 16px;
        }

        .empty-state-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 8px;
        }

        .empty-state-text {
            font-size: 14px;
            color: var(--text-secondary);
        }

        /* ========================================
   FAB (Floating Action Button)
   ======================================== */
        .fab {
            position: fixed;
            bottom: 24px;
            right: 24px;
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: var(--accent);
            color: #fff;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            -webkit-transition: background 0.15s, -webkit-transform 0.15s;
            transition: background 0.15s, transform 0.15s;
            z-index: 50;
            padding-bottom: var(--safe-bottom);
        }

        .fab:hover {
            background: var(--accent-hover);
        }

        .fab:active {
            -webkit-transform: scale(0.95);
            transform: scale(0.95);
        }

        .fab svg {
            width: 24px;
            height: 24px;
            fill: currentColor;
        }

        /* ========================================
   CHAT VIEW
   ======================================== */
        .chat-view {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--bg);
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-orient: vertical;
            -webkit-flex-direction: column;
            -ms-flex-direction: column;
            flex-direction: column;
            z-index: 200;
        }

        .chat-header {
            height: 52px;
            min-height: 52px;
            padding-top: var(--safe-top);
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            padding-left: 4px;
            padding-right: 8px;
            background: var(--bg);
            border-bottom: 1px solid var(--divider);
        }

        .back-btn {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            color: var(--accent);
            background: transparent;
            margin-right: 4px;
        }

        .back-btn:active {
            background: var(--bg-secondary);
        }

        .back-btn svg {
            width: 24px;
            height: 24px;
            fill: currentColor;
        }

        .chat-header-info {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            min-width: 0;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
        }

        .chat-header-avatar {
            margin-right: 10px;
        }

        .chat-header-text {
            min-width: 0;
        }

        .chat-header-name {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            font-size: 16px;
            font-weight: 600;
            color: var(--text);
        }

        .chat-header-status {
            font-size: 12px;
            color: var(--text-secondary);
        }

        .chat-header-status.online {
            color: var(--online);
        }

        /* ========================================
   MESSAGES
   ======================================== */
        .messages-container {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            overflow-y: auto;
            overflow-x: hidden;
            padding: 16px;
            -webkit-overflow-scrolling: touch;
        }

        .message-row {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            margin-bottom: 4px;
        }

        .message-row.incoming {
            -webkit-box-pack: start;
            -webkit-justify-content: flex-start;
            -ms-flex-pack: start;
            justify-content: flex-start;
        }

        .message-row.outgoing {
            -webkit-box-pack: end;
            -webkit-justify-content: flex-end;
            -ms-flex-pack: end;
            justify-content: flex-end;
        }

        .message-bubble {
            max-width: 75%;
            padding: 8px 12px;
            border-radius: 18px;
            word-wrap: break-word;
            word-break: break-word;
        }

        .message-row.incoming .message-bubble {
            background: var(--bubble-incoming);
            color: var(--text);
            border-bottom-left-radius: 4px;
        }

        .message-row.outgoing .message-bubble {
            background: var(--bubble-outgoing);
            color: #fff;
            border-bottom-right-radius: 4px;
        }

        .message-text {
            font-size: 15px;
            line-height: 1.35;
            white-space: pre-wrap;
        }

        .message-time {
            font-size: 11px;
            margin-top: 4px;
            text-align: right;
        }

        .message-row.incoming .message-time {
            color: var(--text-tertiary);
        }

        .message-row.outgoing .message-time {
            color: rgba(255, 255, 255, 0.7);
        }

        .message-status {
            display: -webkit-inline-box;
            display: -webkit-inline-flex;
            display: -ms-inline-flexbox;
            display: inline-flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            margin-left: 4px;
        }

        .message-status svg {
            width: 14px;
            height: 14px;
            fill: currentColor;
        }

        .message-status.read {
            color: rgba(255, 255, 255, 0.9);
        }

        .message-status.delivered {
            color: rgba(255, 255, 255, 0.6);
        }

        .message-status.sent {
            color: rgba(255, 255, 255, 0.5);
        }

        /* Typing indicator */
        .typing-indicator {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            padding: 12px 16px;
            background: var(--bubble-incoming);
            border-radius: 18px;
            border-bottom-left-radius: 4px;
            max-width: 80px;
        }

        .typing-dot {
            width: 8px;
            height: 8px;
            background: var(--text-tertiary);
            border-radius: 50%;
            margin: 0 2px;
            -webkit-animation: typingBounce 1.4s ease-in-out infinite;
            animation: typingBounce 1.4s ease-in-out infinite;
        }

        .typing-dot:nth-child(2) {
            -webkit-animation-delay: 0.2s;
            animation-delay: 0.2s;
        }

        .typing-dot:nth-child(3) {
            -webkit-animation-delay: 0.4s;
            animation-delay: 0.4s;
        }

        @-webkit-keyframes typingBounce {

            0%,
            60%,
            100% {
                -webkit-transform: translateY(0);
                transform: translateY(0);
            }

            30% {
                -webkit-transform: translateY(-4px);
                transform: translateY(-4px);
            }
        }

        @keyframes typingBounce {

            0%,
            60%,
            100% {
                -webkit-transform: translateY(0);
                transform: translateY(0);
            }

            30% {
                -webkit-transform: translateY(-4px);
                transform: translateY(-4px);
            }
        }

        /* ========================================
   COMPOSER
   ======================================== */
        .composer {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: end;
            -webkit-align-items: flex-end;
            -ms-flex-align: end;
            align-items: flex-end;
            padding: 8px 12px;
            padding-bottom: calc(8px + var(--safe-bottom));
            background: var(--bg);
            border-top: 1px solid var(--divider);
            gap: 8px;
        }

        .composer-input-wrap {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: end;
            -webkit-align-items: flex-end;
            -ms-flex-align: end;
            align-items: flex-end;
            min-height: 40px;
            padding: 8px 16px;
            background: var(--bg-secondary);
            border-radius: 20px;
        }

        .composer-input {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            max-height: 100px;
            background: transparent;
            color: var(--text);
            font-size: 16px;
            line-height: 1.35;
            resize: none;
            border: none;
        }

        .composer-input::-webkit-input-placeholder {
            color: var(--text-secondary);
        }

        .composer-input::-moz-placeholder {
            color: var(--text-secondary);
        }

        .composer-input:-ms-input-placeholder {
            color: var(--text-secondary);
        }

        .composer-input::placeholder {
            color: var(--text-secondary);
        }

        .send-btn {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--accent);
            color: #fff;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            -webkit-flex-shrink: 0;
            -ms-flex-negative: 0;
            flex-shrink: 0;
            -webkit-transition: opacity 0.15s;
            transition: opacity 0.15s;
        }

        .send-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .send-btn svg {
            width: 20px;
            height: 20px;
            fill: currentColor;
            margin-left: 2px;
        }

        /* ========================================
   SETTINGS PANEL
   ======================================== */
        .panel {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--bg);
            z-index: 300;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-orient: vertical;
            -webkit-flex-direction: column;
            -ms-flex-direction: column;
            flex-direction: column;
        }

        .panel-header {
            height: 52px;
            min-height: 52px;
            padding-top: var(--safe-top);
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: justify;
            -webkit-justify-content: space-between;
            -ms-flex-pack: justify;
            justify-content: space-between;
            padding-left: 16px;
            padding-right: 8px;
            background: var(--bg);
            border-bottom: 1px solid var(--divider);
        }

        .panel-title {
            font-size: 20px;
            font-weight: 700;
            color: var(--text);
        }

        .panel-content {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            overflow-y: auto;
            padding: 16px;
            padding-bottom: calc(16px + var(--safe-bottom));
            -webkit-overflow-scrolling: touch;
        }

        /* Settings sections */
        .settings-section {
            margin-bottom: 24px;
        }

        .settings-section-title {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 0 4px;
            margin-bottom: 8px;
        }

        .settings-card {
            background: var(--bg);
            border: 1px solid var(--divider);
            border-radius: 12px;
            overflow: hidden;
        }

        .settings-row {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: justify;
            -webkit-justify-content: space-between;
            -ms-flex-pack: justify;
            justify-content: space-between;
            padding: 14px 16px;
            border-bottom: 1px solid var(--divider);
        }

        .settings-row:last-child {
            border-bottom: none;
        }

        .settings-label {
            font-size: 15px;
            color: var(--text);
        }

        .settings-control {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            gap: 8px;
        }

        .font-scale-btn {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--bg-secondary);
            color: var(--text);
            font-size: 18px;
            font-weight: 600;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
        }

        .font-scale-btn:active {
            background: var(--divider);
        }

        .font-scale-value {
            min-width: 50px;
            text-align: center;
            font-size: 14px;
            color: var(--text-secondary);
        }

        .select-control {
            padding: 8px 12px;
            padding-right: 32px;
            border-radius: 8px;
            border: 1px solid var(--divider);
            background: var(--bg);
            color: var(--text);
            font-size: 14px;
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='%236B7280' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10l-5 5z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 8px center;
            min-width: 120px;
        }

        /* ========================================
   AUTH SCREEN
   ======================================== */
        .auth-container {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            padding: 24px;
        }

        .auth-box {
            width: 100%;
            max-width: 360px;
        }

        .auth-logo {
            text-align: center;
            margin-bottom: 32px;
        }

        .auth-logo svg {
            width: 64px;
            height: 64px;
            fill: var(--accent);
        }

        .auth-title {
            font-size: 28px;
            font-weight: 700;
            text-align: center;
            margin-bottom: 8px;
            color: var(--text);
        }

        .auth-subtitle {
            font-size: 14px;
            text-align: center;
            color: var(--text-secondary);
            margin-bottom: 24px;
        }

        .auth-tabs {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            margin-bottom: 20px;
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 4px;
        }

        .auth-tab {
            -webkit-box-flex: 1;
            -webkit-flex: 1;
            -ms-flex: 1;
            flex: 1;
            padding: 10px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-secondary);
            background: transparent;
            -webkit-transition: background 0.15s, color 0.15s;
            transition: background 0.15s, color 0.15s;
        }

        .auth-tab.active {
            background: var(--bg);
            color: var(--text);
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .auth-error {
            padding: 12px;
            border-radius: 8px;
            background: #FEE2E2;
            border: 1px solid #FECACA;
            color: #DC2626;
            font-size: 14px;
            margin-bottom: 16px;
            text-align: center;
        }

        .auth-form .input {
            width: 100%;
            height: 48px;
            padding: 0 16px;
            border-radius: 8px;
            border: 1px solid var(--divider);
            background: var(--bg);
            color: var(--text);
            font-size: 16px;
            margin-bottom: 12px;
            -webkit-transition: border-color 0.15s;
            transition: border-color 0.15s;
        }

        .auth-form .input:focus {
            border-color: var(--accent);
        }

        .auth-form .input::-webkit-input-placeholder {
            color: var(--text-secondary);
        }

        .auth-form .input::-moz-placeholder {
            color: var(--text-secondary);
        }

        .auth-form .input:-ms-input-placeholder {
            color: var(--text-secondary);
        }

        .auth-form .input::placeholder {
            color: var(--text-secondary);
        }

        /* ========================================
   BUTTONS
   ======================================== */
        .btn {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            height: 48px;
            padding: 0 24px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            -webkit-transition: background 0.15s, opacity 0.15s;
            transition: background 0.15s, opacity 0.15s;
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .btn-primary {
            background: var(--accent);
            color: #fff;
        }

        .btn-primary:hover:not(:disabled) {
            background: var(--accent-hover);
        }

        .btn-secondary {
            background: var(--bg-secondary);
            color: var(--text);
        }

        .btn-secondary:hover:not(:disabled) {
            background: var(--divider);
        }

        .btn-danger {
            background: var(--danger);
            color: #fff;
        }

        .btn-block {
            width: 100%;
        }

        /* ========================================
   MODAL
   ======================================== */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: center;
            -webkit-justify-content: center;
            -ms-flex-pack: center;
            justify-content: center;
            padding: 24px;
            z-index: 400;
        }

        .modal {
            width: 100%;
            max-width: 360px;
            background: var(--bg);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
        }

        .modal-title {
            font-size: 18px;
            font-weight: 700;
            color: var(--text);
            margin-bottom: 8px;
        }

        .modal-text {
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.5;
            margin-bottom: 16px;
        }

        .modal-code {
            padding: 12px;
            border-radius: 8px;
            background: var(--bg-secondary);
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            margin-bottom: 16px;
            color: var(--text);
        }

        .modal textarea,
        .modal input[type="text"],
        .modal input[type="password"] {
            width: 100%;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid var(--divider);
            background: var(--bg);
            color: var(--text);
            font-size: 14px;
            margin-bottom: 12px;
        }

        .modal textarea {
            min-height: 80px;
            resize: vertical;
        }

        .modal-actions {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            gap: 8px;
            -webkit-box-pack: end;
            -webkit-justify-content: flex-end;
            -ms-flex-pack: end;
            justify-content: flex-end;
        }

        .modal-actions .btn {
            height: 40px;
            padding: 0 16px;
            font-size: 14px;
        }

        /* ========================================
   TOAST
   ======================================== */
        .toast {
            position: fixed;
            left: 50%;
            bottom: 80px;
            -webkit-transform: translateX(-50%);
            transform: translateX(-50%);
            padding: 12px 20px;
            border-radius: 8px;
            background: #333;
            color: #fff;
            font-size: 14px;
            font-weight: 500;
            z-index: 500;
            max-width: 90%;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }

        .toast-success {
            background: #059669;
        }

        .toast-error {
            background: #DC2626;
        }

        .toast-info {
            background: #2563EB;
        }

        /* ========================================
   ADMIN PANEL
   ======================================== */
        .admin-tabs {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            gap: 8px;
            -webkit-flex-wrap: wrap;
            -ms-flex-wrap: wrap;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }

        .admin-tab {
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            background: var(--bg-secondary);
            color: var(--text-secondary);
        }

        .admin-tab.active {
            background: var(--accent);
            color: #fff;
        }

        .admin-list {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-orient: vertical;
            -webkit-flex-direction: column;
            -ms-flex-direction: column;
            flex-direction: column;
            gap: 10px;
        }

        .admin-item {
            padding: 14px;
            border-radius: 10px;
            background: var(--bg);
            border: 1px solid var(--divider);
        }

        .admin-item-header {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            -webkit-box-align: center;
            -webkit-align-items: center;
            -ms-flex-align: center;
            align-items: center;
            -webkit-box-pack: justify;
            -webkit-justify-content: space-between;
            -ms-flex-pack: justify;
            justify-content: space-between;
            margin-bottom: 8px;
        }

        .status-badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-pending {
            background: #FEF3C7;
            color: #D97706;
        }

        .status-actioned {
            background: #D1FAE5;
            color: #059669;
        }

        .status-rejected {
            background: #FEE2E2;
            color: #DC2626;
        }

        .status-approved {
            background: #D1FAE5;
            color: #059669;
        }

        .admin-item-actions {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            gap: 8px;
            -webkit-flex-wrap: wrap;
            -ms-flex-wrap: wrap;
            flex-wrap: wrap;
            margin-top: 12px;
        }

        .admin-item-actions button {
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            color: #fff;
        }

        .admin-form {
            display: -webkit-box;
            display: -webkit-flex;
            display: -ms-flexbox;
            display: flex;
            gap: 8px;
            -webkit-flex-wrap: wrap;
            -ms-flex-wrap: wrap;
            flex-wrap: wrap;
            margin-bottom: 16px;
            padding: 16px;
            background: var(--bg-secondary);
            border-radius: 10px;
        }

        .admin-form input,
        .admin-form select,
        .admin-form textarea {
            padding: 10px 12px;
            border-radius: 6px;
            border: 1px solid var(--divider);
            background: var(--bg);
            color: var(--text);
            font-size: 14px;
        }

        /* ========================================
   DESKTOP LAYOUT
   ======================================== */
        @media (min-width: 900px) {
            .app-desktop {
                -webkit-box-orient: horizontal;
                -webkit-flex-direction: row;
                -ms-flex-direction: row;
                flex-direction: row;
            }

            .sidebar {
                width: 360px;
                min-width: 360px;
                border-right: 1px solid var(--divider);
                display: -webkit-box;
                display: -webkit-flex;
                display: -ms-flexbox;
                display: flex;
                -webkit-box-orient: vertical;
                -webkit-flex-direction: column;
                -ms-flex-direction: column;
                flex-direction: column;
                height: 100%;
            }

            .main-panel {
                -webkit-box-flex: 1;
                -webkit-flex: 1;
                -ms-flex: 1;
                flex: 1;
                display: -webkit-box;
                display: -webkit-flex;
                display: -ms-flexbox;
                display: flex;
                -webkit-box-orient: vertical;
                -webkit-flex-direction: column;
                -ms-flex-direction: column;
                flex-direction: column;
            }

            .desktop-placeholder {
                -webkit-box-flex: 1;
                -webkit-flex: 1;
                -ms-flex: 1;
                flex: 1;
                display: -webkit-box;
                display: -webkit-flex;
                display: -ms-flexbox;
                display: flex;
                -webkit-box-align: center;
                -webkit-align-items: center;
                -ms-flex-align: center;
                align-items: center;
                -webkit-box-pack: center;
                -webkit-justify-content: center;
                -ms-flex-pack: center;
                justify-content: center;
                background: var(--bg-secondary);
            }

            .desktop-placeholder-text {
                font-size: 18px;
                color: var(--text-secondary);
            }

            .chat-view.desktop {
                position: relative;
                z-index: 1;
            }
        }
    </style>
</head>

<body>
    <div id="app" class="app" v-bind:class="{'app-desktop': isDesktop}" v-cloak>
        <!-- Loading Screen -->
        <div v-if="view === 'loading'" class="loading-screen">
            <div class="loading-spinner"></div>
        </div>

        <!-- Auth Screen -->
        <template v-if="view === 'auth'">
            <div class="auth-container">
                <div class="auth-box">
                    <div class="auth-logo">
                        <svg viewBox="0 0 48 48">
                            <path d="M24 4C12.954 4 4 12.954 4 24c0 5.99 2.632 11.37 6.8 15.04V48l8.52-4.68c1.78.44 3.56.68 5.68.68 11.046 0 20-8.954 20-20S35.046 4 24 4zm2 27l-5.12-5.48L11 31l10.88-11.56L27.04 25 37 15L26 31z" />
                        </svg>
                    </div>
                    <h1 class="auth-title">Messenger</h1>
                    <p class="auth-subtitle">Connect with friends instantly</p>

                    <div class="auth-tabs">
                        <button class="auth-tab" v-bind:class="{active: authTab === 'login'}" v-on:click="authTab = 'login'; authError = ''">Sign In</button>
                        <button class="auth-tab" v-bind:class="{active: authTab === 'register'}" v-on:click="authTab = 'register'; authError = ''">Sign Up</button>
                    </div>

                    <div v-if="authError" class="auth-error">{{ authError }}</div>

                    <form class="auth-form" v-on:submit="handleAuth">
                        <input class="input" type="text" v-model="authForm.username" placeholder="Username" required minlength="3" maxlength="30" autocomplete="username">
                        <input class="input" type="password" v-model="authForm.password" placeholder="Password" required minlength="8" autocomplete="current-password">
                        <button class="btn btn-primary btn-block" type="submit" v-bind:disabled="authLoading">
                            {{ authLoading ? 'Please wait...' : (authTab === 'login' ? 'Sign In' : 'Create Account') }}
                        </button>
                    </form>
                </div>
            </div>
        </template>

        <!-- Main App (Desktop Layout) -->
        <template v-if="view !== 'loading' && view !== 'auth'">
            <!-- Mobile: Single View -->
            <template v-if="!isDesktop">
                <!-- Chats List -->
                <template v-if="view === 'chats'">
                    <div class="header">
                        <h1 class="header-title">Chats</h1>
                        <div class="header-actions">
                            <button class="icon-btn" v-on:click="openSupport" title="Support">
                                <svg viewBox="0 0 24 24">
                                    <path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z" />
                                </svg>
                                <span v-if="supportUnreadCount > 0" class="badge">{{ supportUnreadCount > 9 ? '9+' : supportUnreadCount }}</span>
                            </button>
                            <button class="icon-btn" v-on:click="showSettingsPanel = true" title="Settings">
                                <svg viewBox="0 0 24 24">
                                    <path d="M19.14 12.94c.04-.31.06-.63.06-.94 0-.31-.02-.63-.06-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22l-1.91 3.32c-.12.21-.08.47.12.61l2.03 1.58c-.04.31-.07.62-.07.94s.02.63.06.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z" />
                                </svg>
                            </button>
                            <button v-if="user && user.is_admin" class="icon-btn" v-on:click="showAdminPanel = true" title="Admin">
                                <svg viewBox="0 0 24 24">
                                    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
                                </svg>
                            </button>
                            <button class="icon-btn" v-on:click="logout" title="Sign Out">
                                <svg viewBox="0 0 24 24">
                                    <path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z" />
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div class="search-bar">
                        <div class="search-input-wrap">
                            <svg viewBox="0 0 24 24">
                                <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z" />
                            </svg>
                            <input class="search-input" type="text" v-model="searchQuery" placeholder="Search">
                        </div>
                    </div>

                    <!-- Active Now -->
                    <div v-if="activeUsers.length > 0" class="active-now">
                        <div class="active-now-title">Active Now</div>
                        <div class="active-now-scroll">
                            <div v-for="u in activeUsers" v-bind:key="u.id" class="active-user" v-on:click="openConvoByUser(u)">
                                <div class="active-user-avatar">
                                    <div class="avatar avatar-md">{{ getInitial(u.username) }}</div>
                                    <div class="online-dot online-dot-sm"></div>
                                </div>
                                <div class="active-user-name">{{ u.username }}</div>
                            </div>
                        </div>
                    </div>

                    <div class="content">
                        <div class="chat-list">
                            <div v-if="filteredConvos.length === 0" class="empty-state">
                                <svg viewBox="0 0 24 24">
                                    <path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z" />
                                </svg>
                                <div class="empty-state-title">No conversations yet</div>
                                <div class="empty-state-text">Tap the button below to start chatting</div>
                            </div>
                            <div v-for="c in filteredConvos" v-bind:key="c.id" class="chat-item" v-bind:class="{unread: c.unread_count > 0}" v-on:click="openConvo(c)">
                                <div class="chat-avatar">
                                    <div class="avatar">{{ getInitial(c.other_username) }}
                                        <div v-if="isUserOnline(c)" class="online-dot"></div>
                                    </div>
                                </div>
                                <div class="chat-info">
                                    <div class="chat-name-row">
                                        <span class="chat-name">{{ c.other_username || 'Waiting...' }}</span>
                                        <span v-if="c.other_verified" class="verified-badge">
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                                                <path fill-rule="evenodd" d="M8.603 3.799A4.49 4.49 0 0 1 12 2.25c1.357 0 2.573.6 3.397 1.549a4.49 4.49 0 0 1 3.498 1.307 4.491 4.491 0 0 1 1.307 3.497A4.49 4.49 0 0 1 21.75 12a4.49 4.49 0 0 1-1.549 3.397 4.491 4.491 0 0 1-1.307 3.497 4.491 4.491 0 0 1-3.497 1.307A4.49 4.49 0 0 1 12 21.75a4.49 4.49 0 0 1-3.397-1.549 4.49 4.49 0 0 1-3.498-1.306 4.491 4.491 0 0 1-1.307-3.498A4.49 4.49 0 0 1 2.25 12c0-1.357.6-2.573 1.549-3.397a4.49 4.49 0 0 1 1.307-3.497 4.49 4.49 0 0 1 3.497-1.307Zm7.007 6.387a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd" />
                                            </svg>

                                        </span>
                                    </div>
                                    <div class="chat-preview">Tap to open conversation</div>
                                </div>
                                <div class="chat-meta">
                                    <div v-if="c.unread_count > 0" class="unread-badge">{{ c.unread_count > 99 ? '99+' : c.unread_count }}</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <button class="fab" v-on:click="createInvite">
                        <svg viewBox="0 0 24 24">
                            <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" />
                        </svg>
                    </button>
                </template>

                <!-- Chat View Mobile -->
                <div v-if="view === 'chat'" class="chat-view">
                    <div class="chat-header">
                        <button class="back-btn" v-on:click="goBack">
                            <svg viewBox="0 0 24 24">
                                <path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z" />
                            </svg>
                        </button>
                        <div class="chat-header-info">
                            <div class="chat-header-avatar">
                                <div class="avatar avatar-sm">{{ getInitial(currentConvo ? currentConvo.other_username : '') }}</div>
                            </div>
                            <div class="chat-header-text">
                                <div class="chat-header-name">
                                    <span>{{ currentConvo ? currentConvo.other_username : 'Chat' }}</span>
                                    <span v-if="currentConvo && currentConvo.other_verified" class="verified-badge">
                                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                                            <path fill-rule="evenodd" d="M8.603 3.799A4.49 4.49 0 0 1 12 2.25c1.357 0 2.573.6 3.397 1.549a4.49 4.49 0 0 1 3.498 1.307 4.491 4.491 0 0 1 1.307 3.497A4.49 4.49 0 0 1 21.75 12a4.49 4.49 0 0 1-1.549 3.397 4.491 4.491 0 0 1-1.307 3.497 4.491 4.491 0 0 1-3.497 1.307A4.49 4.49 0 0 1 12 21.75a4.49 4.49 0 0 1-3.397-1.549 4.49 4.49 0 0 1-3.498-1.306 4.491 4.491 0 0 1-1.307-3.498A4.49 4.49 0 0 1 2.25 12c0-1.357.6-2.573 1.549-3.397a4.49 4.49 0 0 1 1.307-3.497 4.49 4.49 0 0 1 3.497-1.307Zm7.007 6.387a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd" />
                                        </svg>

                                    </span>
                                </div>
                                <div v-if="typingIndicator" class="chat-header-status">{{ typingIndicator }}</div>
                                <div v-else-if="activeStatus" class="chat-header-status" v-bind:class="{online: activeStatus === 'Online'}">{{ activeStatus }}</div>
                            </div>
                        </div>
                        <button v-if="currentConvo && currentConvo.other_user_id" class="icon-btn" v-on:click="showReportModal = true">
                            <svg viewBox="0 0 24 24">
                                <path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z" />
                            </svg>
                        </button>
                    </div>

                    <div class="messages-container" ref="messagesContainer">
                        <div v-if="messages.length === 0" class="empty-state">
                            <svg viewBox="0 0 24 24">
                                <path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z" />
                            </svg>
                            <div class="empty-state-title">Start the conversation!</div>
                            <div class="empty-state-text">Send a message to begin</div>
                        </div>
                        <div v-for="m in messages" v-bind:key="m.id" class="message-row" v-bind:class="{outgoing: m.is_mine, incoming: !m.is_mine, 'reaction-active': activeReactionMessageId === m.id}" @mouseleave="activeReactionMessageId = null">

                            <div class="message-content-wrapper">

                                <div class="bubble-group">

                                    <div class="message-bubble" v-bind:class="{'bubble-incoming': !m.is_mine, 'bubble-outgoing': m.is_mine, 'emoji-msg': isOnlyEmoji(m.body)}">
                                        <div class="message-text" v-bind:style="{fontSize: fontSizePx}">{{ m.body }}</div>

                                        <div v-if="m.reactions && m.reactions.length > 0" class="message-reactions" v-on:click.stop="toggleReactionPicker(m)">
                                            <span v-for="r in getUniqueReactions(m.reactions)" :key="r">{{ r }}</span>
                                            <span class="reaction-count" v-if="m.reactions.length > 1">{{ m.reactions.length }}</span>
                                        </div>

                                        <div v-if="activeReactionMessageId === m.id" class="reaction-picker">
                                            <div v-for="emoji in reactionEmojis" :key="emoji" class="reaction-option" v-on:click="reactToMessage(m, emoji)">
                                                {{ emoji }}
                                            </div>
                                        </div>
                                    </div>

                                    <div class="message-meta">
                                        <span class="message-time-text">{{ formatTime(m.created_at) }}</span>

                                        <span v-if="m.is_mine" class="message-status" v-bind:class="{read: m.is_read_by_other, delivered: m.is_delivered && !m.is_read_by_other, sent: !m.is_delivered}">
                                            <svg v-if="m.is_read_by_other" viewBox="0 0 24 24" style="width:14px;height:14px;fill:currentColor;">
                                                <path d="M18 7l-1.41-1.41-6.34 6.34 1.41 1.41L18 7zm4.24-1.41L11.66 16.17 7.48 12l-1.41 1.41L11.66 19l12-12-1.42-1.41zM.41 13.41L6 19l1.41-1.41L1.83 12 .41 13.41z" />
                                            </svg>
                                            <svg v-else-if="m.is_delivered" viewBox="0 0 24 24" style="width:14px;height:14px;fill:currentColor;">
                                                <path d="M18 7l-1.41-1.41-6.34 6.34 1.41 1.41L18 7zm4.24-1.41L11.66 16.17 7.48 12l-1.41 1.41L11.66 19l12-12-1.42-1.41z" />
                                            </svg>
                                            <svg v-else viewBox="0 0 24 24" style="width:14px;height:14px;fill:currentColor;">
                                                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
                                            </svg>
                                        </span>
                                    </div>

                                </div>
                                <div class="reaction-trigger-btn" v-on:click.stop="toggleReactionPicker(m)">
                                    <svg viewBox="0 0 24 24" style="width:18px;height:18px;fill:currentColor;">
                                        <path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11zm3.5 6.5c2.33 0 4.31-1.46 5.11-3.5H6.89c.8 2.04 2.78 3.5 5.11 3.5z" />
                                    </svg>
                                </div>
                            </div>
                        </div>
                        <div v-if="typingIndicator" class="message-row incoming">
                            <div class="typing-indicator">
                                <div class="typing-dot"></div>
                                <div class="typing-dot"></div>
                                <div class="typing-dot"></div>
                            </div>
                        </div>
                    </div>

                    <form class="composer" v-on:submit="sendMessage">
                        <div class="composer-input-wrap">
                            <input class="composer-input" type="text" v-model="messageInput" placeholder="Aa" maxlength="2000" v-on:input="handleTyping">
                        </div>
                        <button class="send-btn" type="submit" v-bind:disabled="!messageInput.trim()">
                            <svg viewBox="0 0 24 24">
                                <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
                            </svg>
                        </button>
                    </form>
                </div>
            </template>

            <!-- Desktop: Two Column Layout -->
            <template v-if="isDesktop">
                <div class="sidebar">
                    <div class="header">
                        <h1 class="header-title">Chats</h1>
                        <div class="header-actions">
                            <button class="icon-btn" v-on:click="openSupport" title="Support">
                                <svg viewBox="0 0 24 24">
                                    <path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z" />
                                </svg>
                                <span v-if="supportUnreadCount > 0" class="badge">{{ supportUnreadCount > 9 ? '9+' : supportUnreadCount }}</span>
                            </button>
                            <button class="icon-btn" v-on:click="showSettingsPanel = true" title="Settings">
                                <svg viewBox="0 0 24 24">
                                    <path d="M19.14 12.94c.04-.31.06-.63.06-.94 0-.31-.02-.63-.06-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22l-1.91 3.32c-.12.21-.08.47.12.61l2.03 1.58c-.04.31-.07.62-.07.94s.02.63.06.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z" />
                                </svg>
                            </button>
                            <button v-if="user && user.is_admin" class="icon-btn" v-on:click="showAdminPanel = true" title="Admin">
                                <svg viewBox="0 0 24 24">
                                    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
                                </svg>
                            </button>
                            <button class="icon-btn" v-on:click="logout" title="Sign Out">
                                <svg viewBox="0 0 24 24">
                                    <path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z" />
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div class="search-bar">
                        <div class="search-input-wrap">
                            <svg viewBox="0 0 24 24">
                                <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z" />
                            </svg>
                            <input class="search-input" type="text" v-model="searchQuery" placeholder="Search">
                        </div>
                    </div>

                    <div class="content">
                        <div class="chat-list">
                            <div v-if="filteredConvos.length === 0" class="empty-state">
                                <svg viewBox="0 0 24 24">
                                    <path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z" />
                                </svg>
                                <div class="empty-state-title">No conversations</div>
                                <div class="empty-state-text">Create an invite to start</div>
                            </div>
                            <div v-for="c in filteredConvos" v-bind:key="c.id" class="chat-item" v-bind:class="{active: currentConvo && currentConvo.id === c.id, unread: c.unread_count > 0}" v-on:click="openConvo(c)">
                                <div class="chat-avatar">
                                    <div class="avatar">{{ getInitial(c.other_username) }}
                                        <div v-if="isUserOnline(c)" class="online-dot"></div>
                                    </div>
                                </div>
                                <div class="chat-info">
                                    <div class="chat-name-row">
                                        <span class="chat-name">{{ c.other_username || 'Waiting...' }}</span>
                                        <span v-if="c.other_verified" class="verified-badge">
                                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                                                <path fill-rule="evenodd" d="M8.603 3.799A4.49 4.49 0 0 1 12 2.25c1.357 0 2.573.6 3.397 1.549a4.49 4.49 0 0 1 3.498 1.307 4.491 4.491 0 0 1 1.307 3.497A4.49 4.49 0 0 1 21.75 12a4.49 4.49 0 0 1-1.549 3.397 4.491 4.491 0 0 1-1.307 3.497 4.491 4.491 0 0 1-3.497 1.307A4.49 4.49 0 0 1 12 21.75a4.49 4.49 0 0 1-3.397-1.549 4.49 4.49 0 0 1-3.498-1.306 4.491 4.491 0 0 1-1.307-3.498A4.49 4.49 0 0 1 2.25 12c0-1.357.6-2.573 1.549-3.397a4.49 4.49 0 0 1 1.307-3.497 4.49 4.49 0 0 1 3.497-1.307Zm7.007 6.387a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd" />
                                            </svg>

                                        </span>
                                    </div>
                                    <div class="chat-preview">Tap to open conversation</div>
                                </div>
                                <div class="chat-meta">
                                    <div v-if="c.unread_count > 0" class="unread-badge">{{ c.unread_count > 99 ? '99+' : c.unread_count }}</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <button class="fab" v-on:click="createInvite" style="position: absolute; bottom: 24px; right: 24px;">
                        <svg viewBox="0 0 24 24">
                            <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" />
                        </svg>
                    </button>
                </div>

                <div class="main-panel">
                    <template v-if="currentConvo">
                        <div class="chat-view desktop">
                            <div class="chat-header">
                                <div class="chat-header-info" style="padding-left: 12px;">
                                    <div class="chat-header-avatar">
                                        <div class="avatar avatar-sm">{{ getInitial(currentConvo.other_username) }}</div>
                                    </div>
                                    <div class="chat-header-text">
                                        <div class="chat-header-name">
                                            <span>{{ currentConvo.other_username || 'Chat' }}</span>
                                            <span v-if="currentConvo.other_verified" class="verified-badge">
                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="size-6">
                                                    <path fill-rule="evenodd" d="M8.603 3.799A4.49 4.49 0 0 1 12 2.25c1.357 0 2.573.6 3.397 1.549a4.49 4.49 0 0 1 3.498 1.307 4.491 4.491 0 0 1 1.307 3.497A4.49 4.49 0 0 1 21.75 12a4.49 4.49 0 0 1-1.549 3.397 4.491 4.491 0 0 1-1.307 3.497 4.491 4.491 0 0 1-3.497 1.307A4.49 4.49 0 0 1 12 21.75a4.49 4.49 0 0 1-3.397-1.549 4.49 4.49 0 0 1-3.498-1.306 4.491 4.491 0 0 1-1.307-3.498A4.49 4.49 0 0 1 2.25 12c0-1.357.6-2.573 1.549-3.397a4.49 4.49 0 0 1 1.307-3.497 4.49 4.49 0 0 1 3.497-1.307Zm7.007 6.387a.75.75 0 1 0-1.22-.872l-3.236 4.53L9.53 12.22a.75.75 0 0 0-1.06 1.06l2.25 2.25a.75.75 0 0 0 1.14-.094l3.75-5.25Z" clip-rule="evenodd" />
                                                </svg>

                                            </span>
                                        </div>
                                        <div v-if="typingIndicator" class="chat-header-status">{{ typingIndicator }}</div>
                                        <div v-else-if="activeStatus" class="chat-header-status" v-bind:class="{online: activeStatus === 'Online'}">{{ activeStatus }}</div>
                                    </div>
                                </div>
                                <button v-if="currentConvo.other_user_id" class="icon-btn" v-on:click="showReportModal = true">
                                    <svg viewBox="0 0 24 24">
                                        <path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z" />
                                    </svg>
                                </button>
                            </div>

                            <div class="messages-container" ref="messagesContainer">
                                <div v-if="messages.length === 0" class="empty-state">
                                    <svg viewBox="0 0 24 24">
                                        <path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z" />
                                    </svg>
                                    <div class="empty-state-title">Start the conversation!</div>
                                    <div class="empty-state-text">Send a message to begin</div>
                                </div>
                                <div v-for="m in messages" v-bind:key="m.id" class="message-row" v-bind:class="{outgoing: m.is_mine, incoming: !m.is_mine, 'reaction-active': activeReactionMessageId === m.id}" @mouseleave="activeReactionMessageId = null">

                                    <div class="message-content-wrapper">

                                        <div class="bubble-group">

                                            <div class="message-bubble" v-bind:class="{'bubble-incoming': !m.is_mine, 'bubble-outgoing': m.is_mine, 'emoji-msg': isOnlyEmoji(m.body)}">
                                                <div class="message-text" v-bind:style="{fontSize: fontSizePx}">{{ m.body }}</div>

                                                <div v-if="m.reactions && m.reactions.length > 0" class="message-reactions" v-on:click.stop="toggleReactionPicker(m)">
                                                    <span v-for="r in getUniqueReactions(m.reactions)" :key="r">{{ r }}</span>
                                                    <span class="reaction-count" v-if="m.reactions.length > 1">{{ m.reactions.length }}</span>
                                                </div>

                                                <div v-if="activeReactionMessageId === m.id" class="reaction-picker">
                                                    <div v-for="emoji in reactionEmojis" :key="emoji" class="reaction-option" v-on:click="reactToMessage(m, emoji)">
                                                        {{ emoji }}
                                                    </div>
                                                </div>
                                            </div>

                                            <div class="message-meta">
                                                <span class="message-time-text">{{ formatTime(m.created_at) }}</span>

                                                <span v-if="m.is_mine" class="message-status" v-bind:class="{read: m.is_read_by_other, delivered: m.is_delivered && !m.is_read_by_other, sent: !m.is_delivered}">
                                                    <svg v-if="m.is_read_by_other" viewBox="0 0 24 24" style="width:14px;height:14px;fill:currentColor;">
                                                        <path d="M18 7l-1.41-1.41-6.34 6.34 1.41 1.41L18 7zm4.24-1.41L11.66 16.17 7.48 12l-1.41 1.41L11.66 19l12-12-1.42-1.41zM.41 13.41L6 19l1.41-1.41L1.83 12 .41 13.41z" />
                                                    </svg>
                                                    <svg v-else-if="m.is_delivered" viewBox="0 0 24 24" style="width:14px;height:14px;fill:currentColor;">
                                                        <path d="M18 7l-1.41-1.41-6.34 6.34 1.41 1.41L18 7zm4.24-1.41L11.66 16.17 7.48 12l-1.41 1.41L11.66 19l12-12-1.42-1.41z" />
                                                    </svg>
                                                    <svg v-else viewBox="0 0 24 24" style="width:14px;height:14px;fill:currentColor;">
                                                        <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
                                                    </svg>
                                                </span>
                                            </div>

                                        </div>
                                        <div class="reaction-trigger-btn" v-on:click.stop="toggleReactionPicker(m)">
                                            <svg viewBox="0 0 24 24" style="width:18px;height:18px;fill:currentColor;">
                                                <path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm3.5-9c.83 0 1.5-.67 1.5-1.5S16.33 8 15.5 8 14 8.67 14 9.5s.67 1.5 1.5 1.5zm-7 0c.83 0 1.5-.67 1.5-1.5S9.33 8 8.5 8 7 8.67 7 9.5 7.67 11 8.5 11zm3.5 6.5c2.33 0 4.31-1.46 5.11-3.5H6.89c.8 2.04 2.78 3.5 5.11 3.5z" />
                                            </svg>
                                        </div>
                                    </div>
                                </div>
                                <div v-if="typingIndicator" class="message-row incoming">
                                    <div class="typing-indicator">
                                        <div class="typing-dot"></div>
                                        <div class="typing-dot"></div>
                                        <div class="typing-dot"></div>
                                    </div>
                                </div>
                            </div>

                            <form class="composer" v-on:submit="sendMessage">
                                <div class="composer-input-wrap">
                                    <input class="composer-input" type="text" v-model="messageInput" placeholder="Aa" maxlength="2000" v-on:input="handleTyping">
                                </div>
                                <button class="send-btn" type="submit" v-bind:disabled="!messageInput.trim()">
                                    <svg viewBox="0 0 24 24">
                                        <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
                                    </svg>
                                </button>
                            </form>
                        </div>
                    </template>
                    <template v-else>
                        <div class="desktop-placeholder">
                            <div class="desktop-placeholder-text">Select a chat to start messaging</div>
                        </div>
                    </template>
                </div>
            </template>
        </template>

        <!-- Invite Modal -->
        <div v-if="showInviteModal" class="modal-overlay" v-on:click="closeInviteModal">
            <div class="modal" v-on:click="stopProp">
                <h2 class="modal-title">Invite Link</h2>
                <p class="modal-text">Share this link to start a conversation. The link expires in 24 hours.</p>
                <div class="modal-code">{{ inviteUrl }}</div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" v-on:click="showInviteModal = false">Cancel</button>
                    <button class="btn btn-primary" v-on:click="copyInvite">Copy Link</button>
                </div>
            </div>
        </div>

        <!-- Report Modal -->
        <div v-if="showReportModal" class="modal-overlay" v-on:click="closeReportModal">
            <div class="modal" v-on:click="stopProp">
                <h2 class="modal-title">Report User</h2>
                <p class="modal-text">Describe the issue. False reports may result in penalties.</p>
                <textarea v-model="reportReason" placeholder="Describe the issue..." maxlength="1000"></textarea>
                <div class="modal-actions">
                    <button class="btn btn-secondary" v-on:click="showReportModal = false">Cancel</button>
                    <button class="btn btn-danger" v-on:click="submitReport">Report</button>
                </div>
            </div>
        </div>

        <!-- Settings Panel -->
        <div v-if="showSettingsPanel" class="panel">
            <div class="panel-header">
                <h2 class="panel-title">Settings</h2>
                <button class="icon-btn" v-on:click="showSettingsPanel = false">
                    <svg viewBox="0 0 24 24">
                        <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
                    </svg>
                </button>
            </div>
            <div class="panel-content">
                <div class="settings-section">
                    <div class="settings-section-title">Appearance</div>
                    <div class="settings-card">
                        <div class="settings-row">
                            <span class="settings-label">Font Size</span>
                            <div class="settings-control">
                                <button class="font-scale-btn" v-on:click="decreaseFontScale">-</button>
                                <span class="font-scale-value">{{ fontScalePercent }}%</span>
                                <button class="font-scale-btn" v-on:click="increaseFontScale">+</button>
                            </div>
                        </div>
                        <div class="settings-row">
                            <span class="settings-label">Font</span>
                            <select class="select-control" v-model="selectedFontId" v-on:change="updateFont">
                                <option v-for="f in availableFonts" v-bind:key="f.id" v-bind:value="f.id">{{ f.name }}</option>
                            </select>
                        </div>
                        <div class="settings-row">
                            <span class="settings-label">Theme</span>
                            <select class="select-control" v-model="selectedThemeId" v-on:change="updateTheme">
                                <option v-bind:value="null">Default</option>
                                <option v-for="t in availableThemes" v-bind:key="t.id" v-bind:value="t.id">{{ t.name }}</option>
                            </select>
                        </div>
                    </div>
                </div>

                <div class="settings-section">
                    <div class="settings-section-title">Account</div>
                    <div class="settings-card">
                        <div class="settings-row">
                            <span class="settings-label">Username</span>
                            <span style="color: var(--text-secondary);">{{ user ? user.username : '' }}</span>
                        </div>
                        <div class="settings-row">
                            <span class="settings-label">Verified</span>
                            <span v-if="user && user.is_verified" style="color: var(--accent);">Yes</span>
                            <button v-else class="btn btn-secondary" style="height: 32px; padding: 0 12px; font-size: 13px;" v-on:click="requestVerification">Request</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Support Panel -->
        <div v-if="showSupportPanel" class="panel">
            <div class="panel-header">
                <h2 class="panel-title">Support</h2>
                <button class="icon-btn" v-on:click="showSupportPanel = false">
                    <svg viewBox="0 0 24 24">
                        <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
                    </svg>
                </button>
            </div>
            <div class="panel-content">
                <div v-if="supportMessages.length === 0" class="empty-state">
                    <div class="empty-state-text">No messages from support yet.</div>
                </div>
                <div v-for="m in supportMessages" v-bind:key="m.id" class="admin-item" v-bind:style="{borderLeft: !m.is_read ? '3px solid var(--accent)' : ''}" v-on:click="openSupportMessage(m)">
                    <div class="admin-item-header">
                        <strong>{{ m.title }}</strong>
                        <span style="font-size: 12px; color: var(--text-tertiary);">{{ formatTime(m.created_at) }}</span>
                    </div>
                    <div v-if="expandedSupportId === m.id" style="margin-top: 8px; font-size: 14px; color: var(--text-secondary); line-height: 1.5;">{{ m.body }}</div>
                </div>
            </div>
        </div>

        <!-- Admin Panel -->
        <div v-if="showAdminPanel" class="panel">
            <div class="panel-header">
                <h2 class="panel-title">Admin</h2>
                <button class="icon-btn" v-on:click="showAdminPanel = false">
                    <svg viewBox="0 0 24 24">
                        <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
                    </svg>
                </button>
            </div>
            <div class="panel-content">
                <div class="admin-tabs">
                    <button class="admin-tab" v-bind:class="{active: adminTab === 'reports'}" v-on:click="adminTab = 'reports'; loadReports()">Reports</button>
                    <button class="admin-tab" v-bind:class="{active: adminTab === 'users'}" v-on:click="adminTab = 'users'; loadUsers()">Users</button>
                    <button class="admin-tab" v-bind:class="{active: adminTab === 'words'}" v-on:click="adminTab = 'words'; loadBannedWords()">Words</button>
                    <button class="admin-tab" v-bind:class="{active: adminTab === 'themes'}" v-on:click="adminTab = 'themes'; loadAdminThemes()">Themes</button>
                    <button class="admin-tab" v-bind:class="{active: adminTab === 'support'}" v-on:click="adminTab = 'support'; loadAdminSupport()">Support</button>
                </div>

                <!-- Reports Tab -->
                <div v-if="adminTab === 'reports'">
                    <div class="admin-list">
                        <div v-if="adminReports.length === 0" style="text-align: center; color: var(--text-tertiary); padding: 24px;">No reports</div>
                        <div v-for="r in adminReports" v-bind:key="r.id" class="admin-item">
                            <div class="admin-item-header">
                                <div><span>{{ r.reporter_username }}</span> → <strong>{{ r.reported_username }}</strong></div>
                                <span class="status-badge" v-bind:class="'status-' + r.status">{{ r.status }}</span>
                            </div>
                            <div style="font-size: 14px; margin: 8px 0;">{{ r.reason }}</div>
                            <div v-if="r.status === 'pending'" class="admin-item-actions">
                                <button style="background: #F59E0B;" v-on:click="adminAction(r.id, 'mute', 3600)">Mute 1h</button>
                                <button style="background: #EF4444;" v-on:click="adminAction(r.id, 'temp_ban', 86400)">Ban 24h</button>
                                <button style="background: #6B7280;" v-on:click="rejectReport(r.id)">Reject</button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Users Tab -->
                <div v-if="adminTab === 'users'">
                    <div class="admin-list">
                        <div v-for="u in adminUsers" v-bind:key="u.id" class="admin-item" style="display: flex; align-items: center; justify-content: space-between;">
                            <div>
                                <strong>{{ u.username }}</strong>
                                <span v-if="u.is_admin" style="margin-left: 8px; padding: 2px 8px; background: #E9D5FF; color: #7C3AED; border-radius: 10px; font-size: 11px;">Admin</span>
                                <span v-if="u.is_verified" style="margin-left: 4px; padding: 2px 8px; background: #DBEAFE; color: #2563EB; border-radius: 10px; font-size: 11px;">Verified</span>
                            </div>
                            <button class="btn" v-bind:class="u.is_verified ? 'btn-secondary' : 'btn-primary'" style="height: 32px; padding: 0 12px; font-size: 12px;" v-on:click="toggleVerified(u)">
                                {{ u.is_verified ? 'Unverify' : 'Verify' }}
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Words Tab -->
                <div v-if="adminTab === 'words'">
                    <div class="admin-form">
                        <input type="text" v-model="newWord.word" placeholder="Word" style="flex: 1; min-width: 100px;">
                        <select v-model="newWord.penalty_type">
                            <option value="warn">Warn</option>
                            <option value="mute">Mute</option>
                            <option value="temp_ban">Temp Ban</option>
                        </select>
                        <input type="number" v-model="newWord.penalty_duration" placeholder="Sec" style="width: 80px;">
                        <button class="btn btn-primary" style="height: 40px;" v-on:click="addBannedWord">Add</button>
                    </div>
                    <div class="admin-list">
                        <div v-for="w in bannedWords" v-bind:key="w.id" class="admin-item" style="display: flex; align-items: center; justify-content: space-between;">
                            <div>
                                <strong>{{ w.word }}</strong>
                                <span style="margin-left: 8px; font-size: 12px; color: var(--text-tertiary);">{{ w.penalty_type }}</span>
                            </div>
                            <button class="icon-btn" style="color: var(--danger);" v-on:click="deleteBannedWord(w.id)">
                                <svg viewBox="0 0 24 24" style="width: 18px; height: 18px;">
                                    <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Themes Tab -->
                <div v-if="adminTab === 'themes'">
                    <div class="admin-form" style="flex-direction: column;">
                        <input type="text" v-model="newTheme.name" placeholder="Theme Name" style="width: 100%;">
                        <textarea v-model="newTheme.definition_json" placeholder='{"background":"#fff","header":"#fff","incomingBubble":"#f0f2f5","outgoingBubble":"#1877f2","accent":"#1877f2"}' style="min-height: 60px; font-family: monospace; font-size: 12px;"></textarea>
                        <button class="btn btn-primary" v-on:click="createTheme">Create Theme</button>
                    </div>
                    <div class="admin-list" style="margin-top: 16px;">
                        <div v-for="t in adminThemes" v-bind:key="t.id" class="admin-item" style="display: flex; align-items: center; justify-content: space-between;">
                            <div>
                                <strong>{{ t.name }}</strong>
                                <span v-if="t.is_active" class="status-badge status-approved" style="margin-left: 8px;">Active</span>
                            </div>
                            <div style="display: flex; gap: 8px;">
                                <button v-if="!t.is_active" class="btn btn-primary" style="height: 32px; padding: 0 12px; font-size: 12px;" v-on:click="activateTheme(t.id)">Activate</button>
                                <button v-else class="btn btn-secondary" style="height: 32px; padding: 0 12px; font-size: 12px;" v-on:click="deactivateTheme(t.id)">Deactivate</button>
                                <button class="btn btn-danger" style="height: 32px; padding: 0 12px; font-size: 12px;" v-on:click="deleteTheme(t.id)">Delete</button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Support Tab -->
                <div v-if="adminTab === 'support'">
                    <div class="admin-form" style="flex-direction: column;">
                        <input type="text" v-model="newSupportMessage.title" placeholder="Title" style="width: 100%;">
                        <textarea v-model="newSupportMessage.body" placeholder="Message body..." style="min-height: 80px;"></textarea>
                        <button class="btn btn-primary" v-on:click="sendSupportMessage">Send to All Users</button>
                    </div>
                    <div class="admin-list" style="margin-top: 16px;">
                        <div v-for="m in adminSupportMessages" v-bind:key="m.id" class="admin-item">
                            <div class="admin-item-header">
                                <strong>{{ m.title }}</strong>
                                <span style="font-size: 12px; color: var(--text-tertiary);">{{ formatTime(m.created_at) }}</span>
                            </div>
                            <div style="font-size: 14px; color: var(--text-secondary); margin-top: 8px;">{{ m.body }}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Toast -->
        <div v-if="toast.show" class="toast" v-bind:class="'toast-' + toast.type">{{ toast.message }}</div>
    </div>

    <!-- ES5 Polyfills -->
    <script nonce="<?php echo $nonce; ?>">
        // Array polyfills for old browsers
        if (!Array.prototype.forEach) {
            Array.prototype.forEach = function(callback, thisArg) {
                var T, k;
                if (this == null) throw new TypeError('this is null or not defined');
                var O = Object(this);
                var len = O.length >>> 0;
                if (typeof callback !== 'function') throw new TypeError(callback + ' is not a function');
                if (arguments.length > 1) T = thisArg;
                k = 0;
                while (k < len) {
                    var kValue;
                    if (k in O) {
                        kValue = O[k];
                        callback.call(T, kValue, k, O);
                    }
                    k++;
                }
            };
        }

        if (!Array.prototype.map) {
            Array.prototype.map = function(callback, thisArg) {
                var T, A, k;
                if (this == null) throw new TypeError('this is null or not defined');
                var O = Object(this);
                var len = O.length >>> 0;
                if (typeof callback !== 'function') throw new TypeError(callback + ' is not a function');
                if (arguments.length > 1) T = thisArg;
                A = new Array(len);
                k = 0;
                while (k < len) {
                    var kValue, mappedValue;
                    if (k in O) {
                        kValue = O[k];
                        mappedValue = callback.call(T, kValue, k, O);
                        A[k] = mappedValue;
                    }
                    k++;
                }
                return A;
            };
        }

        if (!Array.prototype.filter) {
            Array.prototype.filter = function(callback, thisArg) {
                if (this == null) throw new TypeError('this is null or not defined');
                var O = Object(this);
                var len = O.length >>> 0;
                if (typeof callback !== 'function') throw new TypeError(callback + ' is not a function');
                var res = [];
                var T = thisArg;
                var i = 0;
                while (i < len) {
                    if (i in O) {
                        var val = O[i];
                        if (callback.call(T, val, i, O)) res.push(val);
                    }
                    i++;
                }
                return res;
            };
        }

        if (!Array.prototype.find) {
            Array.prototype.find = function(predicate) {
                if (this == null) throw new TypeError('this is null or not defined');
                var o = Object(this);
                var len = o.length >>> 0;
                if (typeof predicate !== 'function') throw new TypeError('predicate must be a function');
                var thisArg = arguments[1];
                var k = 0;
                while (k < len) {
                    var kValue = o[k];
                    if (predicate.call(thisArg, kValue, k, o)) return kValue;
                    k++;
                }
                return undefined;
            };
        }

        if (!Array.prototype.some) {
            Array.prototype.some = function(fun, thisArg) {
                if (this == null) throw new TypeError('Array.prototype.some called on null or undefined');
                if (typeof fun !== 'function') throw new TypeError();
                var t = Object(this);
                var len = t.length >>> 0;
                for (var i = 0; i < len; i++) {
                    if (i in t && fun.call(thisArg, t[i], i, t)) return true;
                }
                return false;
            };
        }

        if (!String.prototype.trim) {
            String.prototype.trim = function() {
                return this.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, '');
            };
        }

        // JSON polyfill check
        if (typeof JSON === 'undefined') {
            window.JSON = {
                parse: function(s) {
                    return eval('(' + s + ')');
                },
                stringify: function(o) {
                    var t = typeof o;
                    if (t !== 'object' || o === null) {
                        if (t === 'string') return '"' + o + '"';
                        return String(o);
                    }
                    var n, v, json = [],
                        arr = (o && o.constructor === Array);
                    for (n in o) {
                        v = o[n];
                        t = typeof v;
                        if (t === 'string') v = '"' + v + '"';
                        else if (t === 'object' && v !== null) v = JSON.stringify(v);
                        json.push((arr ? '' : '"' + n + '":') + String(v));
                    }
                    return (arr ? '[' : '{') + String(json) + (arr ? ']' : '}');
                }
            };
        }

        // Object.keys polyfill
        if (!Object.keys) {
            Object.keys = function(obj) {
                var keys = [];
                for (var key in obj) {
                    if (Object.prototype.hasOwnProperty.call(obj, key)) {
                        keys.push(key);
                    }
                }
                return keys;
            };
        }

        // Date.now polyfill
        if (!Date.now) {
            Date.now = function() {
                return new Date().getTime();
            };
        }
    </script>

    <script src="https://unpkg.com/twemoji@latest/dist/twemoji.min.js" crossorigin="anonymous"></script>

    <!-- Vue 2 Legacy Build -->
    <script nonce="<?php echo $nonce; ?>" src="https://cdn.jsdelivr.net/npm/vue@2.7.14/dist/vue.min.js"></script>

    <!-- Pusher (optional) -->
    <script nonce="<?php echo $nonce; ?>" src="https://js.pusher.com/8.2.0/pusher.min.js"></script>

    <!-- App Script (ES5) -->
    <script nonce="<?php echo $nonce; ?>">
        (function() {
            'use strict';

            // XHR helper for legacy browsers
            function ajax(method, url, data, callback) {
                var xhr = new XMLHttpRequest();
                xhr.open(method, url, true);
                xhr.setRequestHeader('Content-Type', 'application/json');

                var token = window._accessToken;
                if (token) {
                    xhr.setRequestHeader('Authorization', 'Bearer ' + token);
                }

                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4) {
                        var response = null;
                        try {
                            response = JSON.parse(xhr.responseText);
                        } catch (e) {
                            response = {
                                error: 'Parse error'
                            };
                        }
                        callback(xhr.status >= 200 && xhr.status < 300 ? null : response, response);
                    }
                };

                xhr.onerror = function() {
                    callback({
                        error: 'Network error'
                    }, null);
                };

                if (data) {
                    xhr.send(JSON.stringify(data));
                } else {
                    xhr.send();
                }
            }

            function apiGet(url, callback) {
                ajax('GET', url, null, callback);
            }

            function apiPost(url, data, callback) {
                ajax('POST', url, data, callback);
            }

            // Global access token storage
            window._accessToken = null;

            // Create Vue app
            new Vue({
                el: '#app',
                data: {
                    view: 'loading',
                    user: null,
                    isDesktop: window.innerWidth >= 900,

                    // Auth
                    authTab: 'login',
                    authForm: {
                        username: '',
                        password: ''
                    },
                    authError: '',
                    authLoading: false,

                    // Conversations
                    convos: [],
                    currentConvo: null,
                    messages: [],
                    messageInput: '',
                    searchQuery: '',

                    // Reactions
                    activeReactionMessageId: null,
                    reactionEmojis: ['👍', '❤️', '😂', '😮', '😢', '😠'],

                    // UI States
                    showInviteModal: false,
                    inviteUrl: '',
                    showReportModal: false,
                    reportReason: '',
                    showSettingsPanel: false,
                    showSupportPanel: false,
                    showAdminPanel: false,

                    // Settings
                    fontScale: 1.0,
                    selectedFontId: 1,
                    selectedThemeId: null,
                    availableFonts: [],
                    availableThemes: [],
                    currentFont: null,
                    currentTheme: null,

                    // Support
                    supportMessages: [],
                    supportUnreadCount: 0,
                    expandedSupportId: null,

                    // Admin
                    adminTab: 'reports',
                    adminReports: [],
                    adminUsers: [],
                    bannedWords: [],
                    adminThemes: [],
                    adminSupportMessages: [],
                    newWord: {
                        word: '',
                        penalty_type: 'warn',
                        penalty_duration: 0
                    },
                    newTheme: {
                        name: '',
                        definition_json: ''
                    },
                    newSupportMessage: {
                        title: '',
                        body: ''
                    },

                    // Toast
                    toast: {
                        show: false,
                        message: '',
                        type: 'success'
                    },

                    // Realtime
                    typingUsers: {},
                    pusher: null,
                    currentChannel: null,
                    pusherSocketId: null,
                    isTyping: false,

                    // Timers
                    pollInterval: null,
                    refreshTimeout: null,
                    toastTimeout: null
                },

                computed: {
                    filteredConvos: function() {
                        var self = this;
                        var query = this.searchQuery.toLowerCase().trim();
                        if (!query) return this.convos;
                        return this.convos.filter(function(c) {
                            return c.other_username && c.other_username.toLowerCase().indexOf(query) !== -1;
                        });
                    },

                    activeUsers: function() {
                        var self = this;
                        var now = Date.now();
                        return this.convos.filter(function(c) {
                            if (!c.other_last_active) return false;
                            var t = c.other_last_active.replace(' ', 'T') + 'Z';
                            var date = new Date(t);
                            return (now - date.getTime()) < 120000; // 2 minutes
                        });
                    },

                    typingIndicator: function() {
                        var users = [];
                        for (var key in this.typingUsers) {
                            if (this.typingUsers.hasOwnProperty(key)) {
                                users.push(this.typingUsers[key]);
                            }
                        }
                        if (users.length === 0) return '';
                        if (users.length === 1) return users[0] + ' is typing...';
                        return users[0] + ' and others are typing...';
                    },

                    activeStatus: function() {
                        if (!this.currentConvo || !this.currentConvo.other_last_active) return null;
                        var t = this.currentConvo.other_last_active.replace(' ', 'T') + 'Z';
                        var date = new Date(t);
                        var now = Date.now();
                        var diffSeconds = Math.floor((now - date.getTime()) / 1000);
                        if (diffSeconds < 120) return 'Online';
                        if (diffSeconds < 3600) return 'Active ' + Math.floor(diffSeconds / 60) + 'm ago';
                        if (diffSeconds < 86400) return 'Active ' + Math.floor(diffSeconds / 3600) + 'h ago';
                        return null;
                    },

                    fontScalePercent: function() {
                        return Math.round(this.fontScale * 100);
                    },

                    fontSizePx: function() {
                        return (15 * this.fontScale) + 'px';
                    }
                },

                watch: {
                    fontScale: function(val) {
                        document.documentElement.style.setProperty('--font-scale', val);
                    },

                    currentTheme: function(val) {
                        var root = document.documentElement;
                        // Fix: Check if val is the definition itself or contains a .definition property
                        var t = val ? (val.definition || val) : null;

                        if (t && t.background) {
                            root.style.setProperty('--bg', t.background || '#FFFFFF');
                            root.style.setProperty('--bubble-incoming', t.incomingBubble || '#F0F2F5');
                            root.style.setProperty('--bubble-outgoing', t.outgoingBubble || '#1877F2');
                            root.style.setProperty('--accent', t.accent || '#1877F2');
                            root.classList.add('themed');
                        } else {
                            root.style.removeProperty('--bg');
                            root.style.removeProperty('--bubble-incoming');
                            root.style.removeProperty('--bubble-outgoing');
                            root.style.removeProperty('--accent');
                            root.classList.remove('themed');
                        }
                    },

                    currentFont: function(val) {
                        var root = document.documentElement;
                        var linkId = 'dynamic-font-link';
                        var linkEl = document.getElementById(linkId);

                        if (val && val.import_url) {
                            if (!linkEl) {
                                linkEl = document.createElement('link');
                                linkEl.id = linkId;
                                linkEl.rel = 'stylesheet';
                                document.head.appendChild(linkEl);
                            }
                            if (linkEl.href !== val.import_url) {
                                linkEl.href = val.import_url;
                            }
                        } else if (linkEl) {
                            linkEl.parentNode.removeChild(linkEl);
                        }

                        var fontStack = val ? val.css_value : "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif";
                        root.style.setProperty('--font', fontStack);
                    }
                },

                updated: function() {
                    this.parseEmojis();
                },

                methods: {
                    isOnlyEmoji: function(text) {
                        if (!text) return false;
                        // Regex for Emoji-only strings (including spaces)
                        var emojiRegex = /^(\u00a9|\u00ae|[\u2000-\u3300]|\ud83c[\ud000-\udfff]|\ud83d[\ud000-\udfff]|\ud83e[\ud000-\udfff]|\s)+$/gi;
                        return emojiRegex.test(text) && text.trim().length > 0;
                    },
                    parseEmojis: function() {
                        if (window.twemoji) {
                            window.twemoji.parse(this.$el, {
                                folder: 'svg',
                                ext: '.svg'
                            });
                        }
                    },
                    // Toast
                    showToast: function(message, type) {
                        var self = this;
                        type = type || 'success';
                        if (this.toastTimeout) clearTimeout(this.toastTimeout);
                        this.toast.show = true;
                        this.toast.message = message;
                        this.toast.type = type;
                        this.toastTimeout = setTimeout(function() {
                            self.toast.show = false;
                        }, 3000);
                    },

                    // Formatting
                    formatTime: function(dateStr) {
                        if (!dateStr) return '';
                        var d = new Date(dateStr.replace(' ', 'T') + 'Z');
                        if (isNaN(d.getTime())) return dateStr;
                        var now = new Date();
                        if (d.toDateString() === now.toDateString()) {
                            return d.toLocaleTimeString([], {
                                hour: '2-digit',
                                minute: '2-digit'
                            });
                        }
                        return d.toLocaleDateString([], {
                            month: 'short',
                            day: 'numeric'
                        });
                    },

                    getInitial: function(name) {
                        if (!name) return 'U';
                        return name.charAt(0).toUpperCase();
                    },

                    isUserOnline: function(convo) {
                        if (!convo.other_last_active) return false;
                        var t = convo.other_last_active.replace(' ', 'T') + 'Z';
                        var date = new Date(t);
                        return (Date.now() - date.getTime()) < 120000;
                    },

                    stopProp: function(e) {
                        e.stopPropagation();
                    },

                    closeInviteModal: function(e) {
                        if (e.target === e.currentTarget) this.showInviteModal = false;
                    },

                    closeReportModal: function(e) {
                        if (e.target === e.currentTarget) this.showReportModal = false;
                    },

                    // Auth
                    tryRefresh: function() {
                        var self = this;
                        apiPost('/api/auth/refresh', {}, function(err, data) {
                            if (err) {
                                self.view = 'auth';
                                return;
                            }
                            window._accessToken = data.access_token;
                            self.user = data.user;
                            self.fontScale = data.user.font_scale || 1.0;
                            self.selectedFontId = data.user.font_id || 1;
                            self.currentFont = data.user.font;
                            self.selectedThemeId = data.user.theme_id;
                            self.currentTheme = data.user.theme ? (typeof data.user.theme === 'string' ? JSON.parse(data.user.theme) : data.user.theme) : null;

                            self.initPusher();
                            self.handlePendingInvite();
                            self.loadConvos();
                            self.loadAvailableThemes();
                            self.loadFonts();
                            self.loadSupportUnreadCount();
                            self.view = 'chats';
                            self.scheduleRefresh(data.expires_in);
                        });
                    },

                    scheduleRefresh: function(expiresIn) {
                        var self = this;
                        if (this.refreshTimeout) clearTimeout(this.refreshTimeout);
                        var delay = Math.max((expiresIn - 60) * 1000, 10000);
                        this.refreshTimeout = setTimeout(function() {
                            if (self.user) {
                                self.tryRefresh();
                            }
                        }, delay);
                    },

                    handleAuth: function(e) {
                        e.preventDefault();
                        if (this.authLoading) return;

                        var self = this;
                        this.authLoading = true;
                        this.authError = '';

                        var doLogin = function() {
                            apiPost('/api/auth/login', self.authForm, function(err, data) {
                                self.authLoading = false;
                                if (err) {
                                    self.authError = err.error || 'Login failed';
                                    return;
                                }
                                window._accessToken = data.access_token;
                                self.user = data.user;
                                self.fontScale = data.user.font_scale || 1.0;
                                self.selectedFontId = data.user.font_id || 1;
                                self.currentFont = data.user.font;
                                self.selectedThemeId = data.user.theme_id;
                                self.currentTheme = data.user.theme;

                                self.initPusher();
                                self.handlePendingInvite();
                                self.loadConvos();
                                self.loadAvailableThemes();
                                self.loadFonts();
                                self.loadSupportUnreadCount();
                                self.view = 'chats';
                                self.scheduleRefresh(data.expires_in);
                                self.authForm.username = '';
                                self.authForm.password = '';
                            });
                        };

                        if (this.authTab === 'register') {
                            apiPost('/api/auth/register', this.authForm, function(err, data) {
                                if (err) {
                                    self.authLoading = false;
                                    self.authError = err.error || 'Registration failed';
                                    return;
                                }
                                doLogin();
                            });
                        } else {
                            doLogin();
                        }
                    },

                    logout: function() {
                        var self = this;
                        this.stopPolling();
                        if (this.pusher) {
                            this.pusher.disconnect();
                            this.pusher = null;
                        }
                        apiPost('/api/auth/logout', {}, function() {
                            window._accessToken = null;
                            self.user = null;
                            self.convos = [];
                            self.currentConvo = null;
                            self.view = 'auth';
                        });
                    },

                    handlePendingInvite: function() {
                        var self = this;
                        var invite = localStorage.getItem('pending_invite');
                        if (!invite) return;
                        localStorage.removeItem('pending_invite');
                        apiPost('/api/invite/redeem', {
                            token: invite
                        }, function(err, data) {
                            if (err) {
                                if (err.error && err.error.indexOf('Already') === -1) {
                                    self.showToast(err.error, 'error');
                                }
                                return;
                            }
                            self.showToast('Invite accepted!');
                            self.loadConvos();
                        });
                    },

                    // Pusher
                    initPusher: function() {
                        var self = this;
                        if (typeof Pusher === 'undefined') return;

                        apiGet('/api/pusher/config', function(err, config) {
                            if (err || !config.enabled || !config.key) return;

                            self.pusher = new Pusher(config.key, {
                                cluster: config.cluster,
                                authEndpoint: '/api/pusher/auth',
                                auth: {
                                    headers: {
                                        'Authorization': 'Bearer ' + window._accessToken,
                                        'Content-Type': 'application/json'
                                    }
                                }
                            });

                            self.pusher.connection.bind('connected', function() {
                                self.pusherSocketId = self.pusher.connection.socket_id;
                            });
                        });
                    },

                    subscribeToConversation: function(convoId) {
                        var self = this;
                        if (!this.pusher || !convoId) return;

                        if (this.currentChannel) {
                            this.pusher.unsubscribe(this.currentChannel.name);
                            this.currentChannel = null;
                        }

                        var channelName = 'private-conversation-' + convoId;
                        this.currentChannel = this.pusher.subscribe(channelName);

                        this.currentChannel.bind('pusher:subscription_succeeded', function() {
                            self.stopPolling();
                        });

                        this.currentChannel.bind('pusher:subscription_error', function() {
                            self.startPolling();
                        });

                        this.currentChannel.bind('new-message', function(data) {
                            var msgConvoId = data.convo_id || data.conversation_id;
                            if (msgConvoId === (self.currentConvo ? self.currentConvo.id : null)) {
                                var exists = self.messages.some(function(m) {
                                    return m.id === data.message.id;
                                });
                                if (!exists && data.message.user_id !== (self.user ? self.user.id : null)) {
                                    self.messages.push(data.message);
                                    self.$nextTick(function() {
                                        self.scrollToBottom();
                                    });
                                    self.markRead();
                                }
                            }
                            self.loadConvos();
                        });

                        this.currentChannel.bind('user-typing', function(data) {
                            if (data.user_id !== (self.user ? self.user.id : null)) {
                                self.$set(self.typingUsers, data.user_id, data.username);
                                setTimeout(function() {
                                    self.$delete(self.typingUsers, data.user_id);
                                }, 3000);
                            }
                        });

                        this.currentChannel.bind('message-read', function(data) {
                            self.messages.forEach(function(m) {
                                if (m.id <= data.message_id && m.is_mine) {
                                    m.is_read_by_other = true;
                                }
                            });
                        });

                        this.currentChannel.bind('message-reaction', function(data) {
                            var msg = self.messages.find(function(m) {
                                return m.id === data.message_id;
                            });
                            if (msg) {
                                if (!msg.reactions) self.$set(msg, 'reactions', []);

                                // Remove existing reaction by this user
                                var idx = -1;
                                for (var i = 0; i < msg.reactions.length; i++) {
                                    if (msg.reactions[i].user_id === data.user_id) {
                                        idx = i;
                                        break;
                                    }
                                }
                                if (idx !== -1) msg.reactions.splice(idx, 1);

                                // Add new if not empty
                                if (data.reaction) {
                                    msg.reactions.push({
                                        user_id: data.user_id,
                                        reaction: data.reaction
                                    });
                                }
                            }
                        });

                        this.currentChannel.bind('message-deleted', function(data) {
                            var idx = -1;
                            for (var i = 0; i < self.messages.length; i++) {
                                if (self.messages[i].id === data.message_id) {
                                    idx = i;
                                    break;
                                }
                            }
                            if (idx !== -1) {
                                self.messages.splice(idx, 1);
                            }
                        });
                    },

                    handleTyping: function() {
                        var self = this;
                        if (!this.currentConvo || !this.user) return;
                        if (!this.isTyping) {
                            this.isTyping = true;
                            apiPost('/api/pusher/typing', {
                                convo_id: this.currentConvo.id
                            }, function() {});
                            setTimeout(function() {
                                self.isTyping = false;
                            }, 2500);
                        }
                    },

                    // Data loading
                    loadConvos: function() {
                        var self = this;
                        apiGet('/api/convos', function(err, data) {
                            if (err) {
                                self.showToast('Failed to load conversations', 'error');
                                return;
                            }
                            self.convos = data.convos;
                        });
                    },

                    loadAvailableThemes: function() {
                        var self = this;
                        apiGet('/api/themes', function(err, data) {
                            if (err) return;
                            self.availableThemes = data.themes.map(function(t) {
                                t.definition = typeof t.definition === 'string' ? JSON.parse(t.definition) : t.definition;
                                return t;
                            });
                        });
                    },

                    loadFonts: function() {
                        var self = this;
                        apiGet('/api/fonts', function(err, data) {
                            if (err) return;
                            self.availableFonts = data.fonts;
                        });
                    },

                    loadSupportUnreadCount: function() {
                        var self = this;
                        apiGet('/api/support/unread_count', function(err, data) {
                            if (err) return;
                            self.supportUnreadCount = data.unread_count;
                        });
                    },

                    // Conversations
                    createInvite: function() {
                        var self = this;
                        apiPost('/api/invite/create', {}, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.inviteUrl = data.invite_url;
                            self.showInviteModal = true;
                            self.loadConvos();
                        });
                    },

                    copyInvite: function() {
                        var self = this;
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            navigator.clipboard.writeText(this.inviteUrl).then(function() {
                                self.showToast('Copied!');
                                self.showInviteModal = false;
                            }).catch(function() {
                                self.showToast('Failed to copy', 'error');
                            });
                        } else {
                            // Fallback for old browsers
                            var textarea = document.createElement('textarea');
                            textarea.value = this.inviteUrl;
                            document.body.appendChild(textarea);
                            textarea.select();
                            try {
                                document.execCommand('copy');
                                self.showToast('Copied!');
                                self.showInviteModal = false;
                            } catch (e) {
                                self.showToast('Failed to copy', 'error');
                            }
                            document.body.removeChild(textarea);
                        }
                    },

                    openConvo: function(c) {
                        var self = this;
                        this.currentConvo = c;
                        this.messages = [];
                        this.typingUsers = {};

                        if (!this.isDesktop) {
                            this.view = 'chat';
                        }

                        this.subscribeToConversation(c.id);
                        this.loadMessages();

                        if (!this.pusher) {
                            this.startPolling();
                        }
                    },

                    openConvoByUser: function(u) {
                        var c = this.convos.find(function(conv) {
                            return conv.other_user_id === u.id;
                        });
                        if (c) this.openConvo(c);
                    },

                    goBack: function() {
                        this.stopPolling();
                        if (this.currentChannel && this.pusher) {
                            this.pusher.unsubscribe(this.currentChannel.name);
                        }
                        this.currentChannel = null;
                        this.currentConvo = null;
                        this.view = 'chats';
                        this.loadConvos();
                    },

                    loadMessages: function() {
                        var self = this;
                        if (!this.currentConvo) return;

                        apiGet('/api/messages?convo_id=' + this.currentConvo.id, function(err, data) {
                            if (err) {
                                self.showToast('Failed to load messages', 'error');
                                return;
                            }
                            self.messages = data.messages;
                            self.$nextTick(function() {
                                self.scrollToBottom();
                            });
                            self.markRead();
                        });
                    },

                    sendMessage: function(e) {
                        e.preventDefault();
                        var self = this;
                        var body = this.messageInput.trim();
                        if (!body || !this.currentConvo) return;

                        this.messageInput = '';

                        var payload = {
                            convo_id: this.currentConvo.id,
                            body: body
                        };
                        if (this.pusherSocketId) {
                            payload.socket_id = this.pusherSocketId;
                        }

                        apiPost('/api/messages/send', payload, function(err, result) {
                            if (err) {
                                self.messageInput = body;
                                self.showToast(err.error, 'error');
                                return;
                            }

                            self.messages.push({
                                id: result.message_id,
                                convo_id: self.currentConvo.id,
                                user_id: self.user.id,
                                username: self.user.username,
                                is_verified: self.user.is_verified,
                                body: body,
                                created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
                                is_delivered: false,
                                is_read_by_other: false,
                                is_mine: true
                            });

                            self.$nextTick(function() {
                                self.scrollToBottom();
                            });
                        });
                    },

                    markRead: function() {
                        var self = this;
                        if (!this.currentConvo) return;

                        var unread = this.messages.filter(function(m) {
                            return !m.is_mine;
                        });
                        if (unread.length === 0) return;

                        var lastId = 0;
                        unread.forEach(function(m) {
                            if (m.id > lastId) lastId = m.id;
                        });

                        var payload = {
                            convo_id: this.currentConvo.id,
                            up_to_message_id: lastId
                        };
                        if (this.pusherSocketId) {
                            payload.socket_id = this.pusherSocketId;
                        }

                        apiPost('/api/messages/mark_read', payload, function() {});
                    },

                    scrollToBottom: function() {
                        var container = this.$refs.messagesContainer;
                        if (container) {
                            container.scrollTop = container.scrollHeight;
                        }
                    },

                    // Polling
                    startPolling: function() {
                        var self = this;
                        this.stopPolling();

                        this.pollInterval = setInterval(function() {
                            if (self.view !== 'chat' || !self.currentConvo) return;

                            var lastId = 0;
                            self.messages.forEach(function(m) {
                                if (m.id > lastId) lastId = m.id;
                            });

                            apiGet('/api/poll?convo_id=' + self.currentConvo.id + '&last_id=' + lastId, function(err, data) {
                                if (err) return;

                                if (data.messages && data.messages.length) {
                                    var existingIds = {};
                                    self.messages.forEach(function(m) {
                                        existingIds[m.id] = true;
                                    });

                                    var newMsgs = data.messages.filter(function(m) {
                                        return !existingIds[m.id];
                                    });
                                    if (newMsgs.length) {
                                        newMsgs.forEach(function(m) {
                                            self.messages.push(m);
                                        });
                                        self.$nextTick(function() {
                                            self.scrollToBottom();
                                        });
                                        self.markRead();
                                    }
                                }

                                if (data.status_updates) {
                                    data.status_updates.forEach(function(u) {
                                        var msg = self.messages.find(function(m) {
                                            return m.id === u.id;
                                        });
                                        if (msg) {
                                            msg.is_delivered = u.is_delivered;
                                            msg.is_read_by_other = u.is_read_by_other;
                                        }
                                    });
                                }

                                if (data.deleted_ids && data.deleted_ids.length) {
                                    var deletedSet = {};
                                    data.deleted_ids.forEach(function(id) {
                                        deletedSet[id] = true;
                                    });
                                    self.messages = self.messages.filter(function(m) {
                                        return !deletedSet[m.id];
                                    });
                                }

                                if (data.partner_last_active && self.currentConvo) {
                                    self.currentConvo.other_last_active = data.partner_last_active;
                                }
                            });
                        }, 2000);
                    },

                    stopPolling: function() {
                        if (this.pollInterval) {
                            clearInterval(this.pollInterval);
                            this.pollInterval = null;
                        }
                    },

                    // Report
                    submitReport: function() {
                        var self = this;
                        if (!this.reportReason.trim() || !this.currentConvo) return;

                        apiPost('/api/report', {
                            reported_user_id: this.currentConvo.other_user_id,
                            reason: this.reportReason.trim()
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.showToast('Report submitted');
                            self.showReportModal = false;
                            self.reportReason = '';
                        });
                    },

                    // Settings
                    increaseFontScale: function() {
                        var self = this;
                        var newScale = Math.min(1.4, this.fontScale + 0.05);
                        this.fontScale = newScale;
                        apiPost('/api/user/font_scale', {
                            scale: newScale
                        }, function(err) {
                            if (err) self.showToast(err.error, 'error');
                        });
                    },

                    decreaseFontScale: function() {
                        var self = this;
                        var newScale = Math.max(0.85, this.fontScale - 0.05);
                        this.fontScale = newScale;
                        apiPost('/api/user/font_scale', {
                            scale: newScale
                        }, function(err) {
                            if (err) self.showToast(err.error, 'error');
                        });
                    },

                    updateFont: function() {
                        var self = this;
                        apiPost('/api/user/font', {
                            font_id: this.selectedFontId
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.currentFont = data.font;
                            self.showToast('Font updated');
                        });
                    },

                    updateTheme: function() {
                        var self = this;
                        var themeId = this.selectedThemeId;
                        if (themeId !== null && themeId !== undefined && themeId !== '') {
                            themeId = Number(themeId);
                            if (isNaN(themeId) || themeId === 0) themeId = null;
                        } else {
                            themeId = null;
                        }

                        apiPost('/api/user/theme', {
                            theme_id: themeId
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.currentTheme = null;
                            self.$nextTick(function() {
                                if (data.theme) {
                                    self.currentTheme = typeof data.theme === 'string' ? JSON.parse(data.theme) : data.theme;
                                }
                            });
                            self.showToast('Theme updated');
                        });
                    },

                    requestVerification: function() {
                        var self = this;
                        var message = prompt('Why should you be verified?');
                        if (!message || !message.trim()) return;

                        apiPost('/api/user/request_verification', {
                            message: message.trim()
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.showToast('Verification request submitted');
                        });
                    },

                    toggleReactionPicker: function(msg) {
                        if (this.activeReactionMessageId === msg.id) {
                            this.activeReactionMessageId = null;
                        } else {
                            this.activeReactionMessageId = msg.id;
                        }
                    },

                    getUniqueReactions: function(reactions) {
                        if (!reactions) return [];
                        // Return top 3 unique emojis
                        var unique = [];
                        reactions.forEach(function(r) {
                            if (unique.indexOf(r.reaction) === -1) unique.push(r.reaction);
                        });
                        return unique.slice(0, 3);
                    },

                    reactToMessage: function(msg, emoji) {
                        var self = this;
                        this.activeReactionMessageId = null; // Close picker

                        // Optimistic UI Update
                        if (!msg.reactions) self.$set(msg, 'reactions', []);

                        // Check if user already reacted with this emoji (toggle off)
                        var existingIndex = -1;
                        var existingReaction = null;

                        for (var i = 0; i < msg.reactions.length; i++) {
                            if (msg.reactions[i].user_id === self.user.id) {
                                existingIndex = i;
                                existingReaction = msg.reactions[i].reaction;
                                break;
                            }
                        }

                        if (existingIndex !== -1) {
                            // User already has a reaction
                            msg.reactions.splice(existingIndex, 1); // Remove it first
                            if (existingReaction !== emoji) {
                                // If different emoji, add the new one
                                msg.reactions.push({
                                    user_id: self.user.id,
                                    reaction: emoji
                                });
                            } else {
                                // If same emoji, we are toggling it off, so set emoji to empty for API
                                emoji = '';
                            }
                        } else {
                            // Add new reaction
                            msg.reactions.push({
                                user_id: self.user.id,
                                reaction: emoji
                            });
                        }

                        // Call API
                        apiPost('/api/messages/react', {
                            message_id: msg.id,
                            reaction: emoji
                        }, function(err) {
                            if (err) self.showToast('Failed to react', 'error');
                            // If error, we should revert UI (optional complexity)
                        });
                    },

                    // Support
                    openSupport: function() {
                        var self = this;
                        this.showSupportPanel = true;
                        apiGet('/api/support', function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.supportMessages = data.messages;
                        });
                    },

                    openSupportMessage: function(m) {
                        var self = this;
                        if (this.expandedSupportId === m.id) {
                            this.expandedSupportId = null;
                            return;
                        }
                        this.expandedSupportId = m.id;

                        if (!m.is_read) {
                            apiPost('/api/support/mark_read', {
                                message_id: m.id
                            }, function(err) {
                                if (!err) {
                                    m.is_read = true;
                                    self.supportUnreadCount = Math.max(0, self.supportUnreadCount - 1);
                                }
                            });
                        }
                    },

                    // Admin methods
                    loadReports: function() {
                        var self = this;
                        apiGet('/api/admin/reports', function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.adminReports = data.reports;
                        });
                    },

                    adminAction: function(reportId, action, duration) {
                        var self = this;
                        apiPost('/api/admin/reports/action', {
                            report_id: reportId,
                            action: action,
                            duration: duration
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadReports();
                            self.showToast('Action applied');
                        });
                    },

                    rejectReport: function(reportId) {
                        var self = this;
                        apiPost('/api/admin/reports/reject', {
                            report_id: reportId
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadReports();
                            self.showToast('Report rejected');
                        });
                    },

                    loadUsers: function() {
                        var self = this;
                        apiGet('/api/admin/users', function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.adminUsers = data.users;
                        });
                    },

                    toggleVerified: function(u) {
                        var self = this;
                        apiPost('/api/admin/set_verified', {
                            user_id: u.id,
                            value: !u.is_verified
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            u.is_verified = !u.is_verified;
                            self.showToast(u.is_verified ? 'User verified' : 'User unverified');
                        });
                    },

                    loadBannedWords: function() {
                        var self = this;
                        apiGet('/api/admin/banned_words', function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.bannedWords = data.banned_words;
                        });
                    },

                    addBannedWord: function() {
                        var self = this;
                        if (!this.newWord.word.trim()) return;

                        apiPost('/api/admin/banned_words/add', this.newWord, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadBannedWords();
                            self.showToast('Word added');
                            self.newWord.word = '';
                            self.newWord.penalty_type = 'warn';
                            self.newWord.penalty_duration = 0;
                        });
                    },

                    deleteBannedWord: function(id) {
                        var self = this;
                        apiPost('/api/admin/banned_words/delete', {
                            id: id
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadBannedWords();
                            self.showToast('Word deleted');
                        });
                    },

                    loadAdminThemes: function() {
                        var self = this;
                        apiGet('/api/admin/themes', function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.adminThemes = data.themes;
                        });
                    },

                    createTheme: function() {
                        var self = this;
                        if (!this.newTheme.name.trim() || !this.newTheme.definition_json.trim()) return;

                        apiPost('/api/admin/themes/create', this.newTheme, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadAdminThemes();
                            self.loadAvailableThemes();
                            self.showToast('Theme created');
                            self.newTheme.name = '';
                            self.newTheme.definition_json = '';
                        });
                    },

                    activateTheme: function(themeId) {
                        var self = this;
                        apiPost('/api/admin/themes/activate', {
                            theme_id: themeId
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadAdminThemes();
                            self.loadAvailableThemes();
                            self.showToast('Theme activated');
                        });
                    },

                    deactivateTheme: function(themeId) {
                        var self = this;
                        apiPost('/api/admin/themes/deactivate', {
                            theme_id: themeId
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadAdminThemes();
                            self.loadAvailableThemes();
                            self.showToast('Theme deactivated');
                        });
                    },

                    deleteTheme: function(themeId) {
                        var self = this;
                        if (!confirm('Delete this theme?')) return;

                        apiPost('/api/admin/themes/delete', {
                            theme_id: themeId
                        }, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadAdminThemes();
                            self.loadAvailableThemes();
                            self.showToast('Theme deleted');
                        });
                    },

                    loadAdminSupport: function() {
                        var self = this;
                        apiGet('/api/admin/support/list', function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.adminSupportMessages = data.messages;
                        });
                    },

                    sendSupportMessage: function() {
                        var self = this;
                        if (!this.newSupportMessage.title.trim() || !this.newSupportMessage.body.trim()) return;

                        apiPost('/api/admin/support/send', this.newSupportMessage, function(err, data) {
                            if (err) {
                                self.showToast(err.error, 'error');
                                return;
                            }
                            self.loadAdminSupport();
                            self.showToast('Message sent');
                            self.newSupportMessage.title = '';
                            self.newSupportMessage.body = '';
                        });
                    },

                    // Resize handler
                    handleResize: function() {
                        this.isDesktop = window.innerWidth >= 900;
                    }
                },

                mounted: function() {
                    var self = this;
                    this.parseEmojis();

                    // Handle resize
                    window.addEventListener('resize', function() {
                        self.handleResize();
                    });

                    // Check for pending invite
                    var params = new URLSearchParams(window.location.search);
                    var invite = params.get('invite');
                    if (invite) {
                        localStorage.setItem('pending_invite', invite);
                        window.history.replaceState({}, '', window.location.pathname);
                    }

                    // Try to restore session
                    this.tryRefresh();
                },

                beforeDestroy: function() {
                    this.stopPolling();
                    if (this.refreshTimeout) clearTimeout(this.refreshTimeout);
                    if (this.toastTimeout) clearTimeout(this.toastTimeout);
                    if (this.pusher) this.pusher.disconnect();
                }
            });
        })();
    </script>
</body>

</html>
