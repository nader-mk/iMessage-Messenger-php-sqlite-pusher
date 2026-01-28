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

function getPusher() {
    global $pusher, $pusherEnabled;
    return $pusherEnabled ? $pusher : null;
}

function triggerPusherEvent(string $channel, string $event, array $data, ?string $socketId = null): bool {
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

function getDb(): PDO {
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

function safeExecute(PDOStatement $stmt, array $params = []): bool {
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

function initDb(): void {
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
    } catch (PDOException $e) {}
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

function getEncryptionKey(): string {
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

function encryptMessage(string $plaintext): array {
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

function decryptMessage(string $ciphertext, string $nonce): ?string {
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

function base64UrlEncode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64UrlDecode(string $data): string {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

function createJwt(array $payload): string {
    $header = base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload['iat'] = $payload['iat'] ?? time();
    $payload['jti'] = $payload['jti'] ?? bin2hex(random_bytes(16));
    $payloadEncoded = base64UrlEncode(json_encode($payload));
    $signature = base64UrlEncode(hash_hmac('sha256', "$header.$payloadEncoded", JWT_SECRET, true));
    return "$header.$payloadEncoded.$signature";
}

function verifyJwt(string $token): ?array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$header, $payload, $signature] = $parts;
    $expectedSig = base64UrlEncode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
    if (!hash_equals($expectedSig, $signature)) return null;
    $data = json_decode(base64UrlDecode($payload), true);
    if (!is_array($data) || !isset($data['exp']) || $data['exp'] < time()) return null;
    return $data;
}

function checkRateLimit(string $key, int $maxRequests = RATE_LIMIT_REQUESTS, int $window = RATE_LIMIT_WINDOW): bool {
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

function checkRateLimitReadOnly(string $key, int $maxRequests = RATE_LIMIT_REQUESTS, int $window = RATE_LIMIT_WINDOW): bool {
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

function jsonResponse(array $data, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function getClientIp(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function getAuthUser(): ?array {
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

function requireAuth(): array {
    $user = getAuthUser();
    if (!$user) jsonResponse(['error' => 'Unauthorized'], 401);
    return $user;
}

function requireAdmin(): array {
    $user = requireAuth();
    if (!$user['is_admin']) jsonResponse(['error' => 'Forbidden'], 403);
    return $user;
}

function checkBannedWords(string $text, int $userId): ?string {
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

function formatMessage(array $m, int $currentUserId): array {
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

function setRefreshTokenCookie(string $token, int $lifetime): void {
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    setcookie('refresh_token', $token, [
        'expires' => time() + $lifetime,
        'path' => '/',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
}

function clearRefreshTokenCookie(): void {
    setcookie('refresh_token', '', ['expires' => 1, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
}

function getUserTheme(int $themeId): ?array {
    if (!$themeId) return null;
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM themes WHERE id = ? AND is_active = 1");
    $stmt->execute([$themeId]);
    return $stmt->fetch() ?: null;
}

function getUserFont(int $fontId): ?array {
    if (!$fontId) return null;
    $db = getDb();
    $stmt = $db->prepare("SELECT * FROM fonts WHERE id = ?");
    $stmt->execute([$fontId]);
    return $stmt->fetch() ?: null;
}

function issueNewTokens(array $user, string $familyId, string $ip): array {
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

function validateHttpMethod(string $actualMethod, array $allowedMethods): void {
    if (!in_array($actualMethod, $allowedMethods)) {
        http_response_code(405);
        header('Allow: ' . implode(', ', $allowedMethods));
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Method Not Allowed', 'allowed_methods' => $allowedMethods]);
        exit;
    }
}

function handleApi(): void {
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
        jsonResponse(['messages' => $result]);
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
        
        jsonResponse(['messages' => $result, 'status_updates' => $statusUpdates, 'deleted_ids' => $deletedIds, 'partner_last_active' => $lastActive]);
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
header("Content-Security-Policy: default-src 'self'; script-src 'nonce-$nonce' 'unsafe-eval' https://unpkg.com https://js.pusher.com; style-src 'unsafe-inline' https:; font-src https: data:; img-src 'self' data:; connect-src 'self' wss://*.pusher.com https://sockjs.pusher.com https://*.pusher.com; frame-ancestors 'none'");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>Messages</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<style>
:root {
    --font-family: -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', system-ui, sans-serif;
    --font-scale: 1;
    --bg-primary: #000000;
    --bg-secondary: rgba(28, 28, 30, 0.72);
    --bg-tertiary: rgba(44, 44, 46, 0.65);
    --glass-bg: rgba(30, 30, 32, 0.78);
    --glass-border: rgba(255, 255, 255, 0.08);
    --glass-blur: 20px;
    --text-primary: #ffffff;
    --text-secondary: rgba(255, 255, 255, 0.55);
    --text-tertiary: rgba(255, 255, 255, 0.35);
    --accent: #0A84FF;
    --accent-gradient: linear-gradient(180deg, #3EA1FF 0%, #0A84FF 100%);
    --bubble-incoming: rgba(58, 58, 60, 0.85);
    --bubble-outgoing-start: #0A84FF;
    --bubble-outgoing-end: #3EA1FF;
    --separator: rgba(255, 255, 255, 0.06);
    --radius-xs: 8px;
    --radius-sm: 12px;
    --radius-md: 18px;
    --radius-lg: 22px;
    --radius-xl: 28px;
    --radius-full: 9999px;
    --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.15);
    --shadow-md: 0 8px 32px rgba(0, 0, 0, 0.24);
    --shadow-lg: 0 16px 48px rgba(0, 0, 0, 0.32);
    --safe-top: env(safe-area-inset-top, 0px);
    --safe-bottom: env(safe-area-inset-bottom, 0px);
    --safe-left: env(safe-area-inset-left, 0px);
    --safe-right: env(safe-area-inset-right, 0px);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    -webkit-tap-highlight-color: transparent;
    -webkit-touch-callout: none;
}

html, body {
    height: 100%;
    font-family: var(--font-family);
    font-size: calc(16px * var(--font-scale));
    background: var(--bg-primary);
    color: var(--text-primary);
    overscroll-behavior: none;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

[v-cloak] { display: none !important; }

.app {
    height: 100%;
    display: flex;
    flex-direction: column;
    position: relative;
    overflow: hidden;
    background: 
        radial-gradient(ellipse 80% 50% at 20% -20%, rgba(10, 132, 255, 0.15), transparent 50%),
        radial-gradient(ellipse 60% 40% at 80% 10%, rgba(94, 92, 230, 0.12), transparent 50%),
        radial-gradient(ellipse 100% 80% at 50% 100%, rgba(10, 132, 255, 0.08), transparent 40%),
        var(--bg-primary);
}

.app::before {
    content: '';
    position: absolute;
    inset: 0;
    background: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E");
    opacity: 0.02;
    pointer-events: none;
    z-index: 0;
}

.loading-screen {
    position: fixed;
    inset: 0;
    background: var(--bg-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
}

.loading-spinner {
    width: 40px;
    height: 40px;
    border: 3px solid rgba(255, 255, 255, 0.1);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

.glass {
    background: var(--glass-bg);
    backdrop-filter: blur(var(--glass-blur)) saturate(180%);
    -webkit-backdrop-filter: blur(var(--glass-blur)) saturate(180%);
    border: 1px solid var(--glass-border);
}

.glass-light {
    background: rgba(255, 255, 255, 0.06);
    backdrop-filter: blur(16px) saturate(150%);
    -webkit-backdrop-filter: blur(16px) saturate(150%);
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.header {
    position: sticky;
    top: 0;
    z-index: 100;
    padding: calc(var(--safe-top) + 12px) 16px 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    background: rgba(0, 0, 0, 0.72);
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    border-bottom: 1px solid var(--separator);
}

.header-title {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
}

.header-actions {
    display: flex;
    align-items: center;
    gap: 6px;
}

.icon-btn {
    width: 40px;
    height: 40px;
    border-radius: var(--radius-full);
    border: none;
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: transform 0.15s ease, background 0.15s ease;
    position: relative;
}

.icon-btn:hover {
    background: rgba(255, 255, 255, 0.12);
}

.icon-btn:active {
    transform: scale(0.92);
}

.icon-btn svg {
    width: 20px;
    height: 20px;
}

.icon-btn .badge {
    position: absolute;
    top: -2px;
    right: -2px;
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: var(--radius-full);
    background: #FF453A;
    font-size: 11px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
}

.back-btn {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-full);
    border: none;
    background: rgba(255, 255, 255, 0.1);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: transform 0.15s ease, background 0.15s ease;
}

.back-btn:active {
    transform: scale(0.9);
}

.back-btn svg {
    width: 20px;
    height: 20px;
}

.content {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    position: relative;
    z-index: 1;
}

.convo-list {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 8px 12px calc(var(--safe-bottom) + 16px);
    -webkit-overflow-scrolling: touch;
}

.convo-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 60px 24px;
    text-align: center;
    color: var(--text-secondary);
}

.convo-empty svg {
    width: 64px;
    height: 64px;
    margin-bottom: 16px;
    opacity: 0.4;
}

.convo-empty p {
    font-size: 17px;
    font-weight: 500;
}

.convo-empty .hint {
    font-size: 14px;
    color: var(--text-tertiary);
    margin-top: 8px;
}

.convo-item {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 14px;
    border-radius: var(--radius-lg);
    cursor: pointer;
    transition: background 0.2s ease, transform 0.15s ease;
    margin-bottom: 4px;
}

.convo-item:hover {
    background: rgba(255, 255, 255, 0.04);
}

.convo-item:active {
    transform: scale(0.98);
    background: rgba(255, 255, 255, 0.06);
}

.convo-item.active {
    background: rgba(10, 132, 255, 0.15);
}

.avatar {
    width: 52px;
    height: 52px;
    border-radius: var(--radius-full);
    background: linear-gradient(145deg, rgba(255, 255, 255, 0.15), rgba(255, 255, 255, 0.05));
    border: 1px solid rgba(255, 255, 255, 0.1);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    font-weight: 600;
    color: var(--text-primary);
    flex-shrink: 0;
    position: relative;
    overflow: hidden;
}

.avatar::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.2) 0%, transparent 50%);
    pointer-events: none;
}

.avatar-sm {
    width: 40px;
    height: 40px;
    font-size: 16px;
}

.avatar-xs {
    width: 28px;
    height: 28px;
    font-size: 12px;
}

.convo-info {
    flex: 1;
    min-width: 0;
}

.convo-name {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 17px;
    font-weight: 600;
    color: var(--text-primary);
}

.convo-name .verified {
    color: var(--accent);
    flex-shrink: 0;
}

.convo-name .verified svg {
    width: 16px;
    height: 16px;
}

.convo-preview {
    font-size: 14px;
    color: var(--text-secondary);
    margin-top: 3px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.convo-meta {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 6px;
}

.convo-time {
    font-size: 13px;
    color: var(--text-tertiary);
}

.unread-badge {
    min-width: 22px;
    height: 22px;
    padding: 0 7px;
    border-radius: var(--radius-full);
    background: var(--accent);
    font-size: 13px;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
}

.chat-container {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
}

.chat-header {
    position: sticky;
    top: 0;
    z-index: 50;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: calc(var(--safe-top) + 10px) 12px 10px;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    border-bottom: 1px solid var(--separator);
}

.chat-header-info {
    flex: 1;
    min-width: 0;
}

.chat-header-name {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 17px;
    font-weight: 600;
}

.chat-header-name .verified {
    color: var(--accent);
}

.chat-header-name .verified svg {
    width: 16px;
    height: 16px;
}

.chat-header-status {
    font-size: 13px;
    color: var(--text-secondary);
    margin-top: 2px;
}

.chat-header-status.online {
    color: #30D158;
}

.chat-header-actions {
    display: flex;
    align-items: center;
    gap: 4px;
}

.chat-messages {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 16px 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    -webkit-overflow-scrolling: touch;
}

.chat-empty {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-tertiary);
    font-size: 15px;
    text-align: center;
    padding: 40px;
}

.message-row {
    display: flex;
    align-items: flex-end;
    gap: 8px;
    max-width: 85%;
    animation: messageIn 0.25s ease-out;
}

@keyframes messageIn {
    from {
        opacity: 0;
        transform: translateY(10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.message-row.incoming {
    align-self: flex-start;
}

.message-row.outgoing {
    align-self: flex-end;
    flex-direction: row-reverse;
}

.message-avatar {
    flex-shrink: 0;
    margin-bottom: 2px;
}

.message-bubble {
    padding: 10px 14px;
    border-radius: var(--radius-md);
    position: relative;
    box-shadow: var(--shadow-sm);
}

.message-row.incoming .message-bubble {
    background: var(--bubble-incoming);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-top-left-radius: var(--radius-xs);
}

.message-row.outgoing .message-bubble {
    background: linear-gradient(180deg, var(--bubble-outgoing-end), var(--bubble-outgoing-start));
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-top-right-radius: var(--radius-xs);
}

.message-text {
    font-size: calc(16px * var(--font-scale));
    line-height: 1.4;
    word-break: break-word;
    white-space: pre-wrap;
}

.message-meta {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 5px;
    margin-top: 4px;
    font-size: 11px;
    color: rgba(255, 255, 255, 0.55);
}

.message-row.outgoing .message-meta {
    color: rgba(255, 255, 255, 0.7);
}

.message-status {
    display: flex;
    align-items: center;
}

.message-status svg {
    width: 14px;
    height: 14px;
}

.message-status.read svg {
    color: #5AC8FA;
}

.typing-bubble {
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 14px 18px;
    background: var(--bubble-incoming);
    border-radius: var(--radius-md);
    border-top-left-radius: var(--radius-xs);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
}

.typing-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.4);
    animation: typingBounce 1.4s ease-in-out infinite;
}

.typing-dot:nth-child(2) { animation-delay: 0.2s; }
.typing-dot:nth-child(3) { animation-delay: 0.4s; }

@keyframes typingBounce {
    0%, 60%, 100% { transform: translateY(0); }
    30% { transform: translateY(-6px); }
}

.composer {
    position: sticky;
    bottom: 0;
    z-index: 50;
    padding: 10px 12px calc(var(--safe-bottom) + 10px);
    background: rgba(0, 0, 0, 0.78);
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    border-top: 1px solid var(--separator);
}

.composer-inner {
    display: flex;
    align-items: flex-end;
    gap: 10px;
}

.composer-btn {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-full);
    border: none;
    background: rgba(255, 255, 255, 0.08);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    flex-shrink: 0;
    transition: transform 0.12s ease, background 0.15s ease;
}

.composer-btn:hover {
    background: rgba(255, 255, 255, 0.12);
}

.composer-btn:active {
    transform: scale(0.9);
}

.composer-btn svg {
    width: 20px;
    height: 20px;
}

.composer-input-wrapper {
    flex: 1;
    display: flex;
    align-items: flex-end;
    gap: 8px;
    padding: 8px 14px;
    border-radius: var(--radius-lg);
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.08);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.composer-input-wrapper:focus-within {
    border-color: rgba(10, 132, 255, 0.4);
    box-shadow: 0 0 0 3px rgba(10, 132, 255, 0.15);
}

.composer-input-wrapper .side-btn {
    width: 28px;
    height: 28px;
    border-radius: var(--radius-full);
    border: none;
    background: transparent;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    flex-shrink: 0;
    transition: color 0.15s ease;
}

.composer-input-wrapper .side-btn:hover {
    color: var(--text-primary);
}

.composer-input-wrapper .side-btn svg {
    width: 22px;
    height: 22px;
}

.composer-input {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-family: inherit;
    font-size: 16px;
    line-height: 1.4;
    outline: none;
    resize: none;
    min-height: 24px;
    max-height: 120px;
}

.composer-input::placeholder {
    color: var(--text-tertiary);
}

.send-btn {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-full);
    border: none;
    background: var(--accent);
    color: white;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    flex-shrink: 0;
    transition: transform 0.12s ease, opacity 0.15s ease;
}

.send-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
}

.send-btn:not(:disabled):active {
    transform: scale(0.9);
}

.send-btn svg {
    width: 18px;
    height: 18px;
    margin-left: 2px;
}

.modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    z-index: 200;
    animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.modal {
    width: 100%;
    max-width: 380px;
    border-radius: var(--radius-xl);
    padding: 24px;
    background: rgba(44, 44, 46, 0.92);
    backdrop-filter: blur(40px) saturate(180%);
    -webkit-backdrop-filter: blur(40px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: var(--shadow-lg);
    animation: modalIn 0.25s ease-out;
}

@keyframes modalIn {
    from {
        opacity: 0;
        transform: scale(0.95) translateY(10px);
    }
    to {
        opacity: 1;
        transform: scale(1) translateY(0);
    }
}

.modal-title {
    font-size: 20px;
    font-weight: 700;
    margin-bottom: 8px;
}

.modal-text {
    font-size: 14px;
    color: var(--text-secondary);
    line-height: 1.5;
    margin-bottom: 20px;
}

.modal-code {
    padding: 14px;
    border-radius: var(--radius-sm);
    background: rgba(0, 0, 0, 0.3);
    font-family: 'SF Mono', Monaco, monospace;
    font-size: 12px;
    word-break: break-all;
    margin-bottom: 20px;
    border: 1px solid rgba(255, 255, 255, 0.06);
}

.modal textarea,
.modal input[type="text"],
.modal input[type="password"] {
    width: 100%;
    padding: 14px 16px;
    border-radius: var(--radius-sm);
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(0, 0, 0, 0.25);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 16px;
    outline: none;
    margin-bottom: 12px;
    transition: border-color 0.2s ease;
}

.modal textarea:focus,
.modal input:focus {
    border-color: var(--accent);
}

.modal textarea {
    min-height: 100px;
    resize: vertical;
}

.modal-actions {
    display: flex;
    gap: 10px;
    justify-content: flex-end;
}

.btn {
    padding: 12px 20px;
    border-radius: var(--radius-sm);
    border: none;
    font-family: inherit;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.12s ease, opacity 0.15s ease;
}

.btn:active {
    transform: scale(0.97);
}

.btn-primary {
    background: var(--accent);
    color: white;
}

.btn-secondary {
    background: rgba(255, 255, 255, 0.1);
    color: var(--text-primary);
}

.btn-danger {
    background: #FF453A;
    color: white;
}

.panel {
    position: fixed;
    inset: 0;
    z-index: 150;
    background: var(--bg-primary);
    display: flex;
    flex-direction: column;
    animation: slideUp 0.3s ease-out;
}

@keyframes slideUp {
    from {
        opacity: 0;
        transform: translateY(100%);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: calc(var(--safe-top) + 14px) 16px 14px;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    border-bottom: 1px solid var(--separator);
}

.panel-header h2 {
    font-size: 20px;
    font-weight: 700;
}

.panel-content {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
    padding-bottom: calc(var(--safe-bottom) + 24px);
}

.settings-section {
    margin-bottom: 28px;
}

.settings-section h3 {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
    padding-left: 4px;
}

.settings-card {
    background: rgba(255, 255, 255, 0.04);
    border-radius: var(--radius-md);
    overflow: hidden;
}

.settings-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 16px;
    border-bottom: 1px solid var(--separator);
}

.settings-row:last-child {
    border-bottom: none;
}

.settings-label {
    font-size: 16px;
    color: var(--text-primary);
}

.settings-control {
    display: flex;
    align-items: center;
    gap: 12px;
}

.font-scale-btn {
    width: 34px;
    height: 34px;
    border-radius: var(--radius-full);
    border: none;
    background: rgba(255, 255, 255, 0.1);
    color: var(--text-primary);
    font-size: 18px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s ease;
}

.font-scale-btn:active {
    background: rgba(255, 255, 255, 0.15);
}

.font-scale-value {
    min-width: 50px;
    text-align: center;
    font-size: 15px;
    color: var(--text-secondary);
}

.select-control {
    padding: 10px 14px;
    padding-right: 36px;
    border-radius: var(--radius-sm);
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(255, 255, 255, 0.06);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 15px;
    outline: none;
    appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='rgba(255,255,255,0.5)' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10l-5 5z'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 12px center;
    min-width: 140px;
}

.settings-preview {
    padding: 16px;
    background: rgba(0, 0, 0, 0.3);
    border-radius: var(--radius-md);
}

.preview-bubble {
    max-width: 80%;
    padding: 10px 14px;
    border-radius: var(--radius-md);
    margin-bottom: 8px;
}

.preview-bubble.incoming {
    background: var(--bubble-incoming);
    border-top-left-radius: var(--radius-xs);
}

.preview-bubble.outgoing {
    background: linear-gradient(180deg, var(--bubble-outgoing-end), var(--bubble-outgoing-start));
    border-top-right-radius: var(--radius-xs);
    margin-left: auto;
}

.verification-status {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 14px 16px;
    background: rgba(48, 209, 88, 0.12);
    border-radius: var(--radius-md);
    color: #30D158;
    font-weight: 500;
}

.verification-status svg {
    width: 20px;
    height: 20px;
}

.admin-tabs {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}

.admin-tab {
    padding: 10px 16px;
    border-radius: var(--radius-sm);
    border: none;
    font-family: inherit;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s ease;
}

.admin-tab.active {
    background: var(--accent);
    color: white;
}

.admin-tab:not(.active) {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-secondary);
}

.admin-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.admin-item {
    padding: 14px;
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.06);
}

.admin-item-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
}

.admin-item-info {
    font-size: 14px;
    color: var(--text-secondary);
}

.admin-item-info strong {
    color: var(--text-primary);
}

.status-badge {
    padding: 4px 10px;
    border-radius: var(--radius-full);
    font-size: 12px;
    font-weight: 600;
    text-transform: capitalize;
}

.status-pending { background: rgba(255, 159, 10, 0.2); color: #FF9F0A; }
.status-actioned { background: rgba(48, 209, 88, 0.2); color: #30D158; }
.status-rejected { background: rgba(255, 69, 58, 0.2); color: #FF453A; }
.status-approved { background: rgba(48, 209, 88, 0.2); color: #30D158; }

.admin-item-reason {
    font-size: 14px;
    color: var(--text-primary);
    line-height: 1.4;
    margin-bottom: 12px;
}

.admin-item-actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.admin-item-actions button {
    padding: 8px 14px;
    border-radius: var(--radius-sm);
    border: none;
    font-family: inherit;
    font-size: 13px;
    font-weight: 600;
    color: white;
    cursor: pointer;
    transition: opacity 0.15s ease;
}

.admin-item-actions button:hover {
    opacity: 0.85;
}

.admin-form {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
    padding: 16px;
    background: rgba(255, 255, 255, 0.04);
    border-radius: var(--radius-md);
}

.admin-form input,
.admin-form select,
.admin-form textarea {
    padding: 12px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(0, 0, 0, 0.25);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 14px;
    outline: none;
}

.admin-form input:focus,
.admin-form textarea:focus {
    border-color: var(--accent);
}

.word-item,
.theme-item,
.user-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.04);
}

.word-info {
    flex: 1;
}

.word-penalty {
    font-size: 12px;
    color: var(--text-tertiary);
    margin-left: 8px;
}

.theme-preview {
    display: flex;
    gap: 4px;
    margin-right: 12px;
}

.theme-preview-dot {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    border: 1px solid rgba(255, 255, 255, 0.2);
}

.theme-item-name {
    font-weight: 500;
}

.theme-item-actions {
    display: flex;
    gap: 8px;
}

.user-badges {
    display: flex;
    gap: 6px;
    margin-left: 10px;
}

.user-badge {
    padding: 3px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
}

.badge-admin { background: rgba(175, 82, 222, 0.2); color: #BF5AF2; }
.badge-verified { background: rgba(10, 132, 255, 0.2); color: #0A84FF; }
.badge-blocked { background: rgba(255, 69, 58, 0.2); color: #FF453A; }
.badge-banned { background: rgba(255, 69, 58, 0.2); color: #FF453A; }
.badge-muted { background: rgba(255, 159, 10, 0.2); color: #FF9F0A; }

.support-item {
    padding: 14px;
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.04);
    margin-bottom: 10px;
    cursor: pointer;
    transition: background 0.15s ease;
}

.support-item:hover {
    background: rgba(255, 255, 255, 0.06);
}

.support-item.unread {
    border-left: 3px solid var(--accent);
}

.support-item-title {
    font-weight: 600;
    margin-bottom: 4px;
}

.support-item-date {
    font-size: 12px;
    color: var(--text-tertiary);
}

.support-item-body {
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--separator);
    font-size: 14px;
    color: var(--text-secondary);
    line-height: 1.5;
}

.unread-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent);
    display: inline-block;
    margin-right: 8px;
}

.toast {
    position: fixed;
    left: 50%;
    bottom: calc(var(--safe-bottom) + 24px);
    transform: translateX(-50%);
    padding: 14px 20px;
    border-radius: var(--radius-md);
    background: rgba(50, 50, 52, 0.95);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: var(--shadow-lg);
    font-size: 15px;
    font-weight: 500;
    z-index: 300;
    max-width: calc(100% - 48px);
    text-align: center;
    animation: toastIn 0.3s ease-out;
}

@keyframes toastIn {
    from {
        opacity: 0;
        transform: translateX(-50%) translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateX(-50%) translateY(0);
    }
}

.toast-success { border-color: rgba(48, 209, 88, 0.3); }
.toast-error { border-color: rgba(255, 69, 58, 0.3); }
.toast-info { border-color: rgba(10, 132, 255, 0.3); }

.auth-container {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
}

.auth-box {
    width: 100%;
    max-width: 380px;
}

.auth-title {
    font-size: 34px;
    font-weight: 700;
    text-align: center;
    margin-bottom: 32px;
    background: linear-gradient(135deg, #fff 0%, rgba(255,255,255,0.7) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.auth-card {
    padding: 24px;
    border-radius: var(--radius-xl);
    background: rgba(44, 44, 46, 0.65);
    backdrop-filter: blur(40px) saturate(180%);
    -webkit-backdrop-filter: blur(40px) saturate(180%);
    border: 1px solid rgba(255, 255, 255, 0.08);
}

.auth-tabs {
    display: flex;
    gap: 8px;
    margin-bottom: 20px;
}

.auth-tab {
    flex: 1;
    padding: 12px;
    border-radius: var(--radius-sm);
    border: none;
    font-family: inherit;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s ease;
    background: rgba(255, 255, 255, 0.06);
    color: var(--text-secondary);
}

.auth-tab.active {
    background: var(--accent);
    color: white;
}

.auth-error {
    padding: 12px;
    border-radius: var(--radius-sm);
    background: rgba(255, 69, 58, 0.15);
    border: 1px solid rgba(255, 69, 58, 0.3);
    color: #FF453A;
    font-size: 14px;
    margin-bottom: 16px;
    text-align: center;
}

.auth-card .input {
    width: 100%;
    padding: 14px 16px;
    border-radius: var(--radius-sm);
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: rgba(0, 0, 0, 0.25);
    color: var(--text-primary);
    font-family: inherit;
    font-size: 16px;
    outline: none;
    margin-bottom: 12px;
    transition: border-color 0.2s ease;
}

.auth-card .input:focus {
    border-color: var(--accent);
}

.auth-card .btn {
    width: 100%;
    margin-top: 8px;
}

@media (max-width: 480px) {
    .header-title {
        font-size: 24px;
    }
    
    .chat-messages {
        padding: 12px 10px;
    }
    
    .message-row {
        max-width: 90%;
    }
}
</style>
</head>
<body>
<div id="app" class="app" v-cloak>
    <div v-if="view === 'loading'" class="loading-screen">
        <div class="loading-spinner"></div>
    </div>
    
    <template v-else-if="view === 'auth'">
        <div class="auth-container">
            <div class="auth-box">
                <h1 class="auth-title">Messages</h1>
                <div class="auth-card">
                    <div class="auth-tabs">
                        <button class="auth-tab" :class="{ active: authTab === 'login' }" @click="authTab = 'login'; authError = ''">Sign In</button>
                        <button class="auth-tab" :class="{ active: authTab === 'register' }" @click="authTab = 'register'; authError = ''">Create Account</button>
                    </div>
                    <div v-if="authError" class="auth-error">{{ authError }}</div>
                    <form @submit.prevent="handleAuth">
                        <input class="input" type="text" v-model="authForm.username" placeholder="Username" required minlength="3" maxlength="30" autocomplete="username">
                        <input class="input" type="password" v-model="authForm.password" placeholder="Password" required minlength="8" autocomplete="current-password">
                        <button class="btn btn-primary" type="submit" :disabled="authLoading">
                            {{ authLoading ? 'Please wait...' : (authTab === 'login' ? 'Sign In' : 'Create Account') }}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </template>
    
    <template v-else-if="view === 'convos'">
        <div class="header">
            <h1 class="header-title">Messages</h1>
            <div class="header-actions">
                <button class="icon-btn" @click="openSupport" title="Support">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>
                    <span v-if="supportUnreadCount > 0" class="badge">{{ supportUnreadCount > 9 ? '9+' : supportUnreadCount }}</span>
                </button>
                <button class="icon-btn" @click="showSettingsPanel = true" title="Settings">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
                </button>
                <button v-if="user?.is_admin" class="icon-btn" @click="showAdminPanel = true" title="Admin">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                </button>
                <button class="icon-btn" @click="createInvite" title="New Chat">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14m-7-7h14"/></svg>
                </button>
                <button class="icon-btn" @click="logout" title="Sign Out">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4m7 14l5-5-5-5m5 5H9"/></svg>
                </button>
            </div>
        </div>
        <div class="content">
            <div class="convo-list">
                <div v-if="convos.length === 0" class="convo-empty">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/></svg>
                    <p>No conversations yet</p>
                    <p class="hint">Tap + to create an invite link</p>
                </div>
                <div v-for="c in convos" :key="c.id" class="convo-item" @click="openConvo(c)">
                    <div class="avatar">{{ (c.other_username || 'U')[0].toUpperCase() }}</div>
                    <div class="convo-info">
                        <div class="convo-name">
                            <span>{{ c.other_username || 'Waiting...' }}</span>
                            <span v-if="c.other_verified" class="verified">
                                <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                            </span>
                        </div>
                        <div class="convo-preview">Tap to open</div>
                    </div>
                    <div class="convo-meta">
                        <span v-if="c.unread_count > 0" class="unread-badge">{{ c.unread_count > 99 ? '99+' : c.unread_count }}</span>
                    </div>
                </div>
            </div>
        </div>
    </template>
    
    <template v-else-if="view === 'chat'">
        <div class="chat-container">
            <div class="chat-header">
                <button class="back-btn" @click="goBack">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M15 19l-7-7 7-7"/></svg>
                </button>
                <div class="avatar avatar-sm">{{ (currentConvo?.other_username || 'U')[0].toUpperCase() }}</div>
                <div class="chat-header-info">
                    <div class="chat-header-name">
                        <span>{{ currentConvo?.other_username || 'Waiting...' }}</span>
                        <span v-if="currentConvo?.other_verified" class="verified">
                            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                        </span>
                    </div>
                    <div v-if="typingIndicator" class="chat-header-status">{{ typingIndicator }}</div>
                    <div v-else-if="activeStatus" class="chat-header-status" :class="{ online: activeStatus === 'Online' }">{{ activeStatus }}</div>
                </div>
                <div class="chat-header-actions">
                    <button class="icon-btn" @click="showToast('Voice call coming soon', 'info')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72 12.84 12.84 0 00.7 2.81 2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45 12.84 12.84 0 002.81.7A2 2 0 0122 16.92z"/></svg>
                    </button>
                    <button class="icon-btn" @click="showToast('Video call coming soon', 'info')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
                    </button>
                    <button v-if="currentConvo?.other_user_id" class="icon-btn" @click="showReportModal = true">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"/><circle cx="12" cy="5" r="1"/><circle cx="12" cy="19" r="1"/></svg>
                    </button>
                </div>
            </div>
            
            <div class="chat-messages" ref="messagesContainer">
                <div v-if="messages.length === 0" class="chat-empty">
                    Start the conversation!
                </div>
                <template v-for="(m, idx) in messages" :key="m.id">
                    <div class="message-row" :class="m.is_mine ? 'outgoing' : 'incoming'">
                        <div v-if="!m.is_mine && (idx === 0 || messages[idx-1]?.is_mine)" class="message-avatar">
                            <div class="avatar avatar-xs">{{ (currentConvo?.other_username || 'U')[0].toUpperCase() }}</div>
                        </div>
                        <div v-else-if="!m.is_mine" class="message-avatar" style="width: 28px;"></div>
                        <div class="message-bubble">
                            <div class="message-text" :style="{ fontSize: `calc(16px * ${fontScale})` }">{{ m.body }}</div>
                            <div class="message-meta">
                                <span>{{ formatTime(m.created_at) }}</span>
                                <span v-if="m.is_mine" class="message-status" :class="{ read: m.is_read_by_other }">
                                    <svg v-if="m.is_read_by_other" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 7l-8 8-4-4"/><path d="M22 7l-8 8-1-1"/></svg>
                                    <svg v-else-if="m.is_delivered" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 7l-8 8-4-4"/><path d="M22 7l-8 8-1-1" opacity="0.4"/></svg>
                                    <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>
                                </span>
                            </div>
                        </div>
                    </div>
                </template>
                <div v-if="typingIndicator" class="message-row incoming">
                    <div class="message-avatar">
                        <div class="avatar avatar-xs">{{ (currentConvo?.other_username || 'U')[0].toUpperCase() }}</div>
                    </div>
                    <div class="typing-bubble">
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                    </div>
                </div>
            </div>
            
            <div class="composer">
                <form class="composer-inner" @submit.prevent="sendMessage">
                    <button type="button" class="composer-btn" @click="showToast('Attachments coming soon', 'info')">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14m-7-7h14"/></svg>
                    </button>
                    <div class="composer-input-wrapper">
                        <button type="button" class="side-btn" @click="showToast('Camera coming soon', 'info')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4"/></svg>
                        </button>
                        <input type="text" class="composer-input" v-model="messageInput" placeholder="Aa" maxlength="2000" @input="handleTyping">
                        <button type="button" class="side-btn" @click="showToast('Stickers coming soon', 'info')">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
                        </button>
                    </div>
                    <button v-if="messageInput.trim()" type="submit" class="send-btn">
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
                    </button>
                    <button v-else type="button" class="send-btn" @click="sendLike">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3zM7 22H4a2 2 0 01-2-2v-7a2 2 0 012-2h3"/></svg>
                    </button>
                </form>
            </div>
        </div>
    </template>
    
    <div v-if="showInviteModal" class="modal-overlay" @click.self="showInviteModal = false">
        <div class="modal">
            <h2 class="modal-title">Invite Link</h2>
            <p class="modal-text">Share this link to start a conversation. The link expires in 24 hours.</p>
            <div class="modal-code">{{ inviteUrl }}</div>
            <div class="modal-actions">
                <button class="btn btn-secondary" @click="showInviteModal = false">Cancel</button>
                <button class="btn btn-primary" @click="copyInvite">Copy Link</button>
            </div>
        </div>
    </div>
    
    <div v-if="showReportModal" class="modal-overlay" @click.self="showReportModal = false">
        <div class="modal">
            <h2 class="modal-title">Report User</h2>
            <p class="modal-text">Describe the issue. False reports may result in penalties.</p>
            <textarea v-model="reportReason" placeholder="Describe the issue..." maxlength="1000"></textarea>
            <div class="modal-actions">
                <button class="btn btn-secondary" @click="showReportModal = false">Cancel</button>
                <button class="btn btn-danger" @click="submitReport">Report</button>
            </div>
        </div>
    </div>
    
    <div v-if="showSettingsPanel" class="panel">
        <div class="panel-header">
            <h2>Settings</h2>
            <button class="icon-btn" @click="showSettingsPanel = false">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="panel-content">
            <div class="settings-section">
                <h3>Appearance</h3>
                <div class="settings-card">
                    <div class="settings-row">
                        <span class="settings-label">Font Size</span>
                        <div class="settings-control">
                            <button class="font-scale-btn" @click="decreaseFontScale">−</button>
                            <span class="font-scale-value">{{ Math.round(fontScale * 100) }}%</span>
                            <button class="font-scale-btn" @click="increaseFontScale">+</button>
                        </div>
                    </div>
                    <div class="settings-row">
                        <span class="settings-label">Font</span>
                        <select class="select-control" v-model="selectedFontId" @change="updateFont">
                            <option v-for="f in availableFonts" :key="f.id" :value="f.id">{{ f.name }}</option>
                        </select>
                    </div>
                    <div class="settings-row">
                        <span class="settings-label">Theme</span>
                        <select class="select-control" v-model="selectedThemeId" @change="updateTheme">
                            <option :value="null">Default</option>
                            <option v-for="t in availableThemes" :key="t.id" :value="t.id">{{ t.name }}</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <div class="settings-section">
                <h3>Preview</h3>
                <div class="settings-preview">
                    <div class="preview-bubble incoming">
                        <div :style="{ fontSize: `calc(16px * ${fontScale})` }">Hello! How are you?</div>
                    </div>
                    <div class="preview-bubble outgoing">
                        <div :style="{ fontSize: `calc(16px * ${fontScale})` }">I'm doing great, thanks!</div>
                    </div>
                </div>
            </div>
            
            <div class="settings-section">
                <h3>Verification</h3>
                <div v-if="user?.is_verified" class="verification-status">
                    <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6.267 3.455a3.066 3.066 0 001.745-.723 3.066 3.066 0 013.976 0 3.066 3.066 0 001.745.723 3.066 3.066 0 012.812 2.812c.051.643.304 1.254.723 1.745a3.066 3.066 0 010 3.976 3.066 3.066 0 00-.723 1.745 3.066 3.066 0 01-2.812 2.812 3.066 3.066 0 00-1.745.723 3.066 3.066 0 01-3.976 0 3.066 3.066 0 00-1.745-.723 3.066 3.066 0 01-2.812-2.812 3.066 3.066 0 00-.723-1.745 3.066 3.066 0 010-3.976 3.066 3.066 0 00.723-1.745 3.066 3.066 0 012.812-2.812zm7.44 5.252a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
                    Your account is verified
                </div>
                <div v-else class="settings-card">
                    <div v-if="verificationRequestSent" style="padding: 16px; color: var(--text-secondary); text-align: center;">
                        Verification request submitted. Please wait for review.
                    </div>
                    <div v-else style="padding: 16px;">
                        <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 12px;">Request a verified badge for your account.</p>
                        <textarea v-model="verificationMessage" placeholder="Why should you be verified?" maxlength="1000" style="width: 100%; min-height: 80px; margin-bottom: 12px; padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.1); background: rgba(0,0,0,0.25); color: white; font-family: inherit; font-size: 14px;"></textarea>
                        <button class="btn btn-primary" style="width: 100%;" @click="requestVerification" :disabled="!verificationMessage.trim()">Request Verification</button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div v-if="showSupportPanel" class="panel">
        <div class="panel-header">
            <h2>Support</h2>
            <button class="icon-btn" @click="showSupportPanel = false">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="panel-content">
            <div v-if="supportMessages.length === 0" style="text-align: center; color: var(--text-tertiary); padding: 40px;">
                No messages from support yet.
            </div>
            <div v-for="m in supportMessages" :key="m.id" class="support-item" :class="{ unread: !m.is_read }" @click="openSupportMessage(m)">
                <div v-if="!m.is_read" class="unread-dot"></div>
                <div class="support-item-title">{{ m.title }}</div>
                <div class="support-item-date">{{ formatTime(m.created_at) }}</div>
                <div v-if="expandedSupportId === m.id" class="support-item-body">{{ m.body }}</div>
            </div>
        </div>
    </div>
    
    <div v-if="showAdminPanel" class="panel">
        <div class="panel-header">
            <h2>Admin</h2>
            <button class="icon-btn" @click="showAdminPanel = false">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
        </div>
        <div class="panel-content">
            <div class="admin-tabs">
                <button class="admin-tab" :class="{ active: adminTab === 'reports' }" @click="adminTab = 'reports'; loadReports()">Reports</button>
                <button class="admin-tab" :class="{ active: adminTab === 'verification' }" @click="adminTab = 'verification'; loadVerificationRequests()">Verification</button>
                <button class="admin-tab" :class="{ active: adminTab === 'words' }" @click="adminTab = 'words'; loadBannedWords()">Words</button>
                <button class="admin-tab" :class="{ active: adminTab === 'themes' }" @click="adminTab = 'themes'; loadAdminThemes()">Themes</button>
                <button class="admin-tab" :class="{ active: adminTab === 'fonts' }" @click="adminTab = 'fonts'; loadAdminFonts()">Fonts</button>
                <button class="admin-tab" :class="{ active: adminTab === 'support' }" @click="adminTab = 'support'; loadAdminSupport()">Support</button>
                <button class="admin-tab" :class="{ active: adminTab === 'users' }" @click="adminTab = 'users'; loadUsers()">Users</button>
            </div>
            
            <div v-if="adminTab === 'reports'">
                <div class="admin-list">
                    <div v-if="adminReports.length === 0" style="text-align: center; color: var(--text-tertiary); padding: 24px;">No reports</div>
                    <div v-for="r in adminReports" :key="r.id" class="admin-item">
                        <div class="admin-item-header">
                            <div class="admin-item-info"><span>{{ r.reporter_username }}</span> → <strong>{{ r.reported_username }}</strong></div>
                            <span class="status-badge" :class="'status-' + r.status">{{ r.status }}</span>
                        </div>
                        <div class="admin-item-reason">{{ r.reason }}</div>
                        <div v-if="r.status === 'pending'" class="admin-item-actions">
                            <button style="background: #FF9F0A;" @click="adminAction(r.id, 'mute', 3600)">Mute 1h</button>
                            <button style="background: #FF6B35;" @click="adminAction(r.id, 'temp_ban', 86400)">Ban 24h</button>
                            <button style="background: #FF453A;" @click="adminAction(r.id, 'perma_ban', 0)">Perma Ban</button>
                            <button style="background: rgba(255,255,255,0.15);" @click="rejectReport(r.id)">Reject</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div v-if="adminTab === 'verification'">
                <div class="admin-list">
                    <div v-if="verificationRequests.length === 0" style="text-align: center; color: var(--text-tertiary); padding: 24px;">No requests</div>
                    <div v-for="r in verificationRequests" :key="r.id" class="admin-item">
                        <div class="admin-item-header">
                            <div class="admin-item-info"><strong>{{ r.username }}</strong></div>
                            <span class="status-badge" :class="'status-' + r.status">{{ r.status }}</span>
                        </div>
                        <div class="admin-item-reason">{{ r.message }}</div>
                        <div v-if="r.status === 'pending'" class="admin-item-actions">
                            <button style="background: #30D158;" @click="approveVerification(r.id)">Approve</button>
                            <button style="background: rgba(255,255,255,0.15);" @click="rejectVerification(r.id)">Reject</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div v-if="adminTab === 'words'">
                <div class="admin-form">
                    <input type="text" v-model="newWord.word" placeholder="Word" style="flex: 1;">
                    <select v-model="newWord.penalty_type">
                        <option value="warn">Warn</option>
                        <option value="mute">Mute</option>
                        <option value="temp_ban">Temp Ban</option>
                        <option value="perma_ban">Perma Ban</option>
                    </select>
                    <input type="number" v-model.number="newWord.penalty_duration" placeholder="Duration (sec)" style="width: 120px;">
                    <button class="btn btn-primary" @click="addBannedWord">Add</button>
                </div>
                <div class="admin-list">
                    <div v-for="w in bannedWords" :key="w.id" class="word-item">
                        <div class="word-info">
                            <span>{{ w.word }}</span>
                            <span class="word-penalty">{{ w.penalty_type }}{{ w.penalty_duration ? ` (${w.penalty_duration}s)` : '' }}</span>
                        </div>
                        <button class="icon-btn" style="color: #FF453A; width: 32px; height: 32px;" @click="deleteBannedWord(w.id)">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 16px; height: 16px;"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                        </button>
                    </div>
                </div>
            </div>
            
            <div v-if="adminTab === 'themes'">
                <div class="admin-form" style="flex-direction: column;">
                    <input type="text" v-model="newTheme.name" placeholder="Theme Name" style="width: 100%;">
                    <textarea v-model="newTheme.definition_json" placeholder='{"background":"#000","header":"#111","incomingBubble":"#374151","outgoingBubble":"#0A84FF","accent":"#0A84FF"}' style="min-height: 80px; font-family: monospace; font-size: 12px;"></textarea>
                    <button class="btn btn-primary" @click="createTheme">Create Theme</button>
                </div>
                <div class="admin-list" style="margin-top: 16px;">
                    <div v-for="t in adminThemes" :key="t.id" class="theme-item">
                        <div style="display: flex; align-items: center;">
                            <div class="theme-preview" v-if="t.definition">
                                <div class="theme-preview-dot" :style="{background: t.definition.background}"></div>
                                <div class="theme-preview-dot" :style="{background: t.definition.header}"></div>
                                <div class="theme-preview-dot" :style="{background: t.definition.accent}"></div>
                            </div>
                            <span class="theme-item-name">{{ t.name }}</span>
                            <span v-if="t.is_active" class="status-badge status-actioned" style="margin-left: 8px;">Active</span>
                        </div>
                        <div class="theme-item-actions">
                            <button v-if="!t.is_active" class="btn btn-primary" style="padding: 6px 12px; font-size: 12px;" @click="activateTheme(t.id)">Activate</button>
                            <button v-else class="btn btn-secondary" style="padding: 6px 12px; font-size: 12px;" @click="deactivateTheme(t.id)">Deactivate</button>
                            <button class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;" @click="deleteTheme(t.id)">Delete</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <div v-if="adminTab === 'fonts'">
                <div class="admin-form" style="flex-direction: column;">
                    <input type="text" v-model="newFont.name" placeholder="Font Name (e.g. Open Sans)" style="width: 100%;">
                    <input type="text" v-model="newFont.css_value" placeholder="CSS Stack (e.g. 'Open Sans', sans-serif)" style="width: 100%;">
                    <input type="text" v-model="newFont.import_url" placeholder="Import URL (optional)" style="width: 100%;">
                    <button class="btn btn-primary" @click="createFont">Add Font</button>
                </div>
                <div class="admin-list" style="margin-top: 16px;">
                    <div v-for="f in availableFonts" :key="f.id" class="word-item">
                        <div class="word-info">
                            <strong>{{ f.name }}</strong>
                            <div style="font-size: 11px; color: var(--text-tertiary); margin-top: 2px;">{{ f.css_value }}</div>
                        </div>
                        <button v-if="f.id > 1" class="icon-btn" style="color: #FF453A; width: 32px; height: 32px;" @click="deleteFont(f.id)">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 16px; height: 16px;"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                        </button>
                        <span v-else style="font-size: 11px; color: var(--text-tertiary);">Default</span>
                    </div>
                </div>
            </div>
            
            <div v-if="adminTab === 'support'">
                <div class="admin-form" style="flex-direction: column;">
                    <input type="text" v-model="newSupportMessage.title" placeholder="Title" style="width: 100%;">
                    <textarea v-model="newSupportMessage.body" placeholder="Message body..." style="min-height: 100px;"></textarea>
                    <button class="btn btn-primary" @click="sendSupportMessage">Send to All Users</button>
                </div>
                <div class="admin-list" style="margin-top: 20px;">
                    <div v-for="m in adminSupportMessages" :key="m.id" class="admin-item">
                        <div class="admin-item-header">
                            <strong>{{ m.title }}</strong>
                            <span style="font-size: 12px; color: var(--text-tertiary);">{{ formatTime(m.created_at) }}</span>
                        </div>
                        <div class="admin-item-reason">{{ m.body }}</div>
                    </div>
                </div>
            </div>
            
            <div v-if="adminTab === 'users'">
                <div class="admin-list">
                    <div v-for="u in adminUsers" :key="u.id" class="user-item">
                        <div style="display: flex; align-items: center; flex: 1;">
                            <span>{{ u.username }}</span>
                            <div class="user-badges">
                                <span v-if="u.is_admin" class="user-badge badge-admin">Admin</span>
                                <span v-if="u.is_verified" class="user-badge badge-verified">Verified</span>
                                <span v-if="u.is_blocked" class="user-badge badge-blocked">Blocked</span>
                                <span v-if="u.ban_until && new Date(u.ban_until + 'Z') > new Date()" class="user-badge badge-banned">Banned</span>
                                <span v-if="u.mute_until && new Date(u.mute_until + 'Z') > new Date()" class="user-badge badge-muted">Muted</span>
                            </div>
                        </div>
                        <button class="btn" :class="u.is_verified ? 'btn-secondary' : 'btn-primary'" style="padding: 6px 12px; font-size: 12px;" @click="toggleVerified(u)">
                            {{ u.is_verified ? 'Unverify' : 'Verify' }}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div v-if="toast.show" class="toast" :class="'toast-' + toast.type">{{ toast.message }}</div>
</div>

<script nonce="<?= $nonce ?>" src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
<script nonce="<?= $nonce ?>" src="https://js.pusher.com/8.2.0/pusher.min.js"></script>
<script nonce="<?= $nonce ?>">
const { createApp, ref, reactive, computed, watch, onMounted, onUnmounted, nextTick } = Vue;

createApp({
    setup() {
        const view = ref('loading');
        const user = ref(null);
        const accessToken = ref(null);
        const convos = ref([]);
        const currentConvo = ref(null);
        const messages = ref([]);
        const messageInput = ref('');
        const messagesContainer = ref(null);
        
        const authTab = ref('login');
        const authForm = reactive({ username: '', password: '' });
        const authError = ref('');
        const authLoading = ref(false);
        
        const showInviteModal = ref(false);
        const inviteUrl = ref('');
        const showReportModal = ref(false);
        const reportReason = ref('');
        
        const showSettingsPanel = ref(false);
        const fontScale = ref(1.0);
        const selectedFontId = ref(1);
        const currentFont = ref(null);
        const availableFonts = ref([]);
        const selectedThemeId = ref(null);
        const currentTheme = ref(null);
        const availableThemes = ref([]);
        const verificationMessage = ref('');
        const verificationRequestSent = ref(false);
        const newFont = reactive({ name: '', css_value: '', import_url: '' });
        
        const showSupportPanel = ref(false);
        const supportMessages = ref([]);
        const supportUnreadCount = ref(0);
        const expandedSupportId = ref(null);
        
        const showAdminPanel = ref(false);
        const adminTab = ref('reports');
        const adminReports = ref([]);
        const bannedWords = ref([]);
        const adminUsers = ref([]);
        const adminThemes = ref([]);
        const verificationRequests = ref([]);
        const adminSupportMessages = ref([]);
        const newWord = reactive({ word: '', penalty_type: 'warn', penalty_duration: 0 });
        const newTheme = reactive({ name: '', definition_json: '' });
        const newSupportMessage = reactive({ title: '', body: '' });
        
        const toast = reactive({ show: false, message: '', type: 'success' });
        let toastTimeout = null;
        let pollInterval = null;
        let refreshTimeout = null;
        let statusPollInterval = null;

        const pusher = ref(null);
        const currentChannel = ref(null);
        const typingUsers = ref({});
        const typingTimeouts = {};
        const isTyping = ref(false);
        const pusherSocketId = ref(null);

        watch([currentTheme, fontScale, currentFont], () => {
            const root = document.documentElement;
            const fontLinkId = 'dynamic-font-link';
            let linkEl = document.getElementById(fontLinkId);
            
            if (currentFont.value && currentFont.value.import_url) {
                if (!linkEl) {
                    linkEl = document.createElement('link');
                    linkEl.id = fontLinkId;
                    linkEl.rel = 'stylesheet';
                    document.head.appendChild(linkEl);
                }
                if (linkEl.href !== currentFont.value.import_url) {
                    linkEl.href = currentFont.value.import_url;
                }
            } else if (linkEl) {
                linkEl.remove();
            }
            
            const fontStack = currentFont.value ? currentFont.value.css_value : "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', 'Helvetica Neue', system-ui, sans-serif";
            root.style.setProperty('--font-family', fontStack);
            root.style.setProperty('--font-scale', fontScale.value);
            
            if (currentTheme.value) {
                const t = currentTheme.value.definition || currentTheme.value;
                root.style.setProperty('--bg-primary', t.background || '#000');
                root.style.setProperty('--glass-bg', t.header || 'rgba(30, 30, 32, 0.78)');
                root.style.setProperty('--bubble-incoming', t.incomingBubble || 'rgba(58, 58, 60, 0.85)');
                root.style.setProperty('--bubble-outgoing-start', t.outgoingBubble || '#0A84FF');
                root.style.setProperty('--bubble-outgoing-end', t.outgoingBubble || '#3EA1FF');
                root.style.setProperty('--accent', t.accent || '#0A84FF');
            } else {
                ['--bg-primary', '--glass-bg', '--bubble-incoming', '--bubble-outgoing-start', '--bubble-outgoing-end', '--accent']
                    .forEach(prop => root.style.removeProperty(prop));
            }
        }, { immediate: true });

        const typingIndicator = computed(() => {
            const users = Object.values(typingUsers.value);
            if (users.length === 0) return '';
            if (users.length === 1) return users[0] + ' is typing...';
            return users[0] + ' and others are typing...';
        });

        const activeStatus = computed(() => {
            if (!currentConvo.value?.other_last_active) return null;
            const t = currentConvo.value.other_last_active.replace(' ', 'T') + 'Z';
            const date = new Date(t);
            const now = new Date();
            const diffSeconds = Math.floor((now - date) / 1000);
            if (diffSeconds < 120) return 'Online';
            if (diffSeconds < 3600) return 'Active ' + Math.floor(diffSeconds / 60) + 'm ago';
            if (diffSeconds < 86400) return 'Active ' + Math.floor(diffSeconds / 3600) + 'h ago';
            return null;
        });

        const showToast = (message, type = 'success') => {
            if (toastTimeout) clearTimeout(toastTimeout);
            toast.show = true;
            toast.message = message;
            toast.type = type;
            toastTimeout = setTimeout(() => { toast.show = false; }, 3000);
        };

        const api = async (path, opts = {}) => {
            const headers = { 'Content-Type': 'application/json', ...opts.headers };
            if (accessToken.value) headers['Authorization'] = 'Bearer ' + accessToken.value;
            const res = await fetch(path, { ...opts, headers, credentials: 'include' });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Request failed');
            return data;
        };

        const formatTime = (dateStr) => {
            if (!dateStr) return '';
            const d = new Date(dateStr.replace(' ', 'T') + 'Z');
            if (isNaN(d)) return dateStr;
            const now = new Date();
            if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        };

        const scheduleRefresh = (expiresIn) => {
            if (refreshTimeout) clearTimeout(refreshTimeout);
            refreshTimeout = setTimeout(async () => { 
                if (user.value) {
                    await tryRefresh();
                    updatePusherAuth();
                }
            }, Math.max((expiresIn - 60) * 1000, 10000));
        };

        const updatePusherAuth = () => {
            if (pusher.value && accessToken.value) {
                pusher.value.config.auth = {
                    headers: { 'Authorization': 'Bearer ' + accessToken.value, 'Content-Type': 'application/json' }
                };
            }
        };

        const initializePusher = async () => {
            try {
                const config = await api('/api/pusher/config');
                if (!config.enabled || !config.key) return;
                pusher.value = new Pusher(config.key, {
                    cluster: config.cluster,
                    authEndpoint: '/api/pusher/auth',
                    auth: { headers: { 'Authorization': 'Bearer ' + accessToken.value, 'Content-Type': 'application/json' } }
                });
                pusher.value.connection.bind('connected', () => { pusherSocketId.value = pusher.value.connection.socket_id; });
            } catch (err) { console.error('Pusher init failed:', err); }
        };

        const subscribeToConversation = (convoId) => {
            if (!pusher.value || !convoId) return;
            if (currentChannel.value) { pusher.value.unsubscribe(currentChannel.value.name); currentChannel.value = null; }
            const channelName = 'private-conversation-' + convoId;
            currentChannel.value = pusher.value.subscribe(channelName);
            currentChannel.value.bind('pusher:subscription_succeeded', () => { stopPolling(); startStatusPolling(); });
            currentChannel.value.bind('pusher:subscription_error', () => { startPolling(); });
            currentChannel.value.bind('new-message', (data) => {
                const msgConvoId = data.convo_id || data.conversation_id;
                if (msgConvoId === currentConvo.value?.id) {
                    const exists = messages.value.some(m => m.id === data.message.id);
                    if (!exists && data.message.user_id !== user.value?.id) {
                        messages.value.push(data.message);
                        nextTick(() => scrollToBottom());
                        markRead();
                    }
                }
                loadConvos();
            });
            currentChannel.value.bind('user-typing', (data) => {
                if (data.user_id !== user.value?.id) {
                    typingUsers.value[data.user_id] = data.username;
                    if (typingTimeouts[data.user_id]) clearTimeout(typingTimeouts[data.user_id]);
                    typingTimeouts[data.user_id] = setTimeout(() => { delete typingUsers.value[data.user_id]; }, 3000);
                }
            });
            currentChannel.value.bind('message-read', (data) => {
                messages.value.forEach(m => { if (m.id <= data.message_id && m.is_mine) m.is_read_by_other = true; });
            });
            currentChannel.value.bind('message-deleted', (data) => {
                const idx = messages.value.findIndex(m => m.id === data.message_id);
                if (idx !== -1) messages.value.splice(idx, 1);
            });
        };

        const handleTyping = () => {
            if (!currentConvo.value || !user.value) return;
            if (!isTyping.value) {
                isTyping.value = true;
                api('/api/pusher/typing', { method: 'POST', body: JSON.stringify({ convo_id: currentConvo.value.id }) }).catch(() => {});
                setTimeout(() => { isTyping.value = false; }, 2500);
            }
        };

        const startStatusPolling = () => {
            if (statusPollInterval) clearInterval(statusPollInterval);
            statusPollInterval = setInterval(async () => {
                if (view.value !== 'chat' || !currentConvo.value) return;
                try {
                    const lastId = messages.value.length ? Math.max(...messages.value.map(m => m.id)) : 0;
                    const data = await api('/api/poll?convo_id=' + currentConvo.value.id + '&last_id=' + lastId);
                    if (data.partner_last_active) currentConvo.value.other_last_active = data.partner_last_active;
                } catch(e) {}
            }, 60000);
        };

        const tryRefresh = async () => {
            try {
                const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
                if (res.ok) {
                    const data = await res.json();
                    accessToken.value = data.access_token;
                    user.value = data.user;
                    fontScale.value = data.user.font_scale || 1.0;
                    selectedFontId.value = data.user.font_id || 1;
                    currentFont.value = data.user.font;
                    selectedThemeId.value = data.user.theme_id;
                    currentTheme.value = data.user.theme ? (typeof data.user.theme === 'string' ? JSON.parse(data.user.theme) : data.user.theme) : null;
                    await initializePusher();
                    await handlePendingInvite();
                    await loadConvos();
                    await loadAvailableThemes();
                    await loadFonts();
                    await loadSupportUnreadCount();
                    view.value = 'convos';
                    scheduleRefresh(data.expires_in);
                } else { view.value = 'auth'; }
            } catch (e) { view.value = 'auth'; }
        };

        const handlePendingInvite = async () => {
            const invite = localStorage.getItem('pending_invite');
            if (!invite) return;
            localStorage.removeItem('pending_invite');
            try { await api('/api/invite/redeem', { method: 'POST', body: JSON.stringify({ token: invite }) }); showToast('Invite accepted!'); } catch (e) { if (!e.message.includes('Already')) showToast(e.message, 'error'); }
        };

        const handleAuth = async () => {
            if (authLoading.value) return;
            authLoading.value = true;
            authError.value = '';
            try {
                if (authTab.value === 'register') await api('/api/auth/register', { method: 'POST', body: JSON.stringify(authForm) });
                const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(authForm) });
                accessToken.value = data.access_token;
                user.value = data.user;
                fontScale.value = data.user.font_scale || 1.0;
                selectedFontId.value = data.user.font_id || 1;
                currentFont.value = data.user.font;
                selectedThemeId.value = data.user.theme_id;
                currentTheme.value = data.user.theme;
                await initializePusher();
                await handlePendingInvite();
                await loadConvos();
                await loadAvailableThemes();
                await loadFonts();
                await loadSupportUnreadCount();
                view.value = 'convos';
                scheduleRefresh(data.expires_in);
                authForm.username = '';
                authForm.password = '';
            } catch (e) { authError.value = e.message; } finally { authLoading.value = false; }
        };

        const logout = async () => { 
            stopPolling(); 
            if (pusher.value) { pusher.value.disconnect(); pusher.value = null; }
            try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) {} 
            accessToken.value = null; 
            user.value = null; 
            convos.value = []; 
            view.value = 'auth'; 
        };
        
        const loadConvos = async () => { try { const data = await api('/api/convos'); convos.value = data.convos; } catch (e) { showToast('Failed to load conversations', 'error'); } };
        const loadAvailableThemes = async () => { try { const data = await api('/api/themes'); availableThemes.value = data.themes.map(t => ({ ...t, definition: typeof t.definition === 'string' ? JSON.parse(t.definition) : t.definition })); } catch (e) {} };
        const loadFonts = async () => { try { const data = await api('/api/fonts'); availableFonts.value = data.fonts; } catch (e) {} };
        const loadSupportUnreadCount = async () => { try { const data = await api('/api/support/unread_count'); supportUnreadCount.value = data.unread_count; } catch (e) {} };
        const createInvite = async () => { try { const data = await api('/api/invite/create', { method: 'POST' }); inviteUrl.value = data.invite_url; showInviteModal.value = true; await loadConvos(); } catch (e) { showToast(e.message, 'error'); } };
        const copyInvite = async () => { try { await navigator.clipboard.writeText(inviteUrl.value); showToast('Copied!'); showInviteModal.value = false; } catch (e) { showToast('Failed to copy', 'error'); } };
        
        const openConvo = async (c) => { 
            currentConvo.value = c; 
            messages.value = []; 
            typingUsers.value = {}; 
            view.value = 'chat'; 
            subscribeToConversation(c.id); 
            await loadMessages(); 
            if (!pusher.value) startPolling(); 
        };
        
        const goBack = async () => { 
            stopPolling(); 
            if (currentChannel.value && pusher.value) pusher.value.unsubscribe(currentChannel.value.name);
            currentChannel.value = null; 
            view.value = 'convos'; 
            await loadConvos(); 
        };
        
        const loadMessages = async () => { try { const data = await api('/api/messages?convo_id=' + currentConvo.value.id); messages.value = data.messages; await nextTick(); scrollToBottom(); await markRead(); } catch (e) { showToast('Failed to load messages', 'error'); } };
        
        const sendMessage = async () => { 
            const body = messageInput.value.trim(); 
            if (!body) return; 
            messageInput.value = ''; 
            try { 
                const payload = { convo_id: currentConvo.value.id, body };
                if (pusherSocketId.value) payload.socket_id = pusherSocketId.value;
                const result = await api('/api/messages/send', { method: 'POST', body: JSON.stringify(payload) }); 
                messages.value.push({
                    id: result.message_id,
                    convo_id: currentConvo.value.id,
                    user_id: user.value.id,
                    username: user.value.username,
                    is_verified: user.value.is_verified,
                    body: body,
                    created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
                    is_delivered: false,
                    is_read_by_other: false,
                    is_mine: true
                });
                await nextTick();
                scrollToBottom();
            } catch (e) { messageInput.value = body; showToast(e.message, 'error'); } 
        };

        const sendLike = async () => {
            if (!currentConvo.value?.id) return;
            if (messageInput.value.trim()) return sendMessage();
            messageInput.value = '👍';
            await sendMessage();
        };
        
        const markRead = async () => { 
            const unread = messages.value.filter(m => !m.is_mine); 
            if (unread.length === 0) return; 
            const lastId = Math.max(...unread.map(m => m.id)); 
            try { 
                const payload = { convo_id: currentConvo.value.id, up_to_message_id: lastId };
                if (pusherSocketId.value) payload.socket_id = pusherSocketId.value;
                await api('/api/messages/mark_read', { method: 'POST', body: JSON.stringify(payload) }); 
            } catch (e) {} 
        };
        
        const scrollToBottom = () => { if (messagesContainer.value) messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight; };
        
        const startPolling = () => { 
            stopPolling(); 
            pollInterval = setInterval(async () => { 
                if (view.value !== 'chat' || !currentConvo.value) return; 
                try { 
                    const lastId = messages.value.length ? Math.max(...messages.value.map(m => m.id)) : 0; 
                    const data = await api('/api/poll?convo_id=' + currentConvo.value.id + '&last_id=' + lastId); 
                    if (data.messages?.length) { 
                        const existingIds = new Set(messages.value.map(m => m.id)); 
                        const newMsgs = data.messages.filter(m => !existingIds.has(m.id)); 
                        if (newMsgs.length) { 
                            messages.value.push(...newMsgs); 
                            await nextTick(); 
                            scrollToBottom(); 
                            await markRead(); 
                        } 
                    } 
                    if (data.status_updates) data.status_updates.forEach(u => { const msg = messages.value.find(m => m.id === u.id); if (msg) { msg.is_delivered = u.is_delivered; msg.is_read_by_other = u.is_read_by_other; } }); 
                    if (data.deleted_ids?.length) { const deletedSet = new Set(data.deleted_ids); messages.value = messages.value.filter(m => !deletedSet.has(m.id)); } 
                } catch (e) {} 
            }, 2000); 
        };
        
        const stopPolling = () => { 
            if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
            if (statusPollInterval) { clearInterval(statusPollInterval); statusPollInterval = null; }
        };

        const submitReport = async () => { if (!reportReason.value.trim()) return; try { await api('/api/report', { method: 'POST', body: JSON.stringify({ reported_user_id: currentConvo.value.other_user_id, reason: reportReason.value.trim() }) }); showToast('Report submitted'); showReportModal.value = false; reportReason.value = ''; } catch (e) { showToast(e.message, 'error'); } };
        const increaseFontScale = async () => { const newScale = Math.min(1.4, fontScale.value + 0.05); fontScale.value = newScale; try { await api('/api/user/font_scale', { method: 'POST', body: JSON.stringify({ scale: newScale }) }); } catch (e) { showToast(e.message, 'error'); } };
        const decreaseFontScale = async () => { const newScale = Math.max(0.85, fontScale.value - 0.05); fontScale.value = newScale; try { await api('/api/user/font_scale', { method: 'POST', body: JSON.stringify({ scale: newScale }) }); } catch (e) { showToast(e.message, 'error'); } };
        const updateFont = async () => { try { const data = await api('/api/user/font', { method: 'POST', body: JSON.stringify({ font_id: selectedFontId.value }) }); currentFont.value = data.font; showToast('Font updated'); } catch (e) { showToast(e.message, 'error'); } };
        const updateTheme = async () => { 
            try { 
                let themeId = selectedThemeId.value;
                if (themeId !== null && themeId !== undefined && themeId !== '') { themeId = Number(themeId); if (isNaN(themeId) || themeId === 0) themeId = null; } else { themeId = null; }
                const data = await api('/api/user/theme', { method: 'POST', body: JSON.stringify({ theme_id: themeId }) }); 
                currentTheme.value = null; 
                await nextTick();
                if (data.theme) currentTheme.value = typeof data.theme === 'string' ? JSON.parse(data.theme) : data.theme;
                showToast('Theme updated'); 
            } catch (e) { showToast(e.message, 'error'); } 
        };
        const requestVerification = async () => { if (!verificationMessage.value.trim()) return; try { await api('/api/user/request_verification', { method: 'POST', body: JSON.stringify({ message: verificationMessage.value.trim() }) }); verificationRequestSent.value = true; showToast('Verification request submitted'); } catch (e) { showToast(e.message, 'error'); } };
        const openSupport = async () => { showSupportPanel.value = true; try { const data = await api('/api/support'); supportMessages.value = data.messages; } catch (e) { showToast(e.message, 'error'); } };
        const openSupportMessage = async (m) => { if (expandedSupportId.value === m.id) { expandedSupportId.value = null; return; } expandedSupportId.value = m.id; if (!m.is_read) { try { await api('/api/support/mark_read', { method: 'POST', body: JSON.stringify({ message_id: m.id }) }); m.is_read = true; supportUnreadCount.value = Math.max(0, supportUnreadCount.value - 1); } catch (e) {} } };
        const loadReports = async () => { try { const data = await api('/api/admin/reports'); adminReports.value = data.reports; } catch (e) { showToast(e.message, 'error'); } };
        const adminAction = async (reportId, action, duration) => { try { await api('/api/admin/reports/action', { method: 'POST', body: JSON.stringify({ report_id: reportId, action, duration }) }); await loadReports(); showToast('Action applied'); } catch (e) { showToast(e.message, 'error'); } };
        const rejectReport = async (reportId) => { try { await api('/api/admin/reports/reject', { method: 'POST', body: JSON.stringify({ report_id: reportId }) }); await loadReports(); showToast('Report rejected'); } catch (e) { showToast(e.message, 'error'); } };
        const loadBannedWords = async () => { try { const data = await api('/api/admin/banned_words'); bannedWords.value = data.banned_words; } catch (e) { showToast(e.message, 'error'); } };
        const addBannedWord = async () => { if (!newWord.word.trim()) return; try { await api('/api/admin/banned_words/add', { method: 'POST', body: JSON.stringify(newWord) }); await loadBannedWords(); showToast('Word added'); newWord.word = ''; newWord.penalty_type = 'warn'; newWord.penalty_duration = 0; } catch (e) { showToast(e.message, 'error'); } };
        const deleteBannedWord = async (id) => { try { await api('/api/admin/banned_words/delete', { method: 'POST', body: JSON.stringify({ id }) }); await loadBannedWords(); showToast('Word deleted'); } catch (e) { showToast(e.message, 'error'); } };
        const loadUsers = async () => { try { const data = await api('/api/admin/users'); adminUsers.value = data.users; } catch (e) { showToast(e.message, 'error'); } };
        const toggleVerified = async (u) => { try { await api('/api/admin/set_verified', { method: 'POST', body: JSON.stringify({ user_id: u.id, value: !u.is_verified }) }); u.is_verified = !u.is_verified; showToast(u.is_verified ? 'User verified' : 'User unverified'); } catch (e) { showToast(e.message, 'error'); } };
        const loadAdminThemes = async () => { try { const data = await api('/api/admin/themes'); adminThemes.value = data.themes; } catch (e) { showToast(e.message, 'error'); } };
        const createTheme = async () => { if (!newTheme.name.trim() || !newTheme.definition_json.trim()) return; try { await api('/api/admin/themes/create', { method: 'POST', body: JSON.stringify(newTheme) }); await loadAdminThemes(); await loadAvailableThemes(); showToast('Theme created'); newTheme.name = ''; newTheme.definition_json = ''; } catch (e) { showToast(e.message, 'error'); } };
        const activateTheme = async (themeId) => { try { await api('/api/admin/themes/activate', { method: 'POST', body: JSON.stringify({ theme_id: themeId }) }); await loadAdminThemes(); await loadAvailableThemes(); showToast('Theme activated'); } catch (e) { showToast(e.message, 'error'); } };
        const deactivateTheme = async (themeId) => { try { await api('/api/admin/themes/deactivate', { method: 'POST', body: JSON.stringify({ theme_id: themeId }) }); await loadAdminThemes(); await loadAvailableThemes(); showToast('Theme deactivated'); } catch (e) { showToast(e.message, 'error'); } };
        const deleteTheme = async (themeId) => { try { await api('/api/admin/themes/delete', { method: 'POST', body: JSON.stringify({ theme_id: themeId }) }); await loadAdminThemes(); await loadAvailableThemes(); showToast('Theme deleted'); } catch (e) { showToast(e.message, 'error'); } };
        const loadAdminFonts = async () => { try { const data = await api('/api/admin/fonts'); availableFonts.value = data.fonts; } catch (e) { showToast(e.message, 'error'); } };
        const createFont = async () => { if (!newFont.name.trim() || !newFont.css_value.trim()) return; try { await api('/api/admin/fonts/add', { method: 'POST', body: JSON.stringify(newFont) }); await loadAdminFonts(); showToast('Font added'); newFont.name = ''; newFont.css_value = ''; newFont.import_url = ''; } catch (e) { showToast(e.message, 'error'); } };
        const deleteFont = async (id) => { if (!confirm('Delete this font?')) return; try { await api('/api/admin/fonts/delete', { method: 'POST', body: JSON.stringify({ id }) }); await loadAdminFonts(); showToast('Font deleted'); } catch (e) { showToast(e.message, 'error'); } };
        const loadVerificationRequests = async () => { try { const data = await api('/api/admin/verification_requests'); verificationRequests.value = data.requests; } catch (e) { showToast(e.message, 'error'); } };
        const approveVerification = async (requestId) => { try { await api('/api/admin/verification_requests/approve', { method: 'POST', body: JSON.stringify({ request_id: requestId }) }); await loadVerificationRequests(); showToast('Approved'); } catch (e) { showToast(e.message, 'error'); } };
        const rejectVerification = async (requestId) => { try { await api('/api/admin/verification_requests/reject', { method: 'POST', body: JSON.stringify({ request_id: requestId }) }); await loadVerificationRequests(); showToast('Rejected'); } catch (e) { showToast(e.message, 'error'); } };
        const loadAdminSupport = async () => { try { const data = await api('/api/admin/support/list'); adminSupportMessages.value = data.messages; } catch (e) { showToast(e.message, 'error'); } };
        const sendSupportMessage = async () => { if (!newSupportMessage.title.trim() || !newSupportMessage.body.trim()) return; try { await api('/api/admin/support/send', { method: 'POST', body: JSON.stringify(newSupportMessage) }); await loadAdminSupport(); showToast('Sent'); newSupportMessage.title = ''; newSupportMessage.body = ''; } catch (e) { showToast(e.message, 'error'); } };

        onMounted(() => { 
            const params = new URLSearchParams(window.location.search); 
            const invite = params.get('invite'); 
            if (invite) { localStorage.setItem('pending_invite', invite); window.history.replaceState({}, '', window.location.pathname); } 
            tryRefresh(); 
        });
        
        onUnmounted(() => { 
            stopPolling(); 
            if (refreshTimeout) clearTimeout(refreshTimeout); 
            if (toastTimeout) clearTimeout(toastTimeout); 
            if (pusher.value) pusher.value.disconnect(); 
        });

        return { 
            view, user, convos, currentConvo, messages, messageInput, messagesContainer, 
            authTab, authForm, authError, authLoading, showInviteModal, inviteUrl, showReportModal, 
            reportReason, showSettingsPanel, fontScale, selectedFontId, currentFont, availableFonts,
            selectedThemeId, currentTheme, availableThemes, verificationMessage, verificationRequestSent, 
            showSupportPanel, supportMessages, supportUnreadCount, expandedSupportId, showAdminPanel, 
            adminTab, adminReports, bannedWords, adminUsers, adminThemes, verificationRequests, 
            adminSupportMessages, newWord, newTheme, newFont, newSupportMessage, toast, 
            typingIndicator, activeStatus, formatTime, handleAuth, logout, createInvite, 
            copyInvite, openConvo, goBack, sendMessage, sendLike, submitReport, increaseFontScale, 
            decreaseFontScale, updateFont, updateTheme, requestVerification, openSupport, 
            openSupportMessage, loadReports, adminAction, rejectReport, loadBannedWords, 
            addBannedWord, deleteBannedWord, loadUsers, toggleVerified, loadAdminThemes, 
            createTheme, activateTheme, deactivateTheme, deleteTheme, loadAdminFonts, createFont,
            deleteFont, loadVerificationRequests, approveVerification, rejectVerification, 
            loadAdminSupport, sendSupportMessage, handleTyping, showToast
        };
    }
}).mount('#app');
</script>
</body>
</html>
