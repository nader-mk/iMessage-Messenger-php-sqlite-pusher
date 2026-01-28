<?php

declare(strict_types=1);

/*
 TeleCDN.php
 Telegram-backed CDN module
*/

//// LOAD ENV ////
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

//// CONFIG ////

define('TG_BOT_TOKEN', getenv('TELEGRAM_BOT_TOKEN') ?: 'PUT_BOT_TOKEN_IN_ENV');
define('TG_CHAT_ID', getenv('TELEGRAM_CHAT_ID') ?: 'PUT_CHAT_ID_IN_ENV');
const DB_FILE     = __DIR__ . '/data/telecdn.sqlite'; // Put in data dir for cleanliness

const MAX_FILE_BYTES = 12000000; // 12MB safe
const ALLOWED_MIME = [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/webp' => 'webp',
    'image/gif' => 'gif'
];

//// DB INIT ////

function telecdn_db(): PDO
{
    static $pdo;
    if ($pdo) return $pdo;

    // Ensure data dir exists
    if (!is_dir(dirname(DB_FILE))) @mkdir(dirname(DB_FILE), 0700, true);

    $pdo = new PDO("sqlite:" . DB_FILE, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
    $pdo->exec("PRAGMA journal_mode=WAL");
    $pdo->exec("CREATE TABLE IF NOT EXISTS files(
        id TEXT PRIMARY KEY,
        tg_file_id TEXT,
        mime TEXT,
        created INTEGER
    )");
    return $pdo;
}

//// HELPERS ////

function telecdn_json($arr, $code = 200)
{
    http_response_code($code);
    header("Content-Type: application/json");
    echo json_encode($arr);
    exit;
}

function telecdn_rand($l = 9)
{
    return rtrim(strtr(base64_encode(random_bytes($l)), '+/', '-_'), '=');
}

//// TELEGRAM API ////

function telecdn_tg_api($method, $data, $files = [])
{
    $url = "https://api.telegram.org/bot" . TG_BOT_TOKEN . "/" . $method;

    foreach ($files as $k => $p)
        $data[$k] = new CURLFile($p);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $data,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT => 30
    ]);
    $res = curl_exec($ch);
    curl_close($ch);

    $j = json_decode($res, true);
    if (!$j || empty($j['ok'])) {
        error_log("TeleCDN Error: " . print_r($j, true));
        telecdn_json(['error' => 'Telegram API error'], 502);
    }
    return $j;
}

//// UPLOAD HANDLER ////

function telecdn_upload()
{
    // Basic CORS for upload
    header("Access-Control-Allow-Origin: *");

    if (empty($_FILES['file'])) telecdn_json(['error' => 'No file'], 400);
    $f = $_FILES['file'];

    if ($f['size'] > MAX_FILE_BYTES) telecdn_json(['error' => 'File too large'], 413);

    $mime = mime_content_type($f['tmp_name']);
    if (!isset(ALLOWED_MIME[$mime])) telecdn_json(['error' => 'Invalid type'], 415);

    // Send to Telegram
    $tg = telecdn_tg_api('sendDocument', [
        'chat_id' => TG_CHAT_ID,
        'disable_content_type_detection' => true
    ], [
        'document' => $f['tmp_name']
    ]);

    $doc = $tg['result']['document'] ?? null;
    if (!$doc) telecdn_json(['error' => 'Upload failed'], 500);

    $id = telecdn_rand();

    telecdn_db()->prepare("INSERT INTO files VALUES(?,?,?,?)")
        ->execute([$id, $doc['file_id'], $mime, time()]);

    telecdn_json(['ok' => true, 'id' => $id]);
}

//// VIEW HANDLER ////

function telecdn_view($id)
{
    $st = telecdn_db()->prepare("SELECT tg_file_id,mime FROM files WHERE id=?");
    $st->execute([$id]);
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (!$r) {
        http_response_code(404);
        exit;
    }

    // Get Telegram file path
    $tg = telecdn_tg_api('getFile', ['file_id' => $r['tg_file_id']]);
    $path = $tg['result']['file_path'];

    $url = "https://api.telegram.org/file/bot" . TG_BOT_TOKEN . "/" . $path;

    header("Content-Type: " . $r['mime']);
    header("Cache-Control: public, max-age=31536000, immutable");

    // Zero-memory streaming
    $fp = fopen($url, 'rb');
    if ($fp) {
        while (!feof($fp)) {
            echo fread($fp, 8192);
            flush();
        }
        fclose($fp);
    }
    exit;
}

//// ROUTER ////

$action = $_GET['action'] ?? '';

if ($action === 'upload' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    telecdn_upload();
}

if ($action === 'view' && isset($_GET['id'])) {
    telecdn_view($_GET['id']);
}

telecdn_json(['error' => 'Bad request'], 400);
