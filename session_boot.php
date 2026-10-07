<?php
// Use this at the top of EVERY page instead of:  session_start(); require_once 'db.php';
const TERMS_VERSION = '1.0';   // change this number to make everybody accept the terms again
const STAY_DAYS     = 30;      // how long a login lasts

$IS_HTTPS = !empty($_SERVER['HTTPS']) || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
ini_set('session.gc_maxlifetime', (string)(STAY_DAYS * 86400));
session_set_cookie_params([
    'lifetime' => STAY_DAYS * 86400, 'path' => '/',
    'secure' => $IS_HTTPS, 'httponly' => true, 'samesite' => 'Lax',
]);
session_start();
require_once __DIR__ . '/db.php';

function start_user_session($id, $username, $role) {
    session_regenerate_id(true);
    $_SESSION = ['user_id' => (int)$id, 'username' => $username, 'role' => $role];
}

function set_remember_cookie($value, $expires) {
    global $IS_HTTPS;
    setcookie('remember', $value, ['expires' => $expires, 'path' => '/',
        'secure' => $IS_HTTPS, 'httponly' => true, 'samesite' => 'Lax']);
}

// "Stay logged in" token stored in the database, so it survives server/container restarts.
function issue_remember($conn, $user_id) {
    $conn->query('DELETE FROM remember_tokens WHERE expires < ' . time());
    $selector  = bin2hex(random_bytes(9));
    $validator = bin2hex(random_bytes(24));
    $expires   = time() + STAY_DAYS * 86400;
    $st = $conn->prepare('INSERT INTO remember_tokens (selector, token_hash, user_id, expires) VALUES (?, ?, ?, ?)');
    $st->bindValue(1, $selector, SQLITE3_TEXT);
    $st->bindValue(2, hash('sha256', $validator), SQLITE3_TEXT);
    $st->bindValue(3, (int)$user_id, SQLITE3_INTEGER);
    $st->bindValue(4, $expires, SQLITE3_INTEGER);
    $st->execute();
    set_remember_cookie("$selector:$validator", $expires);
}

function forget_remember($conn) {
    if (!empty($_COOKIE['remember'])) {
        $selector = explode(':', $_COOKIE['remember'], 2)[0];
        $st = $conn->prepare('DELETE FROM remember_tokens WHERE selector = ?');
        $st->bindValue(1, $selector, SQLITE3_TEXT);
        $st->execute();
    }
    set_remember_cookie('', time() - 3600);
}

// Guest = a temporary account, so the existing scanner code works unchanged.
function create_guest($conn) {
    $old = "role = 'guest' AND created_at < datetime('now', '-2 days')";
    $conn->query("DELETE FROM scan_history WHERE user_id IN (SELECT id FROM users WHERE $old)");
    $conn->query("DELETE FROM users WHERE $old");
    $name = 'Guest-' . bin2hex(random_bytes(3));
    $st = $conn->prepare("INSERT INTO users (username, email, password, role, verified) VALUES (?, ?, ?, 'guest', 1)");
    $st->bindValue(1, $name, SQLITE3_TEXT);
    $st->bindValue(2, strtolower($name) . '@guest.invalid', SQLITE3_TEXT);
    $st->bindValue(3, password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT), SQLITE3_TEXT);
    $st->execute();
    return [$conn->insert_id(), $name];
}

// 1) Restore the login from the "stay logged in" cookie.
if (empty($_SESSION['user_id']) && !empty($_COOKIE['remember'])) {
    [$sel, $val] = array_pad(explode(':', $_COOKIE['remember'], 2), 2, '');
    $st = $conn->prepare('SELECT t.token_hash, t.expires, u.id, u.username, u.role, u.verified
                          FROM remember_tokens t JOIN users u ON u.id = t.user_id WHERE t.selector = ?');
    $st->bindValue(1, $sel, SQLITE3_TEXT);
    $r = $st->execute()->fetchArray(SQLITE3_ASSOC);
    if ($r && $r['expires'] > time() && !empty($r['verified'])
        && hash_equals($r['token_hash'], hash('sha256', $val))) {
        start_user_session($r['id'], $r['username'], $r['role'] ?: 'user');
    } else {
        set_remember_cookie('', time() - 3600);
    }
}

// 2) A guest whose temporary account was cleaned up must start again.
if (($_SESSION['role'] ?? '') === 'guest') {
    $st = $conn->prepare('SELECT id FROM users WHERE id = ?');
    $st->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    if (!$st->execute()->fetchArray()) { $_SESSION = []; session_destroy(); header('Location: index.php'); exit(); }
}

// 3) Registered users must have accepted the CURRENT terms (API files are skipped).
$script = basename($_SERVER['SCRIPT_NAME']);
if (!empty($_SESSION['user_id']) && ($_SESSION['role'] ?? '') !== 'guest'
    && ($_SESSION['terms_ok'] ?? '') !== TERMS_VERSION
    && !in_array($script, ['terms.php', 'logout.php'], true) && strpos($script, 'api_') !== 0) {
    $st = $conn->prepare('SELECT terms_version FROM users WHERE id = ?');
    $st->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $u = $st->execute()->fetchArray(SQLITE3_ASSOC);
    if ($u && $u['terms_version'] === TERMS_VERSION) { $_SESSION['terms_ok'] = TERMS_VERSION; }
    else { header('Location: terms.php'); exit(); }
}