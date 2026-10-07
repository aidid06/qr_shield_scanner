<?php
require_once 'session_boot.php';

// Guests: delete the temporary account and its scans straight away.
if (($_SESSION['role'] ?? '') === 'guest' && !empty($_SESSION['user_id'])) {
    foreach (['DELETE FROM scan_history WHERE user_id = ?', 'DELETE FROM users WHERE id = ?'] as $sql) {
        $st = $conn->prepare($sql);
        $st->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
        $st->execute();
    }
}

forget_remember($conn);     // otherwise the "stay logged in" cookie would log them straight back in
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 3600, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();
header('Location: index.php');
exit();