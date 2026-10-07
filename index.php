<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
require_once 'session_boot.php';

// Already logged in (session or "stay logged in" cookie) -> straight to the app.
if (!empty($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

$error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['guest'])) {
        // Guest mode: no login, temporary account, simple scanner.
        [$gid, $gname] = create_guest($conn);
        start_user_session($gid, $gname, 'guest');
        header("Location: scanner.php");
        exit();
    }

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!empty($email) && !empty($password)) {
        $stmt = $conn->prepare("SELECT id, username, password, verified, role FROM users WHERE email = ?");
        if ($stmt) {
            $stmt->bindValue(1, $email, SQLITE3_TEXT);
            $result = $stmt->execute();
            $row = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;

            if ($row && $row['role'] !== 'guest' && password_verify($password, $row['password'])) {
                if (empty($row['verified'])) {
                    $error = "Please verify your email before logging in. Check your inbox for the verification link, or <a href='resend_verification.php?email=" . urlencode($email) . "'>resend it</a>.";
                } else {
                    start_user_session($row['id'], $row['username'], $row['role'] ?: 'user');
                    if (!empty($_POST['remember'])) {
                        issue_remember($conn, $row['id']);   // stay logged in for 30 days
                    }
                    header("Location: dashboard.php");   // session_boot sends them to terms.php if needed
                    exit();
                }
            } else {
                $error = "Invalid email or password!";
            }
            $stmt->close();
        }
    } else {
        $error = "Please fill in all fields.";
    }
}

if (isset($conn)) {
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - QR Shield Scanner</title>
<link rel="stylesheet" href="style.css">
<style>
body { display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background-color: var(--bg-main); }
.login-container { background: var(--card-bg); padding: 35px; border-radius: var(--radius); box-shadow: var(--shadow); width: 100%; max-width: 420px; border: 1px solid var(--border-color); }
h2 { text-align: center; margin-bottom: 25px; color: var(--text-main); }
.password-wrapper { position: relative; }
.password-wrapper input { width: 100%; padding-right: 40px; }
.toggle-password { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); cursor: pointer; font-size: 18px; user-select: none; }
.links-row { display: flex; justify-content: space-between; align-items: center; margin-top: 15px; font-size: 14px; }
.links-row a { color: var(--primary); text-decoration: none; font-weight: 600; }
.links-row a:hover { text-decoration: underline; }
.register-link { text-align: center; margin-top: 20px; font-size: 14px; color: var(--text-muted); }
.register-link a { color: var(--primary); text-decoration: none; font-weight: 600; }
.register-link a:hover { text-decoration: underline; }
.small-note { font-size: 12px; color: var(--text-muted); margin: 0 0 14px 0; text-align: center; }
.small-note a { color: var(--primary); }
.guest-btn { width: 100%; background: transparent; color: var(--primary); border: 1px solid var(--primary); }
.divider { text-align: center; color: var(--text-muted); font-size: 12px; margin: 18px 0 12px; }
</style>
</head>
<body>
<div class="login-container">
    <div class="login-logo">
        <div style="text-align: center; margin-bottom: 25px;">
            <img src="image/QR SHIELD TEXT.png" alt="QR Shield Logo" style="height: 200px; max-width: 100%; margin-bottom: 8px;">
        </div>
    </div>

    <h2>User Login</h2>

    <?php if (!empty($error)): ?>
        <div class="error"><?php echo $error; ?></div>
    <?php endif; ?>

    <form action="index.php" method="POST">
        <div class="form-group">
            <label for="email">Email Address</label>
            <input type="email" id="email" name="email" required>
        </div>

        <div class="form-group">
            <label for="password">Password</label>
            <div class="password-wrapper">
                <input type="password" id="password" name="password" required>
                <span class="toggle-password" id="togglePassword"
                      onmousedown="showPassword('password', this)" onmouseup="hidePassword('password', this)" onmouseleave="hidePassword('password', this)"
                      ontouchstart="showPassword('password', this)" ontouchend="hidePassword('password', this)">👁️</span>
            </div>
        </div>

        <div class="links-row" style="margin-bottom: 20px;">
            <label style="font-size: 13px; color: var(--text-muted);"><input type="checkbox" name="remember" value="1" checked> Keep me logged in</label>
            <a href="forgot_password.php" style="font-size: 13px; color: var(--text-muted);">Forgot Password?</a>
        </div>

        <p class="small-note">By logging in you agree to the <a href="terms.php?view=1" target="_blank">Terms &amp; Conditions</a>.</p>
        <button type="submit">Login</button>
    </form>

    <div class="divider">or</div>
    <form action="index.php" method="POST">
        <button type="submit" name="guest" value="1" class="guest-btn">Continue as Guest</button>
        <p class="small-note" style="margin-top:8px;">No account needed. Guests can scan, but cannot print receipts.</p>
    </form>

    <div class="register-link">
        Don't have an account? <a href="register.php">Register here</a>
    </div>
</div>

<script>
function showPassword(fieldId, icon) {
    document.getElementById(fieldId).type = "text";
    icon.textContent = "🙈";
}
function hidePassword(fieldId, icon) {
    document.getElementById(fieldId).type = "password";
    icon.textContent = "👁️";
}
</script>
</body>
</html>