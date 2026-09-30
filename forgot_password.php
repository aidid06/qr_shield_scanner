<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

require_once 'db.php';
require_once 'email_helper.php';

$error = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);

    if (empty($email)) {
        $error = "Please enter your email address.";
    } else {
        $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ?");
        if ($stmt) {
            $stmt->bindValue(1, $email, SQLITE3_TEXT);
            $result = $stmt->execute();
            $user = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;
            $stmt->close();

            if ($user) {
                $reset_token = bin2hex(random_bytes(32));
                // Token expires 1 hour from now
                $reset_expires = date('Y-m-d H:i:s', time() + 3600);

                $update_stmt = $conn->prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?");
                if ($update_stmt) {
                    $update_stmt->bindValue(1, $reset_token, SQLITE3_TEXT);
                    $update_stmt->bindValue(2, $reset_expires, SQLITE3_TEXT);
                    $update_stmt->bindValue(3, $user['id'], SQLITE3_INTEGER);
                    $update_stmt->execute();
                    $update_stmt->close();

                    $host = $_SERVER['HTTP_HOST'];
                    send_reset_email($user['username'], $email, $reset_token, $host);
                }
            }
            // Same message whether or not the email exists, so this page
            // can't be used to check which emails are registered.
            $success = "If an account exists with that email, a password reset link has been sent. Please check your inbox.";
        }
    }
}
if (isset($conn)) { $conn->close(); }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: var(--bg-main); }
        .reset-container { background: var(--card-bg); padding: 35px; border-radius: var(--radius); box-shadow: var(--shadow); width: 100%; max-width: 420px; border: 1px solid var(--border-color); }
        h2 { text-align: center; margin-bottom: 25px; color: var(--text-main); }
        p.hint { text-align: center; color: var(--text-muted); font-size: 0.9rem; margin-top: -15px; margin-bottom: 20px; }
        .link { text-align: center; margin-top: 20px; font-size: 14px; color: var(--text-muted); }
        .link a { color: var(--primary); text-decoration: none; font-weight: 600; }
        .link a:hover { text-decoration: underline; }
    </style>
</head>
<body>

<div class="reset-container">
    <div class="login-logo">
        <div style="text-align: center; margin-bottom: 25px;">
            <img src="image/QR SHIELD TEXT.png" alt="QR Shield Logo" style="height: 200px; margin-bottom: 8px;">
        </div>
    </div>

    <h2>Forgot Password</h2>
    <p class="hint">Enter your email and we'll send you a link to reset your password.</p>

    <?php if (!empty($error)): ?>
        <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="success"><?php echo htmlspecialchars($success); ?></div>
    <?php endif; ?>

    <?php if (empty($success)): ?>
    <form action="forgot_password.php" method="POST">
        <div class="form-group">
            <label for="email">Your Registered Email</label>
            <input type="email" id="email" name="email" required>
        </div>
        <button type="submit">Send Reset Link</button>
    </form>
    <?php endif; ?>

    <div class="link">
        Remember your password? <a href="index.php">Login here</a>
    </div>
</div>

</body>
</html>