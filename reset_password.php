<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

require_once 'db.php';

$error = "";
$success = "";
$token = isset($_GET['token']) ? trim($_GET['token']) : (isset($_POST['token']) ? trim($_POST['token']) : "");
$valid_token = false;
$user_id = null;

if (empty($token)) {
    $error = "Invalid or missing reset link.";
} else {
    $stmt = $conn->prepare("SELECT id, reset_expires FROM users WHERE reset_token = ?");
    $stmt->bindValue(1, $token, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;
    $stmt->close();

    if (!$user) {
        $error = "This reset link is invalid or has already been used.";
    } elseif (strtotime($user['reset_expires']) < time()) {
        $error = "This reset link has expired. Please request a new one.";
    } else {
        $valid_token = true;
        $user_id = $user['id'];
    }
}

if ($valid_token && $_SERVER["REQUEST_METHOD"] == "POST") {
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    if (empty($new_password) || empty($confirm_password)) {
        $error = "Please fill in all fields.";
    } elseif ($new_password !== $confirm_password) {
        $error = "Passwords do not match!";
    } else {
        $length_ok = strlen($new_password) >= 8;
        $upper_ok  = preg_match('/[A-Z]/', $new_password);
        $lower_ok  = preg_match('/[a-z]/', $new_password);
        $number_ok = preg_match('/[0-9]/', $new_password);
        $symbol_ok = preg_match('/[\W_]/', $new_password);

        if (!$length_ok || !$upper_ok || !$lower_ok || !$number_ok || !$symbol_ok) {
            $error = "Password must be at least 8 characters and include an Uppercase letter, Lowercase letter, Number & Symbol.";
        } else {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            // Clear the token so this link can't be used again
            $update_stmt = $conn->prepare("UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?");
            $update_stmt->bindValue(1, $hashed_password, SQLITE3_TEXT);
            $update_stmt->bindValue(2, $user_id, SQLITE3_INTEGER);

            if ($update_stmt->execute()) {
                $success = "Password successfully reset! You can now <a href='index.php'>log in</a> with your new password.";
                $valid_token = false; // hide the form now that it's done
            } else {
                $error = "Something went wrong. Please try again.";
            }
            $update_stmt->close();
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
    <title>Reset Password - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: var(--bg-main); }
        .reset-container { background: var(--card-bg); padding: 35px; border-radius: var(--radius); box-shadow: var(--shadow); width: 100%; max-width: 420px; border: 1px solid var(--border-color); }
        h2 { text-align: center; margin-bottom: 25px; color: var(--text-main); }
        .password-wrapper { position: relative; }
        .password-wrapper input { width: 100%; padding-right: 40px; }
        .toggle-password { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); cursor: pointer; font-size: 18px; user-select: none; }
        .link { text-align: center; margin-top: 20px; font-size: 14px; color: var(--text-muted); }
        .link a { color: var(--primary); text-decoration: none; font-weight: 600; }
        .link a:hover { text-decoration: underline; }
        .password-hint { font-size: 12px; color: var(--text-muted); margin-top: 5px; }
    </style>
</head>
<body>

<div class="reset-container">
    <div class="login-logo">
        <div style="text-align: center; margin-bottom: 25px;">
            <img src="image/QR SHIELD TEXT.png" alt="QR Shield Logo" style="height: 200px; margin-bottom: 8px;">
        </div>
    </div>

    <h2>Reset Password</h2>

    <?php if (!empty($error)): ?>
        <div class="error"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="success"><?php echo $success; ?></div>
    <?php endif; ?>

    <?php if ($valid_token): ?>
    <form action="reset_password.php" method="POST">
        <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
        <div class="form-group">
            <label for="new_password">New Password</label>
            <div class="password-wrapper">
                <input type="password" id="new_password" name="new_password" required>
                <span class="toggle-password"
                    onmousedown="showPassword('new_password', this)" onmouseup="hidePassword('new_password', this)" onmouseleave="hidePassword('new_password', this)"
                    ontouchstart="showPassword('new_password', this)" ontouchend="hidePassword('new_password', this)">👁️</span>
            </div>
            <div class="password-hint">Min 8 chars (A-Z, a-z, 0-9, symbol)</div>
        </div>
        <div class="form-group">
            <label for="confirm_password">Confirm New Password</label>
            <div class="password-wrapper">
                <input type="password" id="confirm_password" name="confirm_password" required>
                <span class="toggle-password"
                    onmousedown="showPassword('confirm_password', this)" onmouseup="hidePassword('confirm_password', this)" onmouseleave="hidePassword('confirm_password', this)"
                    ontouchstart="showPassword('confirm_password', this)" ontouchend="hidePassword('confirm_password', this)">👁️</span>
            </div>
        </div>
        <button type="submit">Reset Password</button>
    </form>
    <?php endif; ?>

    <div class="link">
        Remember your password? <a href="index.php">Login here</a>
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