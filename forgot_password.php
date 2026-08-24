<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'db.php';

$error = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $new_password = $_POST['new_password'];
    $confirm_password = $_POST['confirm_password'];

    if (!empty($email) && !empty($new_password) && !empty($confirm_password)) {
        if ($new_password !== $confirm_password) {
            $error = "New passwords do not match!";
        } else {
            // Semak kriteria keselamatan password yang sama seperti register
            $length_ok = strlen($new_password) >= 8;
            $upper_ok  = preg_match('/[A-Z]/', $new_password);
            $lower_ok  = preg_match('/[a-z]/', $new_password);
            $number_ok = preg_match('/[0-9]/', $new_password);
            $symbol_ok = preg_match('/[\W_]/', $new_password);

            if (!$length_ok || !$upper_ok || !$lower_ok || !$number_ok || !$symbol_ok) {
                $error = "Password must be at least 8 characters include Uppercase, Lowercase, Number & Symbol.";
            } else {
                // Semak sama ada emel wujud di dalam database
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $stmt->store_result();

                if ($stmt->num_rows > 0) {
                    $stmt->close();

                    // Kemaskini dengan password baru yang di-hash
                    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                    $update_stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
                    $update_stmt->bind_param("ss", $hashed_password, $email);

                    if ($update_stmt->execute()) {
                        $success = "Password successfully reset! You can now <a href='login.php'>Login</a>.";
                    } else {
                        $error = "Something went wrong. Please try again.";
                    }
                    $update_stmt->close();
                } else {
                    $error = "Email address not found in our system!";
                }
            }
        }
    } else {
        $error = "Please fill in all fields.";
    }
}
$conn->close();
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
    <h2>Reset Password</h2>
    
    <?php if (!empty($error)): ?>
        <div class="error"><?php echo $error; ?></div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="success"><?php echo $success; ?></div>
    <?php endif; ?>

    <form action="forgot_password.php" method="POST">
        <div class="form-group">
            <label for="email">Your Registered Email</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="new_password">New Password</label>
            <div class="password-wrapper">
                <input type="password" id="new_password" name="new_password" required>
                <span class="toggle-password" onclick="togglePassword('new_password', this)">👁️</span>
            </div>
            <div class="password-hint">Min 8 chars (A-Z, a-z, 0-9, symbol)</div>
        </div>
        <div class="form-group">
            <label for="confirm_password">Confirm New Password</label>
            <div class="password-wrapper">
                <input type="password" id="confirm_password" name="confirm_password" required>
                <span class="toggle-password" onclick="togglePassword('confirm_password', this)">👁️</span>
            </div>
        </div>
        <button type="submit">Reset Password</button>
    </form>
    
    <div class="link">
        Remember your password? <a href="login.php">Login here</a>
    </div>
</div>

<script>
function togglePassword(fieldId, icon) {
    const passwordField = document.getElementById(fieldId);
    if (passwordField.type === "password") {
        passwordField.type = "text";
        icon.textContent = "🙈";
    } else {
        passwordField.type = "password";
        icon.textContent = "👁️";
    }
}
</script>

</body>
</html>