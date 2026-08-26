<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'db.php';

$error = "";
$success = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if (!empty($username) && !empty($email) && !empty($password) && !empty($confirm_password)) {
        if ($password !== $confirm_password) {
            $error = "Passwords do not match!";
        } else {
            // Semakan kriteria password: Min 8 aksara, Huruf Besar, Huruf Kecil, Nombor, Simbol
            $length_ok = strlen($password) >= 8;
            $upper_ok  = preg_match('/[A-Z]/', $password);
            $lower_ok  = preg_match('/[a-z]/', $password);
            $number_ok = preg_match('/[0-9]/', $password);
            $symbol_ok = preg_match('/[\W_]/', $password); // Simbol khas

            if (!$length_ok || !$upper_ok || !$lower_ok || !$number_ok || !$symbol_ok) {
                $error = "User must enter at least 8 characters include Uppercase, Lowercase, Number & Symbol.";
            } else {
                // Check if email already exists using SQLite syntax
                $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
                if ($stmt) {
                    $stmt->bindValue(1, $email, SQLITE3_TEXT);
                    $result = $stmt->execute();
                    $existing_user = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;

                    if ($existing_user) {
                        $error = "Email is already registered!";
                        $stmt->close();
                    } else {
                        $stmt->close();

                        // Hash password securely
                        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                        // Insert new user into database using SQLite syntax
                        $insert_stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
                        if ($insert_stmt) {
                            $insert_stmt->bindValue(1, $username, SQLITE3_TEXT);
                            $insert_stmt->bindValue(2, $email, SQLITE3_TEXT);
                            $insert_stmt->bindValue(3, $hashed_password, SQLITE3_TEXT);

                            if ($insert_stmt->execute()) {
                                $success = "Registration successful! You can now <a href='index.php'>Login</a>.";
                            } else {
                                $error = "Something went wrong. Please try again.";
                            }
                            $insert_stmt->close();
                        }
                    }
                }
            }
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
    <title>Register - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: var(--bg-main); }
        .register-container { background: var(--card-bg); padding: 35px; border-radius: var(--radius); box-shadow: var(--shadow); width: 100%; max-width: 420px; border: 1px solid var(--border-color); }
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

<div class="register-container">
    <!-- App Logo -->
    <div class="login-logo">
        <div style="text-align: center; margin-bottom: 25px;">
        <img src="image/QR SHIELD TEXT.png" alt="QR Shield Logo" style="height: 200px; margin-bottom: 8px;">
    </div>
</div>

    <h2>Create Account</h2>
    
    <?php if (!empty($error)): ?>
        <div class="error"><?php echo $error; ?></div>
    <?php endif; ?>

    <?php if (!empty($success)): ?>
        <div class="success"><?php echo $success; ?></div>
    <?php endif; ?>

    <form action="register.php" method="POST">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="email">Email Address</label>
            <input type="email" id="email" name="email" required>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <div class="password-wrapper">
                <input type="password" id="password" name="password" required>
                <span class="toggle-password" onclick="togglePassword('password', this)">👁️</span>
            </div>
            <div class="password-hint">Min 8 chars (A-Z, a-z, 0-9, symbol)</div>
        </div>
        <div class="form-group">
            <label for="confirm_password">Confirm Password</label>
            <div class="password-wrapper">
                <input type="password" id="confirm_password" name="confirm_password" required>
                <span class="toggle-password" onclick="togglePassword('confirm_password', this)">👁️</span>
            </div>
        </div>
        <button type="submit">Register</button>
    </form>
    
    <div class="link">
        Already have an account? <a href="index.php">Login here</a>
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