<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'db.php';

$error = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    if (!empty($email) && !empty($password)) {
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $row = $result->fetch_assoc();
            
            if (password_verify($password, $row['password'])) {
                $_SESSION['user_id'] = $row['id'];
                $_SESSION['username'] = $row['username'];

                header("Location: dashboard.php");
                exit();
            } else {
                $error = "Invalid email or password!";
            }
        } else {
            $error = "Invalid email or password!";
        }
        $stmt->close();
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
    <title>Login - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: var(--bg-main); }
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
    </style>
</head>
<body>

<div class="login-container">

    <!-- App Logo -->
    <div class="login-logo">
        <img src="image/QR SHIELD TEXT.png" alt="QR Shield Logo">
    </div>

<div class="login-container">
    <h2>User Login</h2>
    
    <?php if (!empty($error)): ?>
        <div class="error"><?php echo $error; ?></div>
    <?php endif; ?>

    <form action="login.php" method="POST">
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
        </div>
        
        <div class="links-row" style="margin-bottom: 20px; justify-content: flex-end;">
            <a href="forgot_password.php" style="font-size: 13px; color: var(--text-muted);">Forgot Password?</a>
        </div>

        <button type="submit">Login</button>
    </form>
    
    <div class="register-link">
        Don't have an account? <a href="register.php">Register here</a>
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