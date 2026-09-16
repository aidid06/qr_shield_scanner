<?php
require_once 'db.php';

$message = "";
$is_success = false;

$token = isset($_GET['token']) ? trim($_GET['token']) : "";

if (empty($token)) {
    $message = "Invalid verification link.";
} else {
    $stmt = $conn->prepare("SELECT id, verified FROM users WHERE verify_token = ?");
    $stmt->bindValue(1, $token, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;
    $stmt->close();

    if (!$user) {
        $message = "This verification link is invalid or has already been used.";
    } elseif ($user['verified']) {
        $message = "Your email is already verified. You can log in.";
        $is_success = true;
    } else {
        $update = $conn->prepare("UPDATE users SET verified = 1, verify_token = NULL WHERE id = ?");
        $update->bindValue(1, $user['id'], SQLITE3_INTEGER);
        if ($update->execute()) {
            $message = "Your email has been verified! You can now log in.";
            $is_success = true;
        } else {
            $message = "Something went wrong verifying your account. Please try again.";
        }
        $update->close();
    }
}
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Verify Email - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
</head>
<body style="display:flex;justify-content:center;align-items:center;height:100vh;">
    <div style="text-align:center;">
        <h2><?php echo $is_success ? "Success" : "Verification"; ?></h2>
        <p><?php echo htmlspecialchars($message); ?></p>
        <a href="index.php">Go to Login</a>
    </div>
</body>
</html>