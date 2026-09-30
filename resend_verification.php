<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

require_once 'db.php';
require_once 'email_helper.php';

$message = "";
$is_success = false;

$email = isset($_GET['email']) ? trim($_GET['email']) : "";

if (empty($email)) {
    $message = "No email address provided.";
} else {
    $stmt = $conn->prepare("SELECT id, username, verified FROM users WHERE email = ?");
    $stmt->bindValue(1, $email, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result ? $result->fetchArray(SQLITE3_ASSOC) : null;
    $stmt->close();

    if (!$user) {
        $message = "No account found with that email address.";
    } elseif ($user['verified']) {
        $message = "This account is already verified. You can log in.";
        $is_success = true;
    } else {
        // Generate a fresh token and update the record
        $new_token = bin2hex(random_bytes(32));

        $update = $conn->prepare("UPDATE users SET verify_token = ? WHERE id = ?");
        $update->bindValue(1, $new_token, SQLITE3_TEXT);
        $update->bindValue(2, $user['id'], SQLITE3_INTEGER);

        if ($update->execute()) {
            $host = $_SERVER['HTTP_HOST'];
            $sent = send_verification_email($user['username'], $email, $new_token, $host);

            if ($sent) {
                $message = "A new verification email has been sent to " . htmlspecialchars($email) . ". Please check your inbox.";
                $is_success = true;
            } else {
                $message = "We couldn't send the verification email right now. Please try again later.";
            }
        } else {
            $message = "Something went wrong. Please try again.";
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
    <title>Resend Verification - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
</head>
<body style="display:flex;justify-content:center;align-items:center;height:100vh;">
    <div style="text-align:center; max-width: 450px; padding: 20px;">
        <h2><?php echo $is_success ? "Check Your Email" : "Resend Verification"; ?></h2>
        <p><?php echo htmlspecialchars($message); ?></p>
        <a href="index.php">Go to Login</a>
    </div>
</body>
</html>