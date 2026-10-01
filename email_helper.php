<?php
/**
 * Sends an email using the Resend API (https://resend.com).
 * Requires RESEND_API_KEY to be set as an environment variable on the server.
 *
 * Returns true on success (Resend accepted the request), false otherwise.
 */
function send_email_via_resend($to_email, $subject, $body_text) {
    $api_key = getenv('RESEND_API_KEY');
    if (!$api_key) {
        error_log("RESEND_API_KEY is not set - cannot send email.");
        return false;
    }

    // Use your verified domain here. Update if you registered a different sending address.
    $from_address = "QR Shield Scanner <no-reply@qrshieldscanner.my>";

    $payload = json_encode([
        "from"    => $from_address,
        "to"      => [$to_email],
        "subject" => $subject,
        "text"    => $body_text
    ]);

    $ch = curl_init("https://api.resend.com/emails");
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
    curl_setopt($ch, CURLOPT_TIMEOUT, 12);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer " . $api_key,
        "Content-Type: application/json"
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    // No curl_close() here - deprecated as of PHP 8.5, and unnecessary since
    // the handle is freed automatically once $ch goes out of scope.

    if ($curl_error) {
        error_log("Resend cURL error: " . $curl_error);
        return false;
    }

    if ($http_code >= 200 && $http_code < 300) {
        return true;
    }

    error_log("Resend API error (HTTP $http_code): " . $response);
    return false;
}

/**
 * Builds and sends a verification email for the given username/email/token.
 * Returns true if Resend accepted the email, false otherwise.
 */
function send_verification_email($username, $email, $verify_token, $host) {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $verify_link = "$scheme://$host/verify.php?token=" . $verify_token;

    $subject = "Verify your QR Shield Scanner account";
    $body = "Hi $username,\n\nPlease verify your email by clicking the link below:\n$verify_link\n\nIf you didn't sign up, you can ignore this email.";

    return send_email_via_resend($email, $subject, $body);
}

/**
 * Builds and sends a password reset email for the given username/email/token.
 * Returns true if Resend accepted the email, false otherwise.
 */
function send_reset_email($username, $email, $reset_token, $host) {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $reset_link = "$scheme://$host/reset_password.php?token=" . $reset_token;

    $subject = "Reset your QR Shield Scanner password";
    $body = "Hi $username,\n\nWe received a request to reset your password. Click the link below to choose a new one. This link expires in 1 hour.\n$reset_link\n\nIf you didn't request this, you can safely ignore this email - your password won't be changed.";

    return send_email_via_resend($email, $subject, $body);
}