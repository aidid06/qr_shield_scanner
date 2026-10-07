<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
require_once 'session_boot.php';

$viewOnly = isset($_GET['view']);
$loggedIn = !empty($_SESSION['user_id']) && ($_SESSION['role'] ?? '') !== 'guest';
if (!$viewOnly && !$loggedIn) { header('Location: index.php'); exit(); }

if (!$viewOnly && $_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['accept'])) {
    $st = $conn->prepare("UPDATE users SET terms_version = ?, terms_at = datetime('now') WHERE id = ?");
    $st->bindValue(1, TERMS_VERSION, SQLITE3_TEXT);
    $st->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
    $st->execute();
    $_SESSION['terms_ok'] = TERMS_VERSION;
    header('Location: dashboard.php'); exit();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terms &amp; Conditions - QR Shield Scanner</title>
<link rel="stylesheet" href="style.css">
<style>
body { background-color: var(--bg-main); margin: 0; padding: 20px; }
.box { max-width: 700px; margin: 30px auto; background: var(--card-bg); padding: 30px; border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border-color); }
.terms-text { max-height: 50vh; overflow-y: auto; border: 1px solid var(--border-color); border-radius: 8px; padding: 14px 18px; font-size: 0.9rem; color: var(--text-main); }
.actions { margin-top: 20px; }
.actions label { display: block; margin-bottom: 14px; font-size: 0.9rem; }
.decline { display: inline-block; margin-top: 12px; font-size: 0.85rem; color: var(--text-muted); }
</style>
</head>
<body>
<div class="box">
  <h2>Terms &amp; Conditions <small style="font-weight:400">(version <?php echo TERMS_VERSION; ?>)</small></h2>
  <div class="terms-text">
    <!-- REPLACE THIS PLACEHOLDER WITH YOUR REAL TERMS (have them reviewed by a legal professional). -->
    <p><strong>1. Service.</strong> QR Shield Scanner checks the links inside QR codes using third-party security engines (VirusTotal). Results are a guide only and are not a guarantee that a link is safe.</p>
    <p><strong>2. Your data.</strong> We store your account details and the links you scan so you can view your history and print receipts. Guest scans are temporary and are deleted automatically.</p>
    <p><strong>3. Acceptable use.</strong> Do not use the service for unlawful activity or to abuse or overload the system.</p>
    <p><strong>4. Liability.</strong> You scan and open links at your own risk. We are not liable for any loss arising from the use of the service.</p>
    <p><strong>5. Changes.</strong> We may update these terms. You will be asked to accept the new version when it changes.</p>
  </div>
  <?php if ($viewOnly): ?>
    <p class="actions"><a href="index.php">Back</a></p>
  <?php else: ?>
  <form method="POST" class="actions">
    <label><input type="checkbox" name="accept" value="1" required> I have read and accept the Terms &amp; Conditions</label>
    <button type="submit">Accept &amp; Continue</button>
  </form>
  <a class="decline" href="logout.php">I do not accept (log out)</a>
  <?php endif; ?>
</div>
</body>
</html>