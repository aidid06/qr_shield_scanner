<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
require_once 'session_boot.php';

if (empty($_SESSION['user_id'])) { header('Location: index.php'); exit(); }
if (($_SESSION['role'] ?? '') === 'guest') {
    http_response_code(403);
    exit('Receipts are for registered users only. Please register or log in.');
}

$uid = (int)$_SESSION['user_id'];
$st = $conn->prepare('SELECT role FROM users WHERE id = ?');
$st->bindValue(1, $uid, SQLITE3_INTEGER);
$me = $st->execute()->fetchArray(SQLITE3_ASSOC);
$isAdmin = $me && $me['role'] === 'admin';

// ?ids=5  or  ?ids=5,6,7
$ids = array_values(array_unique(array_filter(array_map('intval', explode(',', $_GET['ids'] ?? '')))));
$ids = array_slice($ids, 0, 100);
if (!$ids) { http_response_code(400); exit('No receipt selected.'); }

$marks = implode(',', array_fill(0, count($ids), '?'));
$sql = "SELECT h.*, u.username FROM scan_history h JOIN users u ON u.id = h.user_id WHERE h.id IN ($marks)";
if (!$isAdmin) { $sql .= ' AND h.user_id = ?'; }      // normal users: their own scans only
$sql .= ' ORDER BY h.scanned_at ASC';
$st = $conn->prepare($sql);
foreach ($ids as $i => $id) { $st->bindValue($i + 1, $id, SQLITE3_INTEGER); }
if (!$isAdmin) { $st->bindValue(count($ids) + 1, $uid, SQLITE3_INTEGER); }
$res = $st->execute();
$rows = [];
while ($r = $res->fetchArray(SQLITE3_ASSOC)) { $rows[] = $r; }
if (!$rows) { http_response_code(404); exit('Receipt not found.'); }

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function my_time($utc) {   // database stores UTC; show Malaysia time
    try { return (new DateTime($utc, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Asia/Kuala_Lumpur'))->format('d/m/Y H:i:s'); }
    catch (Exception $ex) { return $utc; }
}
$title = count($rows) === 1 ? sprintf('QRS-%06d', $rows[0]['id']) : 'Scan summary (' . count($rows) . ')';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Receipt <?php echo e($title); ?></title>
<style>
body { font-family: "Courier New", monospace; font-size: 12px; color: #000; width: 80mm; max-width: 100%; margin: 10px auto; }
h1 { font-size: 15px; text-align: center; margin: 0; }
.c { text-align: center; }
hr { border: 0; border-top: 1px dashed #000; margin: 8px 0; }
.item { margin: 8px 0; }
.url { word-break: break-all; }
.status { font-weight: bold; text-transform: uppercase; }
button { width: 100%; padding: 10px; margin-top: 12px; font-size: 14px; cursor: pointer; }
@media print { .no-print { display: none; } body { margin: 0; } }
</style>
</head>
<body>
<h1>QR SHIELD SCANNER</h1>
<div class="c">Scan Receipt</div>
<hr>
<div>Receipt : <?php echo e($title); ?></div>
<div>Printed : <?php echo e(my_time(gmdate('Y-m-d H:i:s'))); ?></div>
<?php if (!$isAdmin): ?><div>User    : <?php echo e($rows[0]['username']); ?></div><?php endif; ?>
<hr>
<?php foreach ($rows as $n => $r): ?>
<div class="item">
  <div>#<?php echo (int)$r['id']; ?> &nbsp; <?php echo e(my_time($r['scanned_at'])); ?></div>
  <?php if ($isAdmin): ?><div>User: <?php echo e($r['username']); ?></div><?php endif; ?>
  <div>Scanned data:</div>
  <div class="url"><?php echo e($r['scanned_url']); ?></div>
  <div>Result: <span class="status"><?php echo e($r['scan_status']); ?></span></div>
  <div>Engines flagged: <?php echo (int)$r['malicious_count']; ?> / <?php echo (int)$r['total_engines']; ?></div>
</div>
<?php if ($n < count($rows) - 1): ?><hr><?php endif; ?>
<?php endforeach; ?>
<hr>
<div>Total scans: <?php echo count($rows); ?></div>
<div class="c" style="margin-top:8px;">Results are a guide only.<br>Thank you for using QR Shield.</div>
<button class="no-print" onclick="window.print()">Print</button>
</body>
</html>