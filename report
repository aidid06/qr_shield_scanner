<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
require_once 'session_boot.php';

if (empty($_SESSION['user_id'])) { header('Location: index.php'); exit(); }
if (($_SESSION['role'] ?? '') === 'guest') {
    http_response_code(403);
    exit('Reports are for registered users only. Please register or log in.');
}

$uid = (int)$_SESSION['user_id'];
$st = $conn->prepare('SELECT role, username FROM users WHERE id = ?');
$st->bindValue(1, $uid, SQLITE3_INTEGER);
$me = $st->execute()->fetchArray(SQLITE3_ASSOC);
if (!$me) { header('Location: index.php'); exit(); }
$isAdmin = $me['role'] === 'admin';

// Month (Malaysia time). ?month=2026-10  -> defaults to the current month.
$tz  = new DateTimeZone('Asia/Kuala_Lumpur');
$utc = new DateTimeZone('UTC');
$month = $_GET['month'] ?? '';
if (!preg_match('/^\d{4}-(0[1-9]|1[0-2])$/', $month)) { $month = (new DateTime('now', $tz))->format('Y-m'); }
$start = new DateTime($month . '-01 00:00:00', $tz);
$end   = (clone $start)->modify('+1 month');
$from  = (clone $start)->setTimezone($utc)->format('Y-m-d H:i:s');   // database stores UTC
$to    = (clone $end)->setTimezone($utc)->format('Y-m-d H:i:s');

$sql = 'SELECT h.id, h.scanned_url, h.scan_status, h.malicious_count, h.total_engines, h.scanned_at, u.username
        FROM scan_history h JOIN users u ON u.id = h.user_id
        WHERE h.scanned_at >= ? AND h.scanned_at < ?';
if (!$isAdmin) { $sql .= ' AND h.user_id = ?'; }      // normal users: their own scans only
$sql .= ' ORDER BY h.scanned_at ASC LIMIT 1000';
$st = $conn->prepare($sql);
$st->bindValue(1, $from, SQLITE3_TEXT);
$st->bindValue(2, $to, SQLITE3_TEXT);
if (!$isAdmin) { $st->bindValue(3, $uid, SQLITE3_INTEGER); }
$res = $st->execute();
$rows = [];
$count = ['Safe' => 0, 'Suspicious' => 0, 'Malicious' => 0];
while ($r = $res->fetchArray(SQLITE3_ASSOC)) {
    $rows[] = $r;
    if (isset($count[$r['scan_status']])) { $count[$r['scan_status']]++; }
}

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function my_time($utcStr) {
    try { return (new DateTime($utcStr, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('Asia/Kuala_Lumpur'))->format('d/m/Y H:i'); }
    catch (Exception $ex) { return $utcStr; }
}
$generated = (new DateTime('now', $tz))->format('d/m/Y H:i');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Monthly Scan Report - <?php echo e($start->format('F Y')); ?></title>
<style>
body { font-family: Arial, Helvetica, sans-serif; font-size: 13px; color: #111; margin: 0; background: #f1f5f9; }
.bar { background: #1e293b; color: #fff; padding: 12px 20px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
.bar a { color: #cbd5e1; text-decoration: none; }
.bar form { display: flex; gap: 8px; align-items: center; margin: 0; }
.bar input, .bar button { padding: 7px 10px; font-size: 14px; border-radius: 6px; border: 0; }
.bar button { background: #3b82f6; color: #fff; cursor: pointer; }
.page { background: #fff; max-width: 780px; margin: 20px auto; padding: 30px 36px; box-shadow: 0 1px 6px rgba(0,0,0,.15); }
h1 { font-size: 20px; margin: 0 0 2px; }
.sub { color: #475569; margin-bottom: 14px; }
.meta { display: flex; justify-content: space-between; flex-wrap: wrap; border-top: 2px solid #111; border-bottom: 1px solid #94a3b8; padding: 8px 0; margin-bottom: 14px; }
.summary { display: flex; gap: 10px; margin-bottom: 16px; }
.box { flex: 1; border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px; text-align: center; }
.box b { display: block; font-size: 20px; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #e2e8f0; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
.url { word-break: break-all; }
.st-Malicious { color: #b91c1c; font-weight: bold; }
.st-Suspicious { color: #b45309; font-weight: bold; }
.st-Safe { color: #047857; font-weight: bold; }
.empty { text-align: center; padding: 30px; color: #64748b; }
.foot { margin-top: 18px; font-size: 11px; color: #475569; border-top: 1px solid #94a3b8; padding-top: 8px; }
@page { size: A4; margin: 14mm; }
@media print {
  body { background: #fff; }
  .bar { display: none; }
  .page { box-shadow: none; margin: 0; padding: 0; max-width: none; }
}
</style>
</head>
<body>
<div class="bar">
  <a href="<?php echo $isAdmin ? 'admin.php' : 'history.php'; ?>">&larr; Back</a>
  <form method="GET">
    <label for="month">Month:</label>
    <input type="month" id="month" name="month" value="<?php echo e($month); ?>" max="<?php echo e((new DateTime('now', $tz))->format('Y-m')); ?>">
    <button type="submit">View</button>
  </form>
  <button onclick="window.print()" style="background:#10b981;border:0;color:#fff;padding:7px 14px;border-radius:6px;cursor:pointer;font-size:14px;">Print report</button>
</div>

<div class="page">
  <h1>QR Shield Scanner</h1>
  <div class="sub">Monthly Scan Report &ndash; <?php echo e($start->format('F Y')); ?></div>

  <div class="meta">
    <div><?php echo $isAdmin ? 'Scope: <b>All users</b> (Administrator)' : 'User: <b>' . e($me['username']) . '</b>'; ?></div>
    <div>Generated: <?php echo e($generated); ?></div>
  </div>

  <div class="summary">
    <div class="box"><b><?php echo count($rows); ?></b>Total scans</div>
    <div class="box"><b style="color:#047857"><?php echo $count['Safe']; ?></b>Safe</div>
    <div class="box"><b style="color:#b45309"><?php echo $count['Suspicious']; ?></b>Suspicious</div>
    <div class="box"><b style="color:#b91c1c"><?php echo $count['Malicious']; ?></b>Malicious</div>
  </div>

  <?php if ($rows): ?>
  <table>
    <thead>
      <tr>
        <th style="width:28px">No.</th>
        <th style="width:105px">Date &amp; time</th>
        <?php if ($isAdmin): ?><th style="width:80px">User</th><?php endif; ?>
        <th>Scanned data (QR content)</th>
        <th style="width:70px">Result</th>
        <th style="width:55px">Flagged</th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($rows as $i => $r): ?>
      <tr>
        <td><?php echo $i + 1; ?></td>
        <td><?php echo e(my_time($r['scanned_at'])); ?></td>
        <?php if ($isAdmin): ?><td><?php echo e($r['username']); ?></td><?php endif; ?>
        <td class="url"><?php echo e($r['scanned_url']); ?></td>
        <td class="st-<?php echo e($r['scan_status']); ?>"><?php echo e($r['scan_status']); ?></td>
        <td><?php echo (int)$r['malicious_count']; ?>/<?php echo (int)$r['total_engines']; ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php else: ?>
    <div class="empty">No scans were recorded in <?php echo e($start->format('F Y')); ?>.</div>
  <?php endif; ?>

  <div class="foot">
    "Flagged" shows how many security engines marked the link as malicious out of all engines that checked it.
    Results are a guide only and are not a guarantee of safety. Times are shown in Malaysia time (UTC+8).
  </div>
</div>
</body>
</html>