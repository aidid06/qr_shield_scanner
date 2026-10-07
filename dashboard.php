<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

require_once 'session_boot.php';

// Redirect to login if not logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

require_once 'db.php';

$uid = $_SESSION['user_id'];
$is_admin = false;
$stats = ['total' => 0, 'safe' => 0, 'flagged' => 0];
$recent_scans = [];

// Admin check (to show the Admin Panel link)
$chk_admin = $conn->prepare("SELECT role FROM users WHERE id = ?");
if ($chk_admin) {
    $chk_admin->bindValue(1, $uid, SQLITE3_INTEGER);
    $res_admin = $chk_admin->execute();
    $user_data = $res_admin ? $res_admin->fetchArray(SQLITE3_ASSOC) : null;
    $is_admin = ($user_data && $user_data['role'] === 'admin');
    $chk_admin->close();
}

// This user's scan totals
$stat_stmt = $conn->prepare(
    "SELECT COUNT(*) AS total,
            SUM(CASE WHEN scan_status = 'Safe' THEN 1 ELSE 0 END) AS safe,
            SUM(CASE WHEN scan_status IN ('Suspicious', 'Malicious') THEN 1 ELSE 0 END) AS flagged
     FROM scan_history WHERE user_id = ?"
);
if ($stat_stmt) {
    $stat_stmt->bindValue(1, $uid, SQLITE3_INTEGER);
    $stat_res = $stat_stmt->execute();
    $stat_row = $stat_res ? $stat_res->fetchArray(SQLITE3_ASSOC) : null;
    if ($stat_row) {
        $stats['total']   = (int)$stat_row['total'];
        $stats['safe']    = (int)$stat_row['safe'];
        $stats['flagged'] = (int)$stat_row['flagged'];
    }
    $stat_stmt->close();
}

// Latest 5 scans
$recent_stmt = $conn->prepare("SELECT scanned_url, scan_status, scanned_at FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC LIMIT 5");
if ($recent_stmt) {
    $recent_stmt->bindValue(1, $uid, SQLITE3_INTEGER);
    $recent_res = $recent_stmt->execute();
    while ($recent_res && ($row = $recent_res->fetchArray(SQLITE3_ASSOC))) {
        $recent_scans[] = $row;
    }
    $recent_stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { background-color: var(--bg-main); margin: 0; padding: 0; }
        header { background-color: var(--sidebar-bg); color: white; padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 1.1rem; font-weight: 700; margin: 0; }
        .nav-links { display: flex; align-items: center; gap: 6px; }
        .nav-links a { color: var(--sidebar-text); text-decoration: none; font-size: 0.85rem; font-weight: 500; padding: 6px 10px; border-radius: 6px; }
        .nav-links a:hover { color: var(--sidebar-hover); background: rgba(255, 255, 255, 0.08); }
        .nav-links a.admin-link { color: #fbbf24; font-weight: 700; }
        .nav-links a.logout-link { color: #f87171; }

        .page { max-width: 640px; margin: 0 auto; padding: 22px 18px; }
        .greeting { margin: 0 0 4px 0; color: var(--text-main); font-size: 1.4rem; }
        .subtitle { margin: 0 0 20px 0; color: var(--text-muted); font-size: 0.92rem; }

        .hero { background: var(--primary); color: white; border-radius: 16px; padding: 22px; display: flex; align-items: center; justify-content: space-between; gap: 16px; box-shadow: var(--shadow); }
        .hero h2 { margin: 0 0 4px 0; font-size: 1.15rem; color: white; }
        .hero p { margin: 0; font-size: 0.85rem; color: rgba(255,255,255,0.85); }
        .hero a { background: white; color: var(--primary); text-decoration: none; font-weight: 700; font-size: 0.9rem; padding: 11px 18px; border-radius: 10px; white-space: nowrap; }

        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 18px 0; }
        .stat { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 14px 8px; text-align: center; }
        .stat .num { font-size: 1.5rem; font-weight: 700; color: var(--text-main); }
        .stat .label { font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; margin-top: 2px; }
        .stat.safe .num { color: #10b981; }
        .stat.flagged .num { color: #ef4444; }

        .section-head { display: flex; justify-content: space-between; align-items: center; margin: 22px 0 10px 0; }
        .section-head h3 { margin: 0; font-size: 1rem; color: var(--text-main); }
        .section-head a { font-size: 0.85rem; color: var(--primary); text-decoration: none; font-weight: 600; }

        .scan-list { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; overflow: hidden; }
        .scan-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 13px 16px; border-bottom: 1px solid var(--border-color); }
        .scan-item:last-child { border-bottom: none; }
        .scan-info { min-width: 0; }
        .scan-url { font-size: 0.9rem; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .scan-date { font-size: 0.75rem; color: var(--text-muted); margin-top: 2px; }
        .badge { padding: 4px 10px; font-weight: 700; border-radius: 6px; color: white; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; white-space: nowrap; }
        .Safe { background-color: #10b981; }
        .Suspicious { background-color: #f59e0b; }
        .Malicious { background-color: #ef4444; }
        .empty { padding: 28px 16px; text-align: center; color: var(--text-muted); font-size: 0.9rem; }
    </style>
</head>
<body>

<header>
    <h1>QR Shield Scanner</h1>
    <div class="nav-links">
        <?php if ($is_admin): ?>
            <a href="admin.php" class="admin-link">Admin Panel</a>
        <?php endif; ?>
        <a href="logout.php" class="logout-link">Logout</a>
    </div>
</header>

<div class="page">
    <h2 class="greeting">Hi, <?php echo htmlspecialchars($_SESSION['username'] ?? 'User'); ?> 👋</h2>
    <p class="subtitle">Check any QR code before you open it.</p>

    <div class="hero">
        <div>
            <h2>Ready to scan?</h2>
            <p>Use your camera or upload an image.</p>
        </div>
        <a href="scanner.php">Scan QR</a>
    </div>

    <div class="stats">
        <div class="stat">
            <div class="num"><?php echo $stats['total']; ?></div>
            <div class="label">Total scans</div>
        </div>
        <div class="stat safe">
            <div class="num"><?php echo $stats['safe']; ?></div>
            <div class="label">Safe</div>
        </div>
        <div class="stat flagged">
            <div class="num"><?php echo $stats['flagged']; ?></div>
            <div class="label">Flagged</div>
        </div>
    </div>

    <div class="section-head">
        <h3>Recent scans</h3>
        <a href="history.php">View all</a>
    </div>

    <div class="scan-list">
        <?php if (empty($recent_scans)): ?>
            <div class="empty">No scans yet. Tap the Scan button to check your first QR code.</div>
        <?php else: ?>
            <?php foreach ($recent_scans as $scan): ?>
                <div class="scan-item">
                    <div class="scan-info">
                        <div class="scan-url"><?php echo htmlspecialchars($scan['scanned_url']); ?></div>
                        <div class="scan-date"><?php echo htmlspecialchars(date('d M Y', strtotime($scan['scanned_at']))); ?></div>
                    </div>
                    <span class="badge <?php echo htmlspecialchars($scan['scan_status']); ?>"><?php echo htmlspecialchars($scan['scan_status']); ?></span>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>

<?php include 'bottom_nav.php'; ?>

</body>
</html>
<?php if (isset($conn)) { $conn->close(); } ?>