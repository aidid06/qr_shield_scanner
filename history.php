<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'db.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];

// Fetch scan history for the logged-in user using SQLite syntax
$stmt = $conn->prepare("SELECT scanned_url, scan_status, scanned_at FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC");
$has_rows = false;
$rows = [];

if ($stmt) {
    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    if ($result) {
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
    }
    $stmt->close();
}
$has_rows = count($rows) > 0;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan History - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { background-color: var(--bg-main); margin: 0; padding: 0; }
        header { background-color: var(--sidebar-bg); color: white; padding: 18px 35px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 1.25rem; font-weight: 700; margin: 0; }
        .nav-links { display: flex; align-items: center; gap: 20px; }
        .nav-links a { color: var(--sidebar-text); text-decoration: none; font-size: 0.9rem; font-weight: 500; padding: 6px 12px; border-radius: 6px; }
        .nav-links a:hover { color: var(--sidebar-hover); background: rgba(255, 255, 255, 0.05); }
        .container { max-width: 950px; margin: 40px auto; padding: 40px; background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border-color); }
        h2 { color: var(--text-main); margin-top: 0; }
        p { color: var(--text-muted); }
        table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 20px; border-radius: 8px; overflow: hidden; border: 1px solid var(--border-color); }
        th, td { padding: 14px 18px; text-align: left; font-size: 0.9rem; border-bottom: 1px solid var(--border-color); }
        th { background-color: #f1f5f9; color: var(--text-main); font-weight: 600; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background-color: #f8fafc; }
        .badge { padding: 6px 12px; font-weight: 700; border-radius: 6px; color: white; font-size: 0.75rem; display: inline-block; text-transform: uppercase; letter-spacing: 0.05em; }
        .Safe { background-color: #10b981; }
        .Suspicious { background-color: #f59e0b; color: #fff; }
        .Malicious { background-color: #ef4444; }
        .url-cell { max-width: 350px; word-break: break-all; color: var(--primary); }
        .no-data { text-align: center; color: var(--text-muted); padding: 30px; }
    </style>
</head>
<body>

<header>
    <h1>QR Shield Scanner</h1>
    <div class="nav-links">
        <a href="dashboard.php">Dashboard</a>
        <a href="scanner.php">Scan QR</a>
        <a href="logout.php" style="color: #ef4444;">Logout</a>
    </div>
</header>

<div class="container">
    <h2>Your Scan History</h2>
    <p>Review all previous QR codes and links analyzed through VirusTotal.</p>

    <?php if ($has_rows): ?>
        <table>
            <thead>
                <tr>
                    <th>Date & Time</th>
                    <th>Scanned URL / Content</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($rows as $row): ?>
                    <tr>
                        <td><?php echo $row['scanned_at']; ?></td>
                        <td class="url-cell"><?php echo htmlspecialchars($row['scanned_url']); ?></td>
                        <td>
                            <span class="badge <?php echo $row['scan_status']; ?>">
                                <?php echo $row['scan_status']; ?>
                            </span>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p class="no-data">You haven't scanned any QR codes yet. <a href="scanner.php" style="color: var(--primary); text-decoration: none; font-weight: 600;">Start scanning now!</a></p>
    <?php endif; ?>

</div>

</body>
</html>

<?php
if (isset($conn)) {
    $conn->close();
}
?>