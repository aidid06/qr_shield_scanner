<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

session_start();
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$history_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

$stmt = $conn->prepare("SELECT scanned_url, scan_status, malicious_count, total_engines FROM scan_history WHERE id = ? AND user_id = ?");
$stmt->bindValue(1, $history_id, SQLITE3_INTEGER);
$stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
$res = $stmt->execute();
$row = $res ? $res->fetchArray(SQLITE3_ASSOC) : null;
$stmt->close();
$conn->close();

if (!$row) {
    header("Location: scanner.php");
    exit();
}

$scan_status = $row['scan_status'];
$malicious_count = (int)$row['malicious_count'];
$total_engines = (int)$row['total_engines'];
$scanned_url = $row['scanned_url'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Result - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { background-color: var(--bg-main); margin: 0; padding: 0; }
        header { background-color: var(--sidebar-bg); color: white; padding: 18px 35px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 1.25rem; font-weight: 700; margin: 0; }
        .nav-links a { color: #f87171; text-decoration: none; font-size: 0.85rem; font-weight: 500; }
        .container { max-width: 650px; margin: 40px auto; padding: 40px; background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border-color); }
        h2 { color: var(--text-main); margin-top: 0; }
        p { color: var(--text-muted); font-size: 0.95rem; }
        .badge { padding: 6px 15px; font-weight: 700; border-radius: 6px; color: white; font-size: 0.85rem; display: inline-block; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 5px; }
        .Safe { background-color: #10b981; }
        .Suspicious { background-color: #f59e0b; color: #fff; }
        .Malicious { background-color: #ef4444; }
        .btn-group { display: flex; gap: 15px; margin-top: 30px; }
        .btn-back { display: inline-block; padding: 12px 20px; background: var(--primary); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 0.95rem; text-align: center; flex: 1; transition: background 0.2s; }
        .btn-back:hover { background: var(--primary-hover); }
        .btn-secondary { background: #64748b; }
        .btn-secondary:hover { background: #475569; }
        .url-box { word-break: break-all; color: var(--primary); font-weight: 500; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-color); margin-top: 5px; margin-bottom: 20px; }
        .engine-line { font-size: 0.88rem; color: var(--text-muted); margin-top: 6px; }

        .auto-open-notice { margin-top: 15px; font-size: 0.85rem; color: var(--text-muted); }
        .open-safe-btn { margin-top: 14px; display: inline-block; padding: 10px 18px; background: #10b981; color: white; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 0.9rem; }
        .open-safe-btn:hover { background: #059669; }

        .confirm-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.6); align-items: center; justify-content: center; z-index: 1000; }
        .confirm-overlay.active { display: flex; }
        .confirm-box { background: var(--card-bg); padding: 30px; border-radius: 12px; max-width: 420px; width: 90%; box-shadow: var(--shadow); text-align: center; }
        .confirm-box h3 { margin-top: 0; color: #ef4444; }
        .confirm-box p { color: var(--text-main); font-size: 0.9rem; }
        .confirm-box .url-box { text-align: left; font-size: 0.85rem; }
        .confirm-btn-group { display: flex; gap: 12px; margin-top: 20px; }
        .confirm-btn-group button, .confirm-btn-group a { flex: 1; padding: 12px; border-radius: 8px; font-weight: 600; font-size: 0.9rem; border: none; cursor: pointer; text-decoration: none; text-align: center; }
        .btn-cancel { background: #e2e8f0; color: var(--text-main); }
        .btn-cancel:hover { background: #cbd5e1; }
        .btn-open-anyway { background: #ef4444; color: white; }
        .btn-open-anyway:hover { background: #dc2626; }

        .second-confirm-box p.warn { color: #ef4444; font-weight: 600; }
    </style>
</head>
<body>

<header>
    <h1>QR Shield Scanner</h1>
    <div class="nav-links">
        <a href="logout.php">Logout</a>
    </div>
</header>

<div class="container">
    <h2>VirusTotal Threat Analysis Report</h2>
    <p><strong>Scanned URL / Content:</strong></p>
    <div class="url-box"><?php echo htmlspecialchars($scanned_url); ?></div>

    <p><strong>Threat Status:</strong><br>
        <span class="badge <?php echo htmlspecialchars($scan_status); ?>"><?php echo htmlspecialchars($scan_status); ?></span>
    </p>

    <?php if ($total_engines > 0): ?>
        <p class="engine-line"><?php echo $malicious_count; ?> of <?php echo $total_engines; ?> security engines flagged this link.</p>
    <?php endif; ?>

    <?php if ($scan_status === "Safe"): ?>
        <p class="auto-open-notice" id="autoOpenNotice">This link looks safe. Opening it automatically in a new tab in <span id="countdown">3</span>...</p>
        <a href="<?php echo htmlspecialchars($scanned_url); ?>" target="_blank" rel="noopener noreferrer" class="open-safe-btn" id="manualOpenBtn">Open link now</a>
    <?php elseif ($scan_status === "Suspicious" || $scan_status === "Malicious"): ?>
        <p class="auto-open-notice" style="color: #ef4444; font-weight: 600;">This link was NOT opened automatically because it may be unsafe.</p>
    <?php endif; ?>

    <div class="btn-group">
        <a href="scanner.php" class="btn-back">Scan Another QR</a>
        <a href="history.php" class="btn-back btn-secondary">View History</a>
    </div>
</div>

<!-- First confirmation, for Suspicious or Malicious -->
<div class="confirm-overlay" id="confirmOverlay">
    <div class="confirm-box">
        <h3>⚠️ Warning: Risky Link Detected</h3>
        <p>Our scan flagged this URL as <strong><?php echo htmlspecialchars($scan_status); ?></strong>
            (<?php echo $malicious_count; ?> out of <?php echo $total_engines; ?> engines flagged it).
            Opening it could expose you to phishing, malware, or other threats.</p>
        <div class="url-box"><?php echo htmlspecialchars($scanned_url); ?></div>
        <p>Are you sure you want to continue?</p>
        <div class="confirm-btn-group">
            <button class="btn-cancel" onclick="document.getElementById('confirmOverlay').classList.remove('active');">Cancel</button>
            <button class="btn-open-anyway" onclick="showSecondConfirm();">Continue</button>
        </div>
    </div>
</div>

<!-- Second confirmation, required specifically for Malicious links -->
<div class="confirm-overlay" id="secondConfirmOverlay">
    <div class="confirm-box second-confirm-box">
        <h3>⚠️ Are you absolutely sure?</h3>
        <p class="warn">This link was flagged as MALICIOUS by <?php echo $malicious_count; ?> security engines. Opening it could compromise your device or steal your data.</p>
        <p>This is your final confirmation. We strongly recommend clicking Cancel.</p>
        <div class="confirm-btn-group">
            <button class="btn-cancel" onclick="document.getElementById('secondConfirmOverlay').classList.remove('active');">Cancel</button>
            <a href="<?php echo htmlspecialchars($scanned_url); ?>" target="_blank" rel="noopener noreferrer" class="btn-open-anyway">Yes, Open Anyway</a>
        </div>
    </div>
</div>

<script>
const scanStatus = <?php echo json_encode($scan_status); ?>;
const scannedUrl = <?php echo json_encode($scanned_url); ?>;

if (scanStatus === "Safe" && scannedUrl) {
    let secondsLeft = 3;
    const countdownEl = document.getElementById('countdown');
    const manualBtn = document.getElementById('manualOpenBtn');
    const timer = setInterval(() => {
        secondsLeft--;
        if (countdownEl) countdownEl.textContent = secondsLeft;
        if (secondsLeft <= 0) {
            clearInterval(timer);
            // Try to auto-open; browsers may block this since it's not a direct
            // click, so the "Open link now" button above is always available too.
            const win = window.open(scannedUrl, '_blank', 'noopener,noreferrer');
            if (win) {
                document.getElementById('autoOpenNotice').textContent = "Opened in a new tab.";
            } else {
                document.getElementById('autoOpenNotice').textContent = "Your browser blocked the automatic open. Use the button below instead.";
            }
        }
    }, 1000);
} else if ((scanStatus === "Suspicious" || scanStatus === "Malicious") && scannedUrl) {
    document.getElementById('confirmOverlay').classList.add('active');
}

function showSecondConfirm() {
    document.getElementById('confirmOverlay').classList.remove('active');
    // Malicious links get a second, harder confirmation. Suspicious links
    // only needed the one step, so send them straight through.
    if (scanStatus === "Malicious") {
        document.getElementById('secondConfirmOverlay').classList.add('active');
    } else {
        window.open(scannedUrl, '_blank', 'noopener,noreferrer');
    }
}
</script>

<?php include 'bottom_nav.php'; ?>

</body>
</html>