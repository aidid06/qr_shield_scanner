<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

session_start();
require_once 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$scanned_url = "";
$analysis_id = "";
$is_polling_view = false;

// Check if an AJAX request is asking for status
if (isset($_GET['check_status']) && isset($_SESSION['analysis_id'])) {
    header('Content-Type: application/json');
    $analysis_id = $_SESSION['analysis_id'];
    $api_key = getenv('VT_API_KEY');

    $report_url = 'https://www.virustotal.com/api/v3/analyses/' . $analysis_id;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $report_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'accept: application/json',
        'x-apikey: ' . $api_key
    ]);

    $report_response = curl_exec($ch);
    $report_http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($report_http_code == 200) {
        $report_data = json_decode($report_response, true);
        $status = $report_data['data']['attributes']['status'] ?? "";

        if ($status === "completed") {
            $stats = $report_data['data']['attributes']['stats'] ?? [];
            $malicious_count = $stats['malicious'] ?? 0;
            $suspicious_count = $stats['suspicious'] ?? 0;
            $harmless_count = $stats['harmless'] ?? 0;
            $undetected_count = $stats['undetected'] ?? 0;
            $total_engines = $malicious_count + $suspicious_count + $harmless_count + $undetected_count;

            if ($malicious_count > 0) {
                $scan_status = "Malicious";
            } elseif ($suspicious_count > 0) {
                $scan_status = "Suspicious";
            } else {
                $scan_status = "Safe";
            }

            // Save History to Database once completed
            $hist_stmt = $conn->prepare("INSERT INTO scan_history (user_id, scanned_url, scan_status, malicious_count, total_engines) VALUES (?, ?, ?, ?, ?)");
            if ($hist_stmt) {
                $hist_stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
                $hist_stmt->bindValue(2, $_SESSION['scanned_url'], SQLITE3_TEXT);
                $hist_stmt->bindValue(3, $scan_status, SQLITE3_TEXT);
                $hist_stmt->bindValue(4, $malicious_count, SQLITE3_INTEGER);
                $hist_stmt->bindValue(5, $total_engines, SQLITE3_INTEGER);
                $hist_stmt->execute();
            }

            echo json_encode([
                'status' => 'completed',
                'scan_status' => $scan_status,
                'malicious_count' => $malicious_count,
                'total_engines' => $total_engines,
                'scanned_url' => $_SESSION['scanned_url']
            ]);
            exit;
        }
    }

    echo json_encode(['status' => 'queued_or_running']);
    exit;
}

// Initial POST request with a new URL
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['url'])) {
    $scanned_url = trim($_POST['url']);
    $_SESSION['scanned_url'] = $scanned_url;

    $vt_url = 'https://www.virustotal.com/api/v3/urls';
    $api_key = getenv('VT_API_KEY');

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $vt_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['url' => $scanned_url]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'accept: application/json',
        'x-apikey: ' . $api_key,
        'content-type: application/x-www-form-urlencoded'
    ]);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code == 200) {
        $data = json_decode($response, true);
        $_SESSION['analysis_id'] = $data['data']['id'] ?? null;
        $is_polling_view = true;
    } else {
        $error_message = "API Connection Error (Check API Key)";
    }
}
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analyzing - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { background-color: var(--bg-main); margin: 0; padding: 0; font-family: sans-serif; }
        header { background-color: var(--sidebar-bg); color: white; padding: 18px 35px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 1.25rem; font-weight: 700; margin: 0; }
        .nav-links { display: flex; align-items: center; gap: 20px; }
        .nav-links a { color: var(--sidebar-text); text-decoration: none; font-size: 0.9rem; font-weight: 500; padding: 6px 12px; border-radius: 6px; }
        .nav-links a:hover { color: var(--sidebar-hover); background: rgba(255, 255, 255, 0.05); }
        .container { max-width: 650px; margin: 60px auto; padding: 40px; background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border-color); text-align: center; }
        h2 { color: var(--text-main); margin-top: 0; }
        p { color: var(--text-muted); font-size: 0.95rem; }
        .spinner { width: 50px; height: 50px; border: 5px solid #e2e8f0; border-top: 5px solid var(--primary); border-radius: 50%; animation: spin 1s linear infinite; margin: 30px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .url-box { word-break: break-all; color: var(--primary); font-weight: 500; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-color); margin: 15px 0; text-align: left; }
    </style>
</head>
<body>

<header>
    <h1>QR Shield Scanner</h1>
    <div class="nav-links">
        <a href="dashboard.php">Dashboard</a>
        <a href="scanner.php">Scan Another</a>
        <a href="history.php">History</a>
    </div>
</header>

<div class="container">
    <div id="loadingView">
        <h2>Analyzing URL with VirusTotal</h2>
        <p>Please wait while VirusTotal scans the link across dozens of security engines. This can take a few seconds...</p>
        <div class="url-box"><?php echo htmlspecialchars($scanned_url ?? $_SESSION['scanned_url'] ?? ''); ?></div>
        <div class="spinner"></div>
        <p id="statusText" style="font-weight: 600; color: var(--primary);">Communicating with security engines...</p>
    </div>
</div>

<script>
<?php if ($is_polling_view): ?>
// Poll the backend every 3 seconds until VT finishes analyzing
const pollTimer = setInterval(() => {
    fetch('analyze.php?check_status=1')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'completed') {
                clearInterval(pollTimer);
                // Redirect user to a result presentation view or render dynamically
                // For simplicity, we can pass data to a results template or reload into results view
                window.location.href = 'result.php'; // Or handle layout display right here
            } else {
                document.getElementById('statusText').innerText = "Analysis still in progress... checking again shortly.";
            }
        })
        .catch(err => {
            console.error('Polling error:', err);
        });
}, 3000);
<?php else: ?>
// If someone hits analyze.php directly without a POST request
window.location.href = 'scanner.php';
<?php endif; ?>
</script>

<?php include 'bottom_nav.php'; ?>

</body>
</html>