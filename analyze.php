<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'db.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}

$scan_status = "Error";
$malicious_count = 0;
$total_engines = 0;
$scanned_url = "";

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['url'])) {
    $scanned_url = trim($_POST['url']);
    $user_id = $_SESSION['user_id'];

    // 1. Submit URL to VirusTotal API v3 for analysis
    $vt_url = 'https://www.virustotal.com/api/v3/urls';
    $api_key = '5ad5512fff2367ba837854a93509cc9d4c23b4c0d208f221d785aa682c41eee3'; // <-- API Key

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
        $analysis_id = $data['data']['id'] ?? null;

        if ($analysis_id) {
            $report_url = 'https://www.virustotal.com/api/v3/analyses/' . $analysis_id;
            
            // Sleep 3 seconds to give VT backend time to aggregate engine scores
            sleep(3);

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $report_url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'accept: application/json',
                'x-apikey: ' . $api_key
            ]);

            $report_response = curl_exec($ch);
            curl_close($ch);

            $report_data = json_decode($report_response, true);
            $stats = $report_data['data']['attributes']['stats'] ?? null;

            if ($stats) {
                $malicious_count = $stats['malicious'] ?? 0;
                $suspicious_count = $stats['suspicious'] ?? 0;
                $harmless_count = $stats['harmless'] ?? 0;
                $undetected_count = $stats['undetected'] ?? 0;
                
                $total_engines = $malicious_count + $suspicious_count + $harmless_count + $undetected_count;

                // Determine overall scan status category
                if ($malicious_count > 0) {
                    $scan_status = "Malicious";
                } elseif ($suspicious_count > 0) {
                    $scan_status = "Suspicious";
                } else {
                    $scan_status = "Safe";
                }

                // 2. Save Scan History into SQLite Database using SQLite3 bindValue syntax
                $hist_stmt = $conn->prepare("INSERT INTO scan_history (user_id, scanned_url, scan_status, malicious_count, total_engines) VALUES (?, ?, ?, ?, ?)");
                
                if ($hist_stmt) {
                    $hist_stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
                    $hist_stmt->bindValue(2, $scanned_url, SQLITE3_TEXT);
                    $hist_stmt->bindValue(3, $scan_status, SQLITE3_TEXT);
                    $hist_stmt->bindValue(4, $malicious_count, SQLITE3_INTEGER);
                    $hist_stmt->bindValue(5, $total_engines, SQLITE3_INTEGER);
                    $hist_stmt->execute();
                }
            }
        }
    } else {
        $scan_status = "API Connection Error (Check API Key)";
    }
}
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analysis Result - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { background-color: var(--bg-main); margin: 0; padding: 0; }
        header { background-color: var(--sidebar-bg); color: white; padding: 18px 35px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 1.25rem; font-weight: 700; margin: 0; }
        .nav-links { display: flex; align-items: center; gap: 20px; }
        .nav-links a { color: var(--sidebar-text); text-decoration: none; font-size: 0.9rem; font-weight: 500; padding: 6px 12px; border-radius: 6px; }
        .nav-links a:hover { color: var(--sidebar-hover); background: rgba(255, 255, 255, 0.05); }
        .container { max-width: 650px; margin: 40px auto; padding: 40px; background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border-color); }
        h2 { color: var(--text-main); margin-top: 0; }
        p { color: var(--text-muted); font-size: 0.95rem; }
        .badge { padding: 6px 15px; font-weight: 700; border-radius: 6px; color: white; font-size: 0.85rem; display: inline-block; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 5px; }
        .Safe { background-color: #10b981; }
        .Suspicious { background-color: #f59e0b; color: #fff; }
        .Malicious { background-color: #ef4444; }
        .Error { background-color: #64748b; }
        .btn-group { display: flex; gap: 15px; margin-top: 30px; }
        .btn-back { display: inline-block; padding: 12px 20px; background: var(--primary); color: white; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 0.95rem; text-align: center; flex: 1; transition: background 0.2s; }
        .btn-back:hover { background: var(--primary-hover); }
        .btn-secondary { background: #64748b; }
        .btn-secondary:hover { background: #475569; }
        .url-box { word-break: break-all; color: var(--primary); font-weight: 500; background: #f8fafc; padding: 12px; border-radius: 8px; border: 1px solid var(--border-color); margin-top: 5px; margin-bottom: 20px; }
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
    <h2>VirusTotal Threat Analysis Report</h2>
    <p><strong>Scanned URL / Content:</strong></p>
    <div class="url-box"><?php echo htmlspecialchars($scanned_url); ?></div>
    
    <p><strong>Threat Status:</strong><br>
        <span class="badge <?php echo $scan_status; ?>"><?php echo $scan_status; ?></span>
    </p>

    <div class="btn-group">
        <a href="scanner.php" class="btn-back">Scan Another QR</a>
        <a href="history.php" class="btn-back btn-secondary">View History</a>
    </div>
</div>

</body>
</html>