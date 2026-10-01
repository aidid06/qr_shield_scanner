<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
header('Content-Type: application/json');

// Always send back valid JSON, even if something fatal happens below -
// an empty response is what causes "Unexpected end of JSON input" client-side.
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) {
            http_response_code(500);
        }
        echo json_encode(['status' => 'pending']); // let the browser just keep polling
    }
});

session_start();
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$analysis_id = isset($_GET['id']) ? trim($_GET['id']) : '';
if (empty($analysis_id)) {
    http_response_code(400);
    echo json_encode(['error' => 'Unknown or expired analysis ID']);
    exit();
}

require_once 'db.php';
$lookup_stmt = $conn->prepare("SELECT user_id, scanned_url FROM pending_scans WHERE analysis_id = ?");
$lookup_stmt->bindValue(1, $analysis_id, SQLITE3_TEXT);
$lookup_res = $lookup_stmt->execute();
$pending = $lookup_res ? $lookup_res->fetchArray(SQLITE3_ASSOC) : null;
$lookup_stmt->close();

if (!$pending || (int)$pending['user_id'] !== (int)$_SESSION['user_id']) {
    $conn->close();
    http_response_code(400);
    echo json_encode(['error' => 'Unknown or expired analysis ID']);
    exit();
}
$scanned_url_for_this_scan = $pending['scanned_url'];
// Keep $conn open - we'll need it again below if the scan has finished.

$api_key = getenv('VT_API_KEY');
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/api/v3/analyses/' . $analysis_id);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
curl_setopt($ch, CURLOPT_TIMEOUT, 12);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'accept: application/json',
    'x-apikey: ' . $api_key
]);
$response = curl_exec($ch);
$curl_error = curl_error($ch);

if ($curl_error) {
    // A single failed poll isn't fatal - just tell the browser to try again
    // on the next 3-second cycle instead of giving up.
    error_log("VirusTotal poll curl error: " . $curl_error);
    echo json_encode(['status' => 'pending']);
    exit();
}

$data = json_decode($response, true);
$status = $data['data']['attributes']['status'] ?? 'unknown';
$stats = $data['data']['attributes']['stats'] ?? null;

if ($status !== 'completed' || !$stats) {
    // Still queued or running - tell the browser to keep polling.
    echo json_encode(['status' => 'pending']);
    exit();
}

$malicious = $stats['malicious'] ?? 0;
$suspicious = $stats['suspicious'] ?? 0;
$harmless = $stats['harmless'] ?? 0;
$undetected = $stats['undetected'] ?? 0;
$total = $malicious + $suspicious + $harmless + $undetected;

if ($malicious > 0) {
    $scan_status = 'Malicious';
} elseif ($suspicious > 0) {
    $scan_status = 'Suspicious';
} else {
    $scan_status = 'Safe';
}

$scanned_url = $scanned_url_for_this_scan;

// Save to history now that we have a real, finished result.
// $conn is already open from the pending_scans lookup earlier in this request.
$stmt = $conn->prepare("INSERT INTO scan_history (user_id, scanned_url, scan_status, malicious_count, total_engines) VALUES (?, ?, ?, ?, ?)");
$history_id = null;
if ($stmt) {
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $stmt->bindValue(2, $scanned_url, SQLITE3_TEXT);
    $stmt->bindValue(3, $scan_status, SQLITE3_TEXT);
    $stmt->bindValue(4, $malicious, SQLITE3_INTEGER);
    $stmt->bindValue(5, $total, SQLITE3_INTEGER);
    $stmt->execute();
    $history_id = $conn->insert_id();
    $stmt->close();
}

$cleanup_stmt = $conn->prepare("DELETE FROM pending_scans WHERE analysis_id = ?");
if ($cleanup_stmt) {
    $cleanup_stmt->bindValue(1, $analysis_id, SQLITE3_TEXT);
    $cleanup_stmt->execute();
    $cleanup_stmt->close();
}
$conn->close();

echo json_encode([
    'status' => 'completed',
    'scan_status' => $scan_status,
    'malicious_count' => $malicious,
    'total_engines' => $total,
    'scanned_url' => $scanned_url,
    'history_id' => $history_id
]);