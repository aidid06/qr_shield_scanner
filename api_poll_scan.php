<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
header('Content-Type: application/json');

session_start();
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Not logged in']);
    exit();
}

$analysis_id = isset($_GET['id']) ? trim($_GET['id']) : '';
if (empty($analysis_id) || !isset($_SESSION['pending_scans'][$analysis_id])) {
    http_response_code(400);
    echo json_encode(['error' => 'Unknown or expired analysis ID']);
    exit();
}

$api_key = getenv('VT_API_KEY');
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/api/v3/analyses/' . $analysis_id);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'accept: application/json',
    'x-apikey: ' . $api_key
]);
$response = curl_exec($ch);
curl_close($ch);

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

$scanned_url = $_SESSION['pending_scans'][$analysis_id];

// Save to history now that we have a real, finished result.
require_once 'db.php';
$stmt = $conn->prepare("INSERT INTO scan_history (user_id, scanned_url, scan_status, malicious_count, total_engines) VALUES (?, ?, ?, ?, ?)");
$history_id = null;
if ($stmt) {
    $stmt->bindValue(1, $_SESSION['user_id'], SQLITE3_INTEGER);
    $stmt->bindValue(2, $scanned_url, SQLITE3_TEXT);
    $stmt->bindValue(3, $scan_status, SQLITE3_TEXT);
    $stmt->bindValue(4, $malicious, SQLITE3_INTEGER);
    $stmt->bindValue(5, $total, SQLITE3_INTEGER);
    $stmt->execute();
    $history_id = $conn->lastInsertRowID();
    $stmt->close();
}
$conn->close();

unset($_SESSION['pending_scans'][$analysis_id]);

echo json_encode([
    'status' => 'completed',
    'scan_status' => $scan_status,
    'malicious_count' => $malicious,
    'total_engines' => $total,
    'scanned_url' => $scanned_url,
    'history_id' => $history_id
]);