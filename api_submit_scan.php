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

$scanned_url = isset($_POST['url']) ? trim($_POST['url']) : '';
if (empty($scanned_url)) {
    http_response_code(400);
    echo json_encode(['error' => 'No URL provided']);
    exit();
}

$api_key = getenv('VT_API_KEY');
if (!$api_key) {
    http_response_code(500);
    echo json_encode(['error' => 'Scanner is not configured (missing API key)']);
    exit();
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/api/v3/urls');
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

if ($http_code != 200) {
    http_response_code(502);
    echo json_encode(['error' => 'Could not reach VirusTotal']);
    exit();
}

$data = json_decode($response, true);
$analysis_id = $data['data']['id'] ?? null;

if (!$analysis_id) {
    http_response_code(502);
    echo json_encode(['error' => 'VirusTotal did not return an analysis ID']);
    exit();
}

// Stash the scanned URL against this analysis ID in the session so poll_scan.php
// and save_scan.php can trust it later without the client resending it.
if (!isset($_SESSION['pending_scans'])) {
    $_SESSION['pending_scans'] = [];
}
$_SESSION['pending_scans'][$analysis_id] = $scanned_url;

echo json_encode(['analysis_id' => $analysis_id]);