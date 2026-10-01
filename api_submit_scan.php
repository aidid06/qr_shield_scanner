<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
header('Content-Type: application/json');

// If anything fatal happens below, still send back valid JSON instead of an
// empty response - an empty body is what causes "Unexpected end of JSON
// input" in the browser.
register_shutdown_function(function () {
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) {
            http_response_code(500);
        }
        echo json_encode(['error' => 'Server error while scanning. Please try again.']);
    }
});

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

// VirusTotal keeps a report for any URL it has already analyzed before, under
// an ID that's just the URL, base64url-encoded with the padding stripped.
// Checking that first means a URL someone already scanned (by anyone, not
// just this user) comes back instantly instead of re-running a fresh
// analysis and waiting for it all over again.
$url_id = rtrim(strtr(base64_encode($scanned_url), '+/', '-_'), '=');

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/api/v3/urls/' . $url_id);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
curl_setopt($ch, CURLOPT_TIMEOUT, 12);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'accept: application/json',
    'x-apikey: ' . $api_key
]);
$lookup_response = curl_exec($ch);
$lookup_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if ($lookup_code == 200) {
    $lookup_data = json_decode($lookup_response, true);
    $existing_stats = $lookup_data['data']['attributes']['last_analysis_stats'] ?? null;
    $last_analysis_date = $lookup_data['data']['attributes']['last_analysis_date'] ?? null;

    // Only trust it as "already done" if it actually has engine results and
    // was analyzed reasonably recently (30 days) - an old or empty report
    // isn't useful, so fall through to a fresh submission in that case.
    if ($existing_stats && $last_analysis_date && (time() - $last_analysis_date) < (30 * 24 * 60 * 60)) {
        $malicious = $existing_stats['malicious'] ?? 0;
        $suspicious = $existing_stats['suspicious'] ?? 0;
        $harmless = $existing_stats['harmless'] ?? 0;
        $undetected = $existing_stats['undetected'] ?? 0;
        $total = $malicious + $suspicious + $harmless + $undetected;

        if ($total > 0) {
            if ($malicious > 0) {
                $scan_status = 'Malicious';
            } elseif ($suspicious > 0) {
                $scan_status = 'Suspicious';
            } else {
                $scan_status = 'Safe';
            }

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
                $history_id = $conn->insert_id();
                $stmt->close();
            }
            $conn->close();

            // Already have a real, finished result - skip straight to it,
            // no need to submit a new analysis or poll for anything.
            echo json_encode([
                'status' => 'completed',
                'history_id' => $history_id
            ]);
            exit();
        }
    }
}

// No usable existing report - submit a fresh analysis and let the browser
// poll api_poll_scan.php for it the normal way.
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/api/v3/urls');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
curl_setopt($ch, CURLOPT_TIMEOUT, 12);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(['url' => $scanned_url]));
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'accept: application/json',
    'x-apikey: ' . $api_key,
    'content-type: application/x-www-form-urlencoded'
]);
$response = curl_exec($ch);
$curl_error = curl_error($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

if ($curl_error) {
    error_log("VirusTotal submit curl error: " . $curl_error);
    http_response_code(504);
    echo json_encode(['error' => 'The scan is taking too long to start. Please try again.']);
    exit();
}

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

// Stash the scanned URL against this analysis ID in the database (not the
// session) so api_poll_scan.php can trust it later without depending on
// session cookies surviving between the submit and poll requests.
require_once 'db.php';
$pending_stmt = $conn->prepare("INSERT OR REPLACE INTO pending_scans (analysis_id, user_id, scanned_url) VALUES (?, ?, ?)");
if ($pending_stmt) {
    $pending_stmt->bindValue(1, $analysis_id, SQLITE3_TEXT);
    $pending_stmt->bindValue(2, $_SESSION['user_id'], SQLITE3_INTEGER);
    $pending_stmt->bindValue(3, $scanned_url, SQLITE3_TEXT);
    $pending_stmt->execute();
    $pending_stmt->close();
}
$conn->close();

echo json_encode(['status' => 'pending', 'analysis_id' => $analysis_id]);