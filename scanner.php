<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan QR - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <!-- Include HTML5-QRCode library for camera scanning -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html5-qrcode/2.3.8/html5-qrcode.min.js"></script>
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
        .scanner-box { width: 100%; max-width: 450px; margin: 20px auto; border-radius: 8px; overflow: hidden; border: 1px solid var(--border-color); background: #000; }
        .result-section { margin-top: 25px; padding: 20px; background: #f8fafc; border-radius: 8px; border: 1px solid var(--border-color); display: none; }
        .result-section h3 { margin-top: 0; font-size: 1rem; color: var(--text-main); }
        .url-display { word-break: break-all; font-weight: 500; color: var(--primary); margin-bottom: 15px; font-size: 0.95rem; }
        .btn-vt { background-color: #10b981; color: white; width: 100%; padding: 12px; border: none; border-radius: 8px; font-weight: 600; font-size: 1rem; cursor: pointer; transition: background 0.2s; display: flex; align-items: center; justify-content: center; gap: 10px; }
        .btn-vt:hover { background-color: #059669; }
        .btn-vt:disabled { background-color: #94a3b8; cursor: not-allowed; }
        .tab-buttons { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab-btn { flex: 1; padding: 10px; background: #f1f5f9; border: 1px solid var(--border-color); border-radius: 6px; font-weight: 600; cursor: pointer; color: var(--text-muted); text-align: center; }
        .tab-btn.active { background: var(--primary); color: white; border-color: var(--primary); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .file-upload-box { border: 2px dashed var(--border-color); padding: 30px; text-align: center; border-radius: 8px; cursor: pointer; background: #f8fafc; }
        .file-upload-box:hover { background: #f1f5f9; }

        .spinner { width: 18px; height: 18px; border: 3px solid rgba(255,255,255,0.4); border-top-color: #fff; border-radius: 50%; animation: spin 0.7s linear infinite; display: none; }
        @keyframes spin { to { transform: rotate(360deg); } }

        .loading-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.7); align-items: center; justify-content: center; z-index: 1000; flex-direction: column; color: white; text-align: center; padding: 20px; }
        .loading-overlay.active { display: flex; }
        .loading-overlay .big-spinner { width: 50px; height: 50px; border: 5px solid rgba(255,255,255,0.3); border-top-color: #10b981; border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 20px; }
        .loading-overlay p { color: white; font-size: 1rem; font-weight: 500; margin: 4px 0; }
        .loading-overlay .loading-sub { color: #cbd5e1; font-size: 0.85rem; }

        .dupe-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.6); align-items: center; justify-content: center; z-index: 1000; }
        .dupe-overlay.active { display: flex; }
        .dupe-box { background: var(--card-bg); padding: 30px; border-radius: 12px; max-width: 420px; width: 90%; box-shadow: var(--shadow); text-align: center; }
        .dupe-box h3 { margin-top: 0; color: #f59e0b; }
        .dupe-box p { color: var(--text-main); font-size: 0.9rem; }
        .dupe-box .url-display { text-align: left; background: #f8fafc; padding: 10px; border-radius: 8px; border: 1px solid var(--border-color); }
        .dupe-btn-group { display: flex; gap: 12px; margin-top: 20px; }
        .dupe-btn-group button { flex: 1; padding: 12px; border-radius: 8px; font-weight: 600; font-size: 0.9rem; border: none; cursor: pointer; }
        .btn-dupe-cancel { background: #e2e8f0; color: var(--text-main); }
        .btn-dupe-cancel:hover { background: #cbd5e1; }
        .btn-dupe-continue { background: #f59e0b; color: white; }
        .btn-dupe-continue:hover { background: #d97706; }
        .dupe-checkbox { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 16px; font-size: 0.85rem; color: var(--text-muted); cursor: pointer; user-select: none; }
        .dupe-checkbox input { width: auto; margin: 0; cursor: pointer; }
        .dupe-pref-note { display: none; margin-top: 15px; font-size: 0.8rem; color: var(--text-muted); text-align: center; }
        .dupe-pref-note a { color: var(--primary); cursor: pointer; font-weight: 600; text-decoration: none; }
        .dupe-pref-note a:hover { text-decoration: underline; }

        .scan-error { display: none; margin-top: 15px; padding: 12px 16px; background: #fee2e2; color: #991b1b; border-radius: 8px; font-size: 0.88rem; }
    </style>
</head>
<body>

<header>
    <h1>QR Shield Scanner</h1>
    <div class="nav-links">
        <a href="dashboard.php">Dashboard</a>
        <a href="history.php">History</a>
        <a href="logout.php" style="color: #ef4444;">Logout</a>
    </div>
</header>

<div class="container">
    <h2>Scan QR Code</h2>
    <p>Scan a QR code using your camera or upload an image file containing a QR code.</p>

    <div class="tab-buttons">
        <div class="tab-btn active" onclick="switchTab('camera')">Live Camera</div>
        <div class="tab-btn" onclick="switchTab('upload')">Upload Image</div>
    </div>

    <div id="camera-tab" class="tab-content active">
        <div id="reader" class="scanner-box"></div>
    </div>

    <div id="upload-tab" class="tab-content">
        <div class="file-upload-box" onclick="document.getElementById('qr-file-input').click()">
            <p style="margin: 0; font-weight: 600; color: var(--text-main);">Click here to upload QR image</p>
            <p style="margin: 5px 0 0 0; font-size: 0.85rem;">Supports PNG, JPG, JPEG</p>
            <input type="file" id="qr-file-input" accept="image/*" style="display: none;" onchange="decodeQRFromFile(this)">
        </div>
    </div>

    <div class="dupe-pref-note" id="dupe-pref-note">
        Duplicate-scan warnings are turned off. <a onclick="enableDupeWarning()">Turn back on</a>
    </div>

    <div id="result-section" class="result-section">
        <h3>Extracted URL / Text:</h3>
        <div id="extracted-url" class="url-display"></div>

        <button type="button" class="btn-vt" id="vt-submit-btn" onclick="startScan();">
            <span class="spinner" id="vt-spinner"></span>
            <span id="vt-btn-label">Check Safety with VirusTotal</span>
        </button>

        <div class="scan-error" id="scan-error"></div>
    </div>
</div>

<div class="loading-overlay" id="loadingOverlay">
    <div class="big-spinner"></div>
    <p id="loading-main-text">Submitting link to VirusTotal...</p>
    <p class="loading-sub" id="loading-sub-text">This usually takes a few seconds.</p>
</div>

<div class="dupe-overlay" id="dupeOverlay">
    <div class="dupe-box">
        <h3>⚠️ Already Scanned</h3>
        <p>You've already scanned this exact QR code in this session:</p>
        <div class="url-display" id="dupe-url-display"></div>
        <label class="dupe-checkbox">
            <input type="checkbox" id="dupe-never-show">
            Don't show this warning again
        </label>
        <div class="dupe-btn-group">
            <button class="btn-dupe-cancel" onclick="closeDupePopup()">Cancel</button>
            <button class="btn-dupe-continue" onclick="proceedAfterDupe()">Scan Anyway</button>
        </div>
    </div>
</div>

<script>
let html5QrCode;
let pendingDecodedText = null;
let pollTimer = null;
let currentUrlToScan = null;

function getScannedSet() {
    const raw = sessionStorage.getItem('qrShieldScannedCodes');
    return raw ? new Set(JSON.parse(raw)) : new Set();
}
function rememberScannedCode(text) {
    const set = getScannedSet();
    set.add(text);
    sessionStorage.setItem('qrShieldScannedCodes', JSON.stringify(Array.from(set)));
}

const DUPE_PREF_KEY = 'qrShieldHideDuplicateWarning';
function isDupeWarningDisabled() {
    try { return localStorage.getItem(DUPE_PREF_KEY) === '1'; } catch (e) { return false; }
}
function updateDupePrefNote() {
    document.getElementById('dupe-pref-note').style.display = isDupeWarningDisabled() ? 'block' : 'none';
}
function enableDupeWarning() {
    try { localStorage.removeItem(DUPE_PREF_KEY); } catch (e) {}
    updateDupePrefNote();
}

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    if (tab === 'camera') {
        event.currentTarget.classList.add('active');
        document.getElementById('camera-tab').classList.add('active');
        startCameraScanner();
    } else {
        event.currentTarget.classList.add('active');
        document.getElementById('upload-tab').classList.add('active');
        if (html5QrCode && html5QrCode.isScanning) {
            html5QrCode.stop().catch(err => console.log(err));
        }
    }
}

function showResult(decodedText) {
    document.getElementById('result-section').style.display = 'block';
    document.getElementById('extracted-url').textContent = decodedText;
    currentUrlToScan = decodedText;
    document.getElementById('scan-error').style.display = 'none';
}

function handleDecodedText(decodedText) {
    if (getScannedSet().has(decodedText) && !isDupeWarningDisabled()) {
        pendingDecodedText = decodedText;
        document.getElementById('dupe-url-display').textContent = decodedText;
        document.getElementById('dupe-never-show').checked = false;
        document.getElementById('dupeOverlay').classList.add('active');
        return;
    }
    rememberScannedCode(decodedText);
    showResult(decodedText);
}

function onScanSuccess(decodedText, decodedResult) {
    if (html5QrCode && html5QrCode.isScanning) {
        html5QrCode.stop().catch(err => console.log(err));
    }
    handleDecodedText(decodedText);
}

function closeDupePopup() {
    document.getElementById('dupeOverlay').classList.remove('active');
    pendingDecodedText = null;
    startCameraScanner();
}

function proceedAfterDupe() {
    if (document.getElementById('dupe-never-show').checked) {
        try { localStorage.setItem(DUPE_PREF_KEY, '1'); } catch (e) {}
        updateDupePrefNote();
    }
    document.getElementById('dupeOverlay').classList.remove('active');
    if (pendingDecodedText) {
        rememberScannedCode(pendingDecodedText);
        showResult(pendingDecodedText);
    }
    pendingDecodedText = null;
}

function startCameraScanner() {
    if (!html5QrCode) {
        html5QrCode = new Html5Qrcode("reader");
    }
    html5QrCode.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        onScanSuccess
    ).catch(err => {
        console.log("Camera initialization error: ", err);
    });
}

function decodeQRFromFile(input) {
    if (input.files && input.files[0]) {
        const file = input.files[0];
        const html5QrCodeFile = new Html5Qrcode("reader");
        html5QrCodeFile.scanFile(file, true)
            .then(decodedText => { handleDecodedText(decodedText); })
            .catch(err => {
                alert("Could not extract QR code from image. Please try another image.");
                console.log(err);
            });
    }
}

// ---- Non-blocking scan flow ----
// Submits the URL, gets an analysis ID back instantly, then polls in the
// background instead of holding the page (and PHP) hostage for 20+ seconds.

function setButtonBusy(isBusy) {
    const btn = document.getElementById('vt-submit-btn');
    const spinner = document.getElementById('vt-spinner');
    const label = document.getElementById('vt-btn-label');
    btn.disabled = isBusy;
    spinner.style.display = isBusy ? 'inline-block' : 'none';
    label.textContent = isBusy ? 'Checking...' : 'Check Safety with VirusTotal';
}

function showScanError(message) {
    const errBox = document.getElementById('scan-error');
    errBox.textContent = message;
    errBox.style.display = 'block';
}

async function startScan() {
    if (!currentUrlToScan) return;
    setButtonBusy(true);
    document.getElementById('scan-error').style.display = 'none';

    const overlay = document.getElementById('loadingOverlay');
    document.getElementById('loading-main-text').textContent = 'Submitting link to VirusTotal...';
    document.getElementById('loading-sub-text').textContent = 'This usually takes a few seconds.';
    overlay.classList.add('active');

    try {
        const submitRes = await fetch('api_submit_scan.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'url=' + encodeURIComponent(currentUrlToScan)
        });
        const submitData = await submitRes.json();

        if (!submitRes.ok || submitData.error) {
            throw new Error(submitData.error || 'Could not submit the link for scanning.');
        }

        if (submitData.status === 'completed') {
            // VirusTotal already had a recent report for this exact link -
            // no need to wait for a fresh analysis at all.
            window.location.href = 'result.php?id=' + encodeURIComponent(submitData.history_id);
            return;
        }

        pollForResult(submitData.analysis_id, 0);
    } catch (err) {
        overlay.classList.remove('active');
        setButtonBusy(false);
        showScanError(err.message || 'Something went wrong starting the scan.');
    }
}

async function pollForResult(analysisId, attempt) {
    const maxAttempts = 15; // ~45 seconds at 3s intervals
    document.getElementById('loading-main-text').textContent = 'Analyzing link...';
    document.getElementById('loading-sub-text').textContent =
        attempt === 0 ? 'Checking with security engines.' : 'Still working, hang tight...';

    try {
        const res = await fetch('api_poll_scan.php?id=' + encodeURIComponent(analysisId));
        const data = await res.json();

        if (!res.ok || data.error) {
            throw new Error(data.error || 'Lost connection while checking the scan.');
        }

        if (data.status === 'completed') {
            // Done - go straight to the results page, which reads the saved,
            // finished result rather than anything guessed on this page.
            window.location.href = 'result.php?id=' + encodeURIComponent(data.history_id);
            return;
        }

        if (attempt + 1 >= maxAttempts) {
            throw new Error('This scan is taking longer than usual. Please try again in a moment.');
        }

        pollTimer = setTimeout(() => pollForResult(analysisId, attempt + 1), 3000);
    } catch (err) {
        document.getElementById('loadingOverlay').classList.remove('active');
        setButtonBusy(false);
        showScanError(err.message || 'Something went wrong while scanning.');
    }
}

window.onload = function() {
    updateDupePrefNote();
    startCameraScanner();
};
</script>

<?php include 'bottom_nav.php'; ?>

</body>
</html>