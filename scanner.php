<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
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
        .btn-vt { background-color: #10b981; color: white; width: 100%; padding: 12px; border: none; border-radius: 8px; font-weight: 600; font-size: 1rem; cursor: pointer; transition: background 0.2s; }
        .btn-vt:hover { background-color: #059669; }
        .tab-buttons { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab-btn { flex: 1; padding: 10px; background: #f1f5f9; border: 1px solid var(--border-color); border-radius: 6px; font-weight: 600; cursor: pointer; color: var(--text-muted); text-align: center; }
        .tab-btn.active { background: var(--primary); color: white; border-color: var(--primary); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .file-upload-box { border: 2px dashed var(--border-color); padding: 30px; text-align: center; border-radius: 8px; cursor: pointer; background: #f8fafc; }
        .file-upload-box:hover { background: #f1f5f9; }
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

    <!-- Tabs for Camera vs Upload -->
    <div class="tab-buttons">
        <div class="tab-btn active" onclick="switchTab('camera')">Live Camera</div>
        <div class="tab-btn" onclick="switchTab('upload')">Upload Image</div>
    </div>

    <!-- Camera Scanner Tab -->
    <div id="camera-tab" class="tab-content active">
        <div id="reader" class="scanner-box"></div>
    </div>

    <!-- Upload Image Tab -->
    <div id="upload-tab" class="tab-content">
        <div class="file-upload-box" onclick="document.getElementById('qr-file-input').click()">
            <p style="margin: 0; font-weight: 600; color: var(--text-main);">Click here to upload QR image</p>
            <p style="margin: 5px 0 0 0; font-size: 0.85rem;">Supports PNG, JPG, JPEG</p>
            <input type="file" id="qr-file-input" accept="image/*" style="display: none;" onchange="decodeQRFromFile(this)">
        </div>
    </div>

    <!-- Scan Result & VT Submission Section -->
    <div id="result-section" class="result-section">
        <h3>Extracted URL / Text:</h3>
        <div id="extracted-url" class="url-display"></div>
        
        <form id="vt-form" action="analyze.php" method="POST">
            <input type="hidden" id="url-input" name="url">
            <button type="submit" class="btn-vt">Check Safety with VirusTotal</button>
        </form>
    </div>
</div>

<script>
let html5QrCode;

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

function onScanSuccess(decodedText, decodedResult) {
    // Display result box and populate form
    document.getElementById('result-section').style.display = 'block';
    document.getElementById('extracted-url').textContent = decodedText;
    document.getElementById('url-input').value = decodedText;

    // Optional: Stop camera after successful scan to save resource
    if (html5QrCode && html5QrCode.isScanning) {
        html5QrCode.stop().catch(err => console.log(err));
    }
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
            .then(decodedText => {
                document.getElementById('result-section').style.display = 'block';
                document.getElementById('extracted-url').textContent = decodedText;
                document.getElementById('url-input').value = decodedText;
            })
            .catch(err => {
                alert("Could not extract QR code from image. Please try another image.");
                console.log(err);
            });
    }
}

// Initialize camera scanner on load
window.onload = function() {
    startCameraScanner();
};
</script>

</body>
</html>