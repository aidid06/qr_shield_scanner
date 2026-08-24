<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

// Check if user is logged in, if not redirect to login page
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
    <link rel="stylesheet" href="style.css">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - QR Shield Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f9; margin: 0; padding: 0; }
        header { background-color: #333; color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { margin: 0; font-size: 20px; }
        .logout-btn { background-color: #dc3545; color: white; padding: 8px 15px; text-decoration: none; border-radius: 4px; font-size: 14px; }
        .logout-btn:hover { background-color: #c82333; }
        .container { max-width: 900px; margin: 40px auto; padding: 20px; background: white; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0,0,0,0.1); }
        h2 { color: #333; }
        p { color: #666; }
        .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 5px solid #007bff; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .card h3 { margin-top: 0; color: #007bff; }
        .card p { font-size: 14px; margin-bottom: 15px; }
        .card a { display: inline-block; padding: 8px 12px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; font-size: 14px; }
        .card a:hover { background: #0056b3; }
    </style>
</head>
<body>

<header>
    <h1>QR Shield Scanner</h1>
    <div class="nav-links">
        <?php
        // Check if the logged-in user is an admin to show the Admin Panel link
        require_once 'db.php';
        $uid = $_SESSION['user_id'];
        $chk_admin = $conn->prepare("SELECT role FROM users WHERE id = ?");
        $chk_admin->bind_param("i", $uid);
        $chk_admin->execute();
        $res_admin = $chk_admin->get_result()->fetch_assoc();
        if ($res_admin && $res_admin['role'] === 'admin') {
            echo '<a href="admin.php" style="color: #ffc107; font-weight: bold;">Admin Panel</a>';
        }
        $chk_admin->close();
        ?>
        <a href="logout.php" style="color: #ff6b6b;">Logout</a>
    </div>
</header>

<div class="container">
    <h2>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>! 👋</h2>
    <p>You are successfully logged into your dashboard. From here, you can scan QR codes for malware and review past analyses.</p>

    <div class="card-grid">
        <div class="card">
            <h3>QR Scanner</h3>
            <p>Scan a QR code using your camera or upload an image file to check for malicious links.</p>
            <a href="scanner.php">Go to Scanner</a>
        </div>
        <div class="card">
            <h3>Scan History</h3>
            <p>View the history and VirusTotal safety status of all the URLs you have previously scanned.</p>
            <a href="history.php">View History</a>
        </div>
    </div>
</div>

</body>
</html>