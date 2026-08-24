<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();
require_once 'db.php';

// Check if user is logged in AND is an admin
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$check_admin = $conn->prepare("SELECT role FROM users WHERE id = ?");
$check_admin->bind_param("i", $user_id);
$check_admin->execute();
$res = $check_admin->get_result();
$user_data = $res->fetch_assoc();

if (!$user_data || $user_data['role'] !== 'admin') {
    header("Location: dashboard.php");
    exit();
}
$check_admin->close();

// Handle User Deletion if requested
if (isset($_GET['delete_user'])) {
    $del_id = intval($_GET['delete_user']);
    if ($del_id !== $user_id) {
        $del_stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        $del_stmt->bind_param("i", $del_id);
        $del_stmt->execute();
        $del_stmt->close();
    }
    header("Location: admin.php");
    exit();
}

// Fetch all registered users
$users_result = $conn->query("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC");

// Fetch global scan metrics & logs
$total_scans_res = $conn->query("SELECT COUNT(*) as count FROM scan_history");
$total_scans = $total_scans_res->fetch_assoc()['count'];

$malicious_scans_res = $conn->query("SELECT COUNT(*) as count FROM scan_history WHERE scan_status = 'Malicious'");
$malicious_scans = $malicious_scans_res->fetch_assoc()['count'];

// Fetch recent scans without selections
$all_history = $conn->query("SELECT scan_history.*, users.username FROM scan_history JOIN users ON scan_history.user_id = users.id ORDER BY scanned_at DESC LIMIT 10");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - QR Shield Scanner</title>
    <link rel="stylesheet" href="style.css">
    <style>
        body { background-color: var(--bg-main); margin: 0; padding: 0; }
        header { background-color: var(--sidebar-bg); color: white; padding: 18px 35px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { font-size: 1.25rem; font-weight: 700; margin: 0; }
        .nav-links { display: flex; align-items: center; gap: 20px; }
        .nav-links a { color: var(--sidebar-text); text-decoration: none; font-size: 0.9rem; font-weight: 500; padding: 6px 12px; border-radius: 6px; }
        .nav-links a:hover { color: var(--sidebar-hover); background: rgba(255, 255, 255, 0.05); }
        .container { max-width: 1000px; margin: 40px auto; padding: 40px; background: var(--card-bg); border-radius: var(--radius); box-shadow: var(--shadow); border: 1px solid var(--border-color); }
        h2, h3 { color: var(--text-main); }
        h3 { margin-top: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8fafc; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid var(--border-color); }
        .stat-card h4 { margin: 0 0 8px 0; color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .stat-card p { margin: 0; font-size: 1.75rem; font-weight: 700; color: var(--primary); }
        table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 15px; margin-bottom: 20px; border-radius: 8px; overflow: hidden; border: 1px solid var(--border-color); }
        th, td { padding: 14px 18px; text-align: left; font-size: 0.9rem; border-bottom: 1px solid var(--border-color); }
        th { background-color: #f1f5f9; color: var(--text-main); font-weight: 600; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background-color: #f8fafc; }
        .badge { padding: 6px 12px; font-weight: 700; border-radius: 6px; color: white; font-size: 0.75rem; display: inline-block; text-transform: uppercase; letter-spacing: 0.05em; }
        .Safe { background-color: #10b981; }
        .Suspicious { background-color: #f59e0b; color: #fff; }
        .Malicious { background-color: #ef4444; }
        .btn-danger { background-color: #ef4444; color: white; padding: 6px 12px; text-decoration: none; border-radius: 6px; font-size: 0.8rem; font-weight: 600; display: inline-block; transition: background 0.2s; }
        .btn-danger:hover { background-color: #dc2626; }
        .url-cell { word-break: break-all; max-width: 300px; color: var(--primary); }
    </style>
</head>
<body>

<header>
    <h1>QR Shield Scanner - Admin Panel</h1>
    <div class="nav-links">
        <a href="dashboard.php">User Dashboard</a>
        <a href="logout.php" style="color: #ef4444;">Logout</a>
    </div>
</header>

<div class="container">
    <h2>System Administrator Control Panel</h2>
    <p>Welcome, Administrator. Here is an overview of platform activity and user management controls.</p>

    <!-- System Statistics Cards -->
    <div class="stats-grid">
        <div class="stat-card">
            <h4>Total Global Scans</h4>
            <p><?php echo $total_scans; ?></p>
        </div>
        <div class="stat-card">
            <h4>Malicious Links Caught</h4>
            <p style="color: #ef4444;"><?php echo $malicious_scans; ?></p>
        </div>
    </div>

    <!-- Registered Users Management Table -->
    <h3>Registered Users</h3>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Joined At</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php while ($user = $users_result->fetch_assoc()): ?>
                <tr>
                    <td><?php echo $user['id']; ?></td>
                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                    <td><?php echo htmlspecialchars($user['email']); ?></td>
                    <td><strong><?php echo ucfirst($user['role']); ?></strong></td>
                    <td><?php echo $user['created_at']; ?></td>
                    <td>
                        <?php if ($user['role'] !== 'admin'): ?>
                            <a href="admin.php?delete_user=<?php echo $user['id']; ?>" class="btn-danger" onclick="return confirm('Are you sure you want to delete this user?');">Delete</a>
                        <?php else: ?>
                            <span style="color: var(--text-muted); font-size: 0.85rem;">Protected</span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endwhile; ?>
        </tbody>
    </table>

    <!-- Recent Global Scan Logs (Detections column removed) -->
    <h3>Recent Platform Scans (Live Stream)</h3>
    <table>
        <thead>
            <tr>
                <th>User</th>
                <th>URL</th>
                <th>Status</th>
                <th>Time</th>
            </tr>
        </thead>
        <tbody>
            <?php while ($log = $all_history->fetch_assoc()): ?>
                <tr>
                    <td><?php echo htmlspecialchars($log['username']); ?></td>
                    <td class="url-cell"><?php echo htmlspecialchars($log['scanned_url']); ?></td>
                    <td><span class="badge <?php echo $log['scan_status']; ?>"><?php echo $log['scan_status']; ?></span></td>
                    <td><?php echo $log['scanned_at']; ?></td>
                </tr>
            <?php endwhile; ?>
        </tbody>
    </table>
</div>

</body>
</html>
<?php $conn->close(); ?>