<?php
require_once 'db.php';

$conn->query("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0");
$conn->query("ALTER TABLE users ADD COLUMN verify_token TEXT");
$conn->query("UPDATE users SET verified = 1 WHERE verify_token IS NULL");

echo "Migration done.";
$conn->close();
?>