<?php
$host = "localhost";
$username = "root";
$password = "";
$database = "qr_shield_scanner";

// Create database connection
$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Database Connection Failed: " . $conn->connect_error);
}
?>