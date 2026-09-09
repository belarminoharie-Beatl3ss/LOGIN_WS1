<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

require_once "db.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: index.html");
    exit();
}

$username = trim($_POST["username"] ?? "");
$password = $_POST["password"] ?? "";

if (empty($username) || empty($password)) {
    die("Please enter your username and password.");
}

$stmt = $conn->prepare(
    "SELECT id, username, password, role
     FROM users
     WHERE username = ?"
);

if (!$stmt) {
    die("Database query error: " . $conn->error);
}

$stmt->bind_param("s", $username);
$stmt->execute();

$stmt->bind_result($id, $dbUsername, $dbPassword, $role);

if (!$stmt->fetch()) {
    $stmt->close();
    $conn->close();

    die("Invalid username or password.");
}

$stmt->close();
$conn->close();

// Check the password
if (!password_verify($password, $dbPassword)) {
    die("Invalid username or password.");
}

// Create the login session
$_SESSION["user_id"] = $id;
$_SESSION["username"] = $dbUsername;
$_SESSION["role"] = $role;

// Redirect based on account role
switch ($role) {

    case "admin":
        header("Location: dashboard/admin-dashboard/admin-dashboard.php");
        break;

    case "staff":
        header("Location: dashboard/staff-dashboard/staff-dashboard.php");
        break;

    case "user":
        header("Location: dashboard/user-dashboard/user-dashboard.php");
        break;

    default:
        session_destroy();
        die("Invalid account role.");
}

exit();

?>
