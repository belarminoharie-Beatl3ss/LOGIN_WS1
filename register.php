<?php

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once "db.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: register/register.html");
    exit();
}

// Get form data
$username = trim($_POST["username"] ?? "");
$firstname = trim($_POST["firstname"] ?? "");
$lastname = trim($_POST["lastname"] ?? "");
$age = $_POST["age"] ?? "";
$phonenum = trim($_POST["phonenum"] ?? "");
$password = $_POST["password"] ?? "";
$passwordverify = $_POST["passwordverify"] ?? "";

// Check required fields
if (
    empty($username) ||
    empty($firstname) ||
    empty($lastname) ||
    empty($age) ||
    empty($password) ||
    empty($passwordverify)
) {
    die("Please fill in all required fields.");
}

// Check passwords match
if ($password !== $passwordverify) {
    die("Passwords do not match.");
}

// Check username already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");

if (!$stmt) {
    die("Database query error: " . $conn->error);
}

$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    $stmt->close();
    $conn->close();

    die("Username already exists.");
}

$stmt->close();

// Hash password
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

// users by default
$role = "user";

// Insert user into database
$stmt = $conn->prepare(
    "INSERT INTO users
    (username, firstname, lastname, age, phonenum, password, role)
    VALUES (?, ?, ?, ?, ?, ?, ?)"
);

if (!$stmt) {
    die("Database query error: " . $conn->error);
}

$stmt->bind_param(
    "sssisss",
    $username,
    $firstname,
    $lastname,
    $age,
    $phonenum,
    $hashedPassword,
    $role
);

if ($stmt->execute()) {

    $stmt->close();
    $conn->close();

    header("Location: index.html");
    exit();

} else {

    die("Registration failed: " . $stmt->error);

}

?>