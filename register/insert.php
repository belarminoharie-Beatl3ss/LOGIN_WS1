<?php

require_once "../db.php";

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    die("Invalid request.");
}

$username = trim($_POST["username"] ?? "");
$firstname = trim($_POST["firstname"] ?? "");
$lastname = trim($_POST["lastname"] ?? "");
$age = (int)($_POST["age"] ?? 0);
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

// Check password confirmation
if ($password !== $passwordverify) {
    die("Passwords do not match.");
}

// Check username
$check = $conn->prepare("SELECT id FROM users WHERE username = ?");
$check->bind_param("s", $username);
$check->execute();
$check->store_result();

if ($check->num_rows > 0) {
    $check->close();
    die("Username already exists.");
}

$check->close();

// Hash password
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

// New accounts are regular users by default
$role = "user";

// Insert account
$stmt = $conn->prepare(
    "INSERT INTO users 
    (username, firstname, lastname, age, phonenum, password, role)
    VALUES (?, ?, ?, ?, ?, ?, ?)"
);

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
    echo "Registration successful! You can now log in.";
} else {
    echo "Registration failed: " . $stmt->error;
}

$stmt->close();
$conn->close();

?>