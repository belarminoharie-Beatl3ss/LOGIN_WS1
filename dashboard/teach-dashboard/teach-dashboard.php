<?php

session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: ../../index.html");
    exit();
}

if ($_SESSION["role"] !== "staff") {
    die("Access denied.");
}

$username = htmlspecialchars($_SESSION["username"]);

?>

<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="staffstyle.css">
    <title>Staff Dashboard</title>
</head>

<body>

    <div class="sidebar">
        <h3>User Dashboard</h3>

        <p>Welcome, <?php echo $username; ?>!</p>

        <a href="#">Home</a>
        <a href="#">Profile</a>
        <a href="#">Settings</a>

        <a href="../../logout.php">Logout</a>
    </div>

    <div class="contents">

        <div class="box">
            <h1>Welcome!</h1>
            <p>You are successfully logged in.</p>
        </div>

        <div class="box">
            <h2>Your Account</h2>
            <p>Username: <?php echo $username; ?></p>
            <p>Role: Staff</p>
        </div>

    </div>

</body>

</html>
