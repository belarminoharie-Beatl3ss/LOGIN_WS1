<?php

session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: ../../index.html");
    exit();
}

if ($_SESSION["role"] !== "user") {
    die("Access denied.");
}

$user_id = $_SESSION["user_id"];


require_once "../../db.php";


$user_stmt = $conn->prepare("
    SELECT username, firstname, lastname
    FROM users
    WHERE id = ?
");

$user_stmt->bind_param("i", $user_id);
$user_stmt->execute();

$user_result = $user_stmt->get_result();
$user = $user_result->fetch_assoc();

if (!$user) {
    die("User account not found.");
}

$username = htmlspecialchars($user["username"]);
$firstname = htmlspecialchars($user["firstname"]);
$lastname = htmlspecialchars($user["lastname"]);


$grade_stmt = $conn->prepare("
    SELECT subject, grade, semester, school_year
    FROM grades
    WHERE user_id = ?
    ORDER BY school_year DESC, semester ASC, subject ASC
");

$grade_stmt->bind_param("i", $user_id);
$grade_stmt->execute();

$grades = $grade_stmt->get_result();

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="userstyle.css">
    <title>Student Dashboard</title>
</head>
<body>
    <div class="sidebar">
        <h3>Student Dashboard</h3>
        <p>
            Welcome,
            <?php echo $firstname . " " . $lastname; ?>!
        </p>
        <a href="#">Home</a>
        <a href="#">Profile</a>
        <a href="#">Settings</a>
        <a href="../../logout.php">Logout</a>
    </div>
    <div class="contents">
        <div class="box">
            <h1>
                Welcome,
                <?php echo $firstname . " " . $lastname; ?>!
            </h1>
            <p>You are successfully logged in.</p>
        </div>
        <div class="box">
            <h2>Your Account</h2>
            <p>
                <strong>Name:</strong>
                <?php echo $firstname . " " . $lastname; ?>
            </p>
            <p>
                <strong>Username:</strong>
                <?php echo $username; ?>
            </p>
            <p>
                <strong>Role:</strong>
                Student
            </p>
        </div>
        <div class="box">
            <h2>Your Grades</h2>
            <?php if ($grades->num_rows > 0): ?>
                <table border="1" cellpadding="10" cellspacing="0">
                    <thead>
                        <tr>
                            <th>Subject</th>
                            <th>Grade</th>
                            <th>Semester</th>
                            <th>School Year</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = $grades->fetch_assoc()): ?>
                            <tr>
                                <td>
                                    <?php echo htmlspecialchars($row["subject"]); ?>
                                </td>
                                <td>
                                    <?php echo htmlspecialchars($row["grade"]); ?>
                                </td>
                                <td>
                                    <?php echo htmlspecialchars($row["semester"]); ?>
                                </td>
                                <td>
                                    <?php echo htmlspecialchars($row["school_year"]); ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p>No grades available yet.</p>
            <?php endif; ?>
        </div>
    </div>
    <?php
    $user_stmt->close();
    $grade_stmt->close();
    $conn->close();
    ?>
</body>
</html>
