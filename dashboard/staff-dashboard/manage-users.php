<?php

session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: ../../index.html");
    exit();
}

if ($_SESSION["role"] !== "staff") {
    die("Access denied.");
}

require_once "../../db.php";

$message = "";
$messageType = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $firstname = trim($_POST["firstname"] ?? "");
    $lastname = trim($_POST["lastname"] ?? "");
    $age = trim($_POST["age"] ?? "");
    $phonenum = trim($_POST["phonenum"] ?? "");
    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    if (
        $firstname === "" ||
        $lastname === "" ||
        $age === "" ||
        $phonenum === "" ||
        $username === "" ||
        $password === ""
    ) {
        $message = "Please complete all fields.";
        $messageType = "error";

    } elseif (!ctype_digit($age) || (int)$age < 1 || (int)$age > 120) {
        $message = "Please enter a valid age.";
        $messageType = "error";

    } elseif (strlen($password) < 8) {
        $message = "Password must contain at least 8 characters.";
        $messageType = "error";

    } else {

        // Check for duplicate usernames
        $stmt = $conn->prepare(
            "SELECT id FROM users WHERE username = ?"
        );

        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $message = "That username is already taken.";
            $messageType = "error";
            $stmt->close();

        } else {
            $stmt->close();

            // Hash the password
            $hashedPassword = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            // Always create a regular User account
            $role = "user";

            $stmt = $conn->prepare(
                "INSERT INTO users
                (username, firstname, lastname, age, phonenum, password, role)
                VALUES (?, ?, ?, ?, ?, ?, ?)"
            );

            $ageValue = (int)$age;

            $stmt->bind_param(
                "sssisss",
                $username,
                $firstname,
                $lastname,
                $ageValue,
                $phonenum,
                $hashedPassword,
                $role
            );

            if ($stmt->execute()) {
                $message = "User account created successfully!";
                $messageType = "success";
            } else {
                $message = "Unable to create the account. Please check your database.";
                $messageType = "error";
            }

            $stmt->close();
        }
    }
}

// Retrieve regular User accounts only
$accounts = $conn->query(
    "SELECT id, firstname, lastname, username, age, phonenum
     FROM users
     WHERE role = 'user'
     ORDER BY id DESC"
);

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="staffstyle.css">
    <title>Manage Users</title>
</head>

<body>

    <div class="sidebar">
        <h3>Staff Dashboard</h3>

        <p>
            Welcome,
            <?php echo htmlspecialchars($_SESSION["username"]); ?>!
        </p>

        <a href="staff-dashboard.php">Home</a>
        <a href="manage-users.php">Manage Users</a>
        <a href="profile-staff.php">Profile</a>
        <a href="settings-staff.php">Settings</a>
        <a href="../../logout.php">Logout</a>
    </div>

    <div class="contents">

        <div class="box">
            <h1>Manage Users</h1>
            <p>View existing User accounts or register a new one.</p>

            <?php if ($message !== ""): ?>
                <p class="<?php echo htmlspecialchars($messageType); ?>">
                    <?php echo htmlspecialchars($message); ?>
                </p>
            <?php endif; ?>
        </div>

        <div class="box">
            <h2>Add New User</h2>

            <form method="POST" action="manage-users.php">

                <label>First Name</label>
                <input type="text" name="firstname" required>

                <label>Last Name</label>
                <input type="text" name="lastname" required>

                <label>Age</label>
                <input type="number" name="age" min="1" max="120" required>

                <label>Phone Number</label>
                <input type="text" name="phonenum" required>

                <label>Username</label>
                <input type="text" name="username" required>

                <label>Password</label>
                <input type="password" name="password"
                       minlength="8" required>

                <button type="submit">Create User Account</button>

            </form>
        </div>

        <div class="box">
            <h2>Existing Users</h2>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Username</th>
                        <th>Age</th>
                        <th>Phone Number</th>
                    </tr>
                </thead>

                <tbody>
                    <?php if ($accounts && $accounts->num_rows > 0): ?>

                        <?php while ($account = $accounts->fetch_assoc()): ?>
                            <tr>
                                <td><?php echo (int)$account["id"]; ?></td>

                                <td>
                                    <?php echo htmlspecialchars(
                                        $account["firstname"] . " " .
                                        $account["lastname"]
                                    ); ?>
                                </td>

                                <td>
                                    <?php echo htmlspecialchars(
                                        $account["username"]
                                    ); ?>
                                </td>

                                <td><?php echo (int)$account["age"]; ?></td>

                                <td>
                                    <?php echo htmlspecialchars(
                                        $account["phonenum"]
                                    ); ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>

                    <?php else: ?>

                        <tr>
                            <td colspan="5">No User accounts found.</td>
                        </tr>

                    <?php endif; ?>
                </tbody>
            </table>
        </div>

    </div>

</body>

</html>

<?php
$conn->close();
?>