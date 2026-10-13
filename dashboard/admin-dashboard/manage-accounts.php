<?php

session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: ../../index.html");
    exit();
}

if ($_SESSION["role"] !== "admin") {
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
    $role = $_POST["role"] ?? "";

    if (
        $firstname === "" ||
        $lastname === "" ||
        $age === "" ||
        $phonenum === "" ||
        $username === "" ||
        $password === "" ||
        !in_array($role, ["user", "staff"], true)
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

            
            $hashedPassword = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            
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
                $message = ucfirst($role) .
                    " account created successfully!";
                $messageType = "success";
            } else {
                $message = "Unable to create account. Please check your database fields.";
                $messageType = "error";
            }

            $stmt->close();
        }
    }
}


$accounts = $conn->query(
    "SELECT id, firstname, lastname, username, role
     FROM users
     WHERE role IN ('user', 'staff')
     ORDER BY id DESC"
);

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="adminstyle.css">
    <title>Manage Accounts</title>
</head>

<body>

    <div class="sidebar">
        <h3>Admin Dashboard</h3>

        <p>
            Welcome,
            <?php echo htmlspecialchars($_SESSION["username"]); ?>!
        </p>

        <a href="admin-dashboard.php">Home</a>
        <a href="manage-accounts.php">Manage Accounts</a>
        <a href="#">Profile</a>
        <a href="#">Settings</a>
        <a href="../../logout.php">Logout</a>
    </div>

    <div class="contents">

        <div class="box">
            <h1>Account Management</h1>
            <p>Create new User and Staff accounts here.</p>

            <?php if ($message !== ""): ?>
                <p class="<?php echo htmlspecialchars($messageType); ?>">
                    <?php echo htmlspecialchars($message); ?>
                </p>
            <?php endif; ?>
        </div>

        <div class="box">
            <h2>Create Account</h2>

            <form method="POST" action="manage-accounts.php">

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

                <label>Account Role</label>
                <select name="role" required>
                    <option value="">Select a role</option>
                    <option value="user">User</option>
                    <option value="staff">Staff</option>
                </select>

                <button type="submit">Create Account</button>

            </form>
        </div>

        <div class="box">
            <h2>Existing User and Staff Accounts</h2>

            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Username</th>
                        <th>Role</th>
                    </tr>
                </thead>

                <tbody>
                    <?php if ($accounts && $accounts->num_rows > 0): ?>

                        <?php while ($account = $accounts->fetch_assoc()): ?>
                            <tr>
                                <td>
                                    <?php echo (int)$account["id"]; ?>
                                </td>
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
                                <td>
                                    <?php echo htmlspecialchars(
                                        ucfirst($account["role"])
                                    ); ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>

                    <?php else: ?>
                        <tr>
                            <td colspan="4">No User or Staff accounts found.</td>
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