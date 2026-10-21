
<?php

session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: ../../index.html");
    exit();
}

if (($_SESSION["role"] ?? "") !== "staff") {
    die("Access denied.");
}

require_once "../../db.php";

$message = "";
$messageType = "";

$userId = (int) $_SESSION["user_id"];

function e($value) {
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        "UTF-8"
    );
}

$username = e($_SESSION["username"] ?? "Staff");

// Process password change
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $currentPassword = $_POST["current_password"] ?? "";
    $newPassword = $_POST["new_password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if (
        $currentPassword === "" ||
        $newPassword === "" ||
        $confirmPassword === ""
    ) {
        $message = "Please complete all fields.";
        $messageType = "error";

    } elseif (strlen($newPassword) < 8) {
        $message = "New password must be new";
        $messageType = "error";

    } elseif ($newPassword !== $confirmPassword) {
        $message = "New passwords do not match.";
        $messageType = "error";

    } else {

        // Retrieve the current password hash
        $stmt = $conn->prepare(
            "SELECT password
             FROM users
             WHERE id = ? AND role = 'staff'"
        );

        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stmt->bind_result($hashedPassword);

        if ($stmt->fetch()) {
            $stmt->close();

            // Verify the current password
            if (!password_verify($currentPassword, $hashedPassword)) {

                $message = "Current password is incorrect.";
                $messageType = "error";

            } elseif (password_verify($newPassword, $hashedPassword)) {

                $message = "Your new password must be different from your current password.";
                $messageType = "error";

            } else {

                // Hash the new password
                $newHashedPassword = password_hash(
                    $newPassword,
                    PASSWORD_DEFAULT
                );

                // Update the password in the database
                $update = $conn->prepare(
                    "UPDATE users
                     SET password = ?
                     WHERE id = ? AND role = 'staff'"
                );

                $update->bind_param(
                    "si",
                    $newHashedPassword,
                    $userId
                );

                if ($update->execute() && $update->affected_rows === 1) {
                    $message = "Password changed successfully!";
                    $messageType = "success";
                } else {
                    $message = "Unable to update password. Please try again.";
                    $messageType = "error";
                }

                $update->close();
            }

        } else {
            $stmt->close();

            $message = "Staff account not found.";
            $messageType = "error";
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link rel="stylesheet" href="staffstyle.css">

    <title>Staff Settings</title>
</head>

<body>

    <!-- Sidebar -->
    <div class="sidebar">

        <h3>Staff Dashboard</h3>

        <p>Welcome, <?php echo $username; ?>!</p>

        <a href="staff-dashboard.php">Home</a>

        <a href="manage-users.php">Manage Users</a>

        <a href="profile-staff.php">Profile</a>

        <a href="settings-staff.php" class="active">Settings</a>

        <a href="../../logout.php">Logout</a>

    </div>

    <!-- Main Content -->
    <div class="contents">

        <div class="box">
            <h1>Settings</h1>
            <p>Manage your account password and security.</p>
        </div>

        <div class="box">

            <h2>Change Password</h2>

            <p>
                Enter your current password and choose a new password.
            </p>

            <?php if ($message !== ""): ?>
                <p class="<?php echo e($messageType); ?>">
                    <?php echo e($message); ?>
                </p>
            <?php endif; ?>

            <form method="POST" action="settings-staff.php">

                <label for="current_password">
                    Current Password
                </label>

                <input
                    type="password"
                    id="current_password"
                    name="current_password"
                    autocomplete="current-password"
                    required
                >

                <label for="new_password">
                    New Password
                </label>

                <input
                    type="password"
                    id="new_password"
                    name="new_password"
                    minlength="8"
                    autocomplete="new-password"
                    required
                >

                <label for="confirm_password">
                    Confirm New Password
                </label>

                <input
                    type="password"
                    id="confirm_password"
                    name="confirm_password"
                    minlength="8"
                    autocomplete="new-password"
                    required
                >

                <button type="submit">
                    Update Password
                </button>

            </form>

        </div>

    </div>

</body>

</html>

<?php
$conn->close();
?>
