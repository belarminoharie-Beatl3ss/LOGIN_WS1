
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

$userId = (int) $_SESSION["user_id"];

// Retrieve the logged-in staff member's information
$stmt = $conn->prepare(
    "SELECT firstname, lastname, username, age, phonenum
     FROM users
     WHERE id = ? AND role = 'staff'"
);

$stmt->bind_param("i", $userId);
$stmt->execute();

$result = $stmt->get_result();
$staff = $result->fetch_assoc();

$stmt->close();

if (!$staff) {
    die("Staff account not found.");
}

// Escape output for safe HTML display
function e($value) {
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        "UTF-8"
    );
}

$username = e($_SESSION["username"] ?? $staff["username"]);

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="staffstyle.css">
    <title>My Profile - Staff</title>

    <style>
        /* Staff Profile */

        .profile-info {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .profile-item {
            background: #f8fafc;
            padding: 15px;
            border: 1px solid #e2e8f0;
            border-radius: 5px;
        }

        .profile-item label {
            display: block;
            font-size: 13px;
            color: #666;
            margin-bottom: 8px;
        }

        .profile-item p {
            font-size: 15px;
            color: #333;
            font-weight: bold;
            overflow-wrap: anywhere;
        }

        .profile-role {
            display: inline-block;
            background: #dbeafe;
            color: #0d3b82;
            padding: 5px 12px;
            border-radius: 5px;
            font-size: 13px;
            font-weight: bold;
        }

        .sidebar a.active {
            background: #0d3b82;
        }

        @media (max-width: 768px) {
            body {
                flex-direction: column;
            }

            .sidebar {
                width: 100%;
                min-height: auto;
            }

            .profile-info {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>

    <!-- Sidebar -->
    <div class="sidebar">

        <h3>Staff Dashboard</h3>

        <p>Welcome, <?php echo $username; ?>!</p>

        <a href="staff-dashboard.php">Home</a>

        <a href="manage-users.php">Manage Users</a>

        <a href="profile-staff.php" class="active">Profile</a>

        <a href="settings-staff.php">Settings</a>

        <a href="../../logout.php">Logout</a>

    </div>

    <!-- Main Content -->
    <div class="contents">

        <div class="box">
            <h1>My Profile</h1>
            <p>View your personal and account information.</p>
        </div>

        <!-- Personal Information -->
        <div class="box">

            <h2>Personal Information</h2>

            <div class="profile-info">

                <div class="profile-item">
                    <label>First Name</label>
                    <p><?php echo e($staff["firstname"]); ?></p>
                </div>

                <div class="profile-item">
                    <label>Last Name</label>
                    <p><?php echo e($staff["lastname"]); ?></p>
                </div>

                <div class="profile-item">
                    <label>Age</label>
                    <p><?php echo e($staff["age"]); ?></p>
                </div>

                <div class="profile-item">
                    <label>Phone Number</label>
                    <p><?php echo e($staff["phonenum"]); ?></p>
                </div>

            </div>

        </div>

        <!-- Account Information -->
        <div class="box">

            <h2>Account Information</h2>

            <div class="profile-info">

                <div class="profile-item">
                    <label>Username</label>
                    <p><?php echo e($staff["username"]); ?></p>
                </div>

                <div class="profile-item">
                    <label>Account ID</label>
                    <p><?php echo $userId; ?></p>
                </div>

                <div class="profile-item">
                    <label>Account Role</label>
                    <p>
                        <span class="profile-role">Staff</span>
                    </p>
                </div>

            </div>

        </div>

    </div>

</body>

</html>

<?php
$conn->close();
?>
