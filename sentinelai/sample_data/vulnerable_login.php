<?php
// VULNERABLE PHP LOGIN - For educational/demo purposes only
// This code contains intentional security flaws for SentinelAI demonstration

$host = "localhost";
$username = "root";
$password = "password123";  // Hardcoded credentials - BAD
$db = "users_db";

$conn = mysqli_connect($host, $username, $password, $db);

if (isset($_POST['submit'])) {
    $user = $_POST['username'];  // No sanitization
    $pass = $_POST['password'];  // No sanitization

    // VULNERABLE: Direct string interpolation into SQL - SQL Injection possible
    $query = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    $result = mysqli_query($conn, $query);

    if (mysqli_num_rows($result) > 0) {
        $_SESSION['user'] = $user;
        echo "Welcome " . $_GET['username'];  // XSS vulnerability - reflects input directly
        header("Location: dashboard.php");
    } else {
        echo "Invalid credentials";
    }
}

// VULNERABLE: MD5 for password hashing - cryptographically broken
function hashPassword($password) {
    return md5($password);
}

// VULNERABLE: No CSRF protection on this form
?>
<form method="POST" action="">
    Username: <input type="text" name="username">
    Password: <input type="password" name="password">
    <input type="submit" name="submit" value="Login">
</form>
