<?php
session_start(); 

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "user_database";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Database Connection is failed.". $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405); // Method Not Allowed
    die("The request is not valid.");
}

//processing the input for validation
$username = trim($_POST['username'] ?? '');
$password = trim($_POST['password'] ?? '');
$fullname = trim($_POST['fullname'] ?? '');
$email = trim($_POST['email'] ?? '');
$age = trim($_POST['age'] ?? '');
$department = trim($_POST['department'] ?? '');

//validation on the input
if (empty($username) || empty($password) || empty($fullname) || empty($email) || empty($age) || empty($department)) {
    http_response_code(400);
    die("All fields are required.");
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    die("the email is not valid.");
}

if (!is_numeric($age) || $age <= 0) {
    http_response_code(400);
    die("age must be more than 0");
}

//Password hashing
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

//check if the user , mail were already exist.
$check_user = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
$check_user->bind_param("ss", $username, $email);
$check_user->execute();
$check_user->store_result();

if ($check_user->num_rows > 0) {
    http_response_code(400);
    die("username or email is already exists.");
}


$check_user->close();

//insert the record in db 
$stmt = $conn->prepare("INSERT INTO users (username, password, fullname, email, age, department) VALUES (?, ?, ?, ?, ?, ?)");
$stmt->bind_param("ssssis", $username, $hashed_password, $fullname, $email, $age, $department);

if ($stmt->execute()) {
    echo "user is added successfully";
    header("Location: login.php");      // redirect to the login page.
    exit();
} else {
    http_response_code(500);
    echo "Error occured during signing up." . $stmt->error;
}


$stmt->close();
$conn->close();
?>