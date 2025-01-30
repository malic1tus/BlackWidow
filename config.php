<?php
define("API_URL", "http://localhost:8000"); // FastAPI URL

$db_host = "localhost";
$db_user = "root";
$db_pass = "password";
$db_name = "phantomvault";

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    die("Échec de connexion à la base de données : " . $conn->connect_error);
}
?>
