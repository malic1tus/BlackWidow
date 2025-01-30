<?php
session_start();
require "config.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link rel="stylesheet" href="public/style.css">
</head>
<body>
    <h2>Bienvenue dans PhantomVault</h2>
    <a href="upload.php" class="btn">Uploader un fichier</a>
    <a href="logout.php" class="btn">Déconnexion</a>
</body>
</html>
