<?php
session_start();
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomVault - Connexion</title>
    <link rel="stylesheet" href="public/style.css">
</head>
<body>
    <div class="container">
        <h2>Bienvenue sur PhantomVault</h2>
        <a href="login.php" class="btn">Se connecter</a>
    </div>
</body>
</html>
