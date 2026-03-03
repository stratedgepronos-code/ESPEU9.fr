<?php
$db = new PDO("mysql:host=localhost;dbname=u527192911_espe_u9", "u527192911_espe_admin", "121186Aude-");
$hash = password_hash('EspeAdmin2026!', PASSWORD_DEFAULT);
$st = $db->prepare("UPDATE users SET password_hash = ? WHERE role = 'coach'");
$st->execute([$hash]);
echo $st->rowCount() . " compte(s) mis à jour. Login: admin / EspeAdmin2026!";