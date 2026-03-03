<?php
/**
 * ESPE BASKET U9 — Configuration base de données
 * Hébergement : Hostinger — espeu9.fr
 * ⚠️ CE FICHIER EST PROTÉGÉ PAR .htaccess — Ne JAMAIS le rendre public
 */

define('DB_HOST', 'localhost');
define('DB_NAME', 'u527192911_espe_u9');
define('DB_USER', 'u527192911_espe_admin');
define('DB_PASS', '121186Aude-');

define('COACH_PIN', '121186');

// ═══ CLÉ API CLAUDE (Anthropic) ═══
define('CLAUDE_API_KEY', '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');

// ═══ SMTP EMAIL ═══
define('SMTP_ENABLED', true);
define('SMTP_HOST', 'smtp.hostinger.com');
define('SMTP_PORT', 587);
define('SMTP_USER', 'noreply@espeu9.fr');
define('SMTP_PASS', 'qx2Z&fSKO^sqjhYD'); // ← Change ici après avoir modifié le mdp sur Hostinger

function getDB() {
    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['error' => 'Erreur serveur']);
        exit;
    }
}
