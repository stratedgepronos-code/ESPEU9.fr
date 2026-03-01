-- =============================================
-- ESPE U9 — Migration v4 : Messagerie + Convocations
-- À exécuter dans phpMyAdmin > onglet SQL
-- =============================================

-- 1) Ajouter le champ email aux utilisateurs
ALTER TABLE users ADD COLUMN email VARCHAR(255) DEFAULT NULL AFTER display_name;

-- 2) Table des messages internes
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    subject VARCHAR(255) NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    msg_type ENUM('general','convocation','gouter','lavage') DEFAULT 'general',
    is_read TINYINT(1) DEFAULT 0,
    parent_msg_id INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_recipient (recipient_id),
    INDEX idx_sender (sender_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3) Table des convocations par match
CREATE TABLE IF NOT EXISTS convocations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    match_id VARCHAR(50) NOT NULL,
    player_id INT NOT NULL,
    convoked TINYINT(1) DEFAULT 0,
    gouter TINYINT(1) DEFAULT 0,
    lavage TINYINT(1) DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_conv (match_id, player_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
