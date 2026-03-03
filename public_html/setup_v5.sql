-- =============================================
-- ESPE U9 — Migration v5 : Matchs & Stats en BDD
-- À exécuter dans phpMyAdmin > onglet SQL
-- =============================================

-- 1) Table des matchs disputés
CREATE TABLE IF NOT EXISTS match_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    journee INT NOT NULL,
    date VARCHAR(20) NOT NULL,
    heure VARCHAR(10) DEFAULT '',
    lieu VARCHAR(100) DEFAULT '',
    dom_ext ENUM('dom','ext') NOT NULL,
    equipe_a_nom VARCHAR(100) NOT NULL,
    equipe_a_short VARCHAR(30) NOT NULL,
    equipe_a_score INT DEFAULT 0,
    equipe_b_nom VARCHAR(100) NOT NULL,
    equipe_b_short VARCHAR(30) NOT NULL,
    equipe_b_score INT DEFAULT 0,
    espe_score INT DEFAULT 0,
    adv_score INT DEFAULT 0,
    win TINYINT(1) DEFAULT 0,
    qt1_a INT DEFAULT 0, qt1_b INT DEFAULT 0,
    qt2_a INT DEFAULT 0, qt2_b INT DEFAULT 0,
    qt3_a INT DEFAULT 0, qt3_b INT DEFAULT 0,
    qt4_a INT DEFAULT 0, qt4_b INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2) Table des stats joueurs par match
--    ON DELETE CASCADE = quand un match est supprimé, ses stats sont auto-supprimées
CREATE TABLE IF NOT EXISTS match_player_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    match_id INT NOT NULL,
    team_type ENUM('espe','adv') NOT NULL,
    num INT NOT NULL,
    nom VARCHAR(100) NOT NULL,
    minutes VARCHAR(10) DEFAULT '00:00',
    pts INT DEFAULT 0,
    tirs INT DEFAULT 0,
    t3 INT DEFAULT 0,
    t2i INT DEFAULT 0,
    t2e INT DEFAULT 0,
    lf INT DEFAULT 0,
    fautes INT DEFAULT 0,
    FOREIGN KEY (match_id) REFERENCES match_results(id) ON DELETE CASCADE,
    INDEX idx_match (match_id),
    INDEX idx_team (match_id, team_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =============================================
-- 3) Migration des 4 matchs existants
-- =============================================

-- Match 1 : J1 — Reims (ext) — 06/12/2025
INSERT INTO match_results (id, journee, date, heure, lieu, dom_ext, equipe_a_nom, equipe_a_short, equipe_a_score, equipe_b_nom, equipe_b_short, equipe_b_score, espe_score, adv_score, win, qt1_a, qt1_b, qt2_a, qt2_b, qt3_a, qt3_b, qt4_a, qt4_b) VALUES
(1, 1, '06/12/2025', '10:30', 'Reims', 'ext', 'Reims Champagne Basket - 2', 'REIMS', 14, 'ESPE Basket Châlons', 'ESPE', 33, 33, 14, 1, 3, 8, 3, 11, 2, 4, 6, 10);

-- Stats ESPE — Match 1
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(1, 'espe', 6, 'HAUTION Malone', '15:06', 2, 1, 0, 1, 0, 0, 0),
(1, 'espe', 8, 'COLLARD Tristan', '15:45', 3, 1, 0, 0, 1, 1, 1),
(1, 'espe', 9, 'HAMM Gaspard', '14:14', 10, 4, 0, 4, 0, 2, 1),
(1, 'espe', 10, 'SLAH Amine', '12:38', 4, 2, 0, 2, 0, 0, 1),
(1, 'espe', 11, 'FRANCART Diego', '11:00', 10, 1, 1, 3, 0, 1, 3),
(1, 'espe', 12, 'DELE Jonas', '10:34', 4, 1, 0, 1, 0, 2, 4),
(1, 'espe', 13, 'FALZON Marceau', '11:18', 0, 0, 0, 0, 0, 0, 0),
(1, 'espe', 14, 'FISCHESSER Robin', '16:16', 0, 0, 0, 0, 0, 0, 1);

-- Stats Adversaire — Match 1
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(1, 'adv', 4, 'JOURNET Sasha', '09:20', 0, 0, 0, 0, 0, 0, 0),
(1, 'adv', 6, 'SAKHO Souleyman', '18:50', 5, 2, 0, 2, 0, 1, 2),
(1, 'adv', 12, 'LUGAND Ilan P.P.', '10:12', 0, 0, 0, 0, 0, 0, 0),
(1, 'adv', 13, 'KOMBRO Ismaël', '16:44', 6, 1, 0, 1, 0, 4, 2),
(1, 'adv', 26, 'DESTOOP A.', '22:57', 0, 0, 0, 0, 0, 0, 1),
(1, 'adv', 35, 'NDIAYE Ousmane', '20:42', 3, 1, 0, 1, 0, 1, 0),
(1, 'adv', 37, 'HAN Alexandre', '04:24', 0, 0, 0, 0, 0, 0, 0);

-- Match 2 : J3 — Courtisols (dom) — 17/01/2026
INSERT INTO match_results (id, journee, date, heure, lieu, dom_ext, equipe_a_nom, equipe_a_short, equipe_a_score, equipe_b_nom, equipe_b_short, equipe_b_score, espe_score, adv_score, win, qt1_a, qt1_b, qt2_a, qt2_b, qt3_a, qt3_b, qt4_a, qt4_b) VALUES
(2, 3, '17/01/2026', '11:45', 'Châlons-en-Champagne', 'dom', 'ESPE Basket Châlons', 'ESPE', 40, 'Avenir Sportif Courtisols', 'COURTISOLS', 2, 40, 2, 1, 4, 0, 12, 0, 16, 0, 8, 2);

-- Stats ESPE — Match 2
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(2, 'espe', 6, 'HAUTION Malone', '16:10', 8, 4, 0, 3, 1, 0, 1),
(2, 'espe', 8, 'COLLARD Tristan', '12:42', 0, 0, 0, 0, 0, 0, 1),
(2, 'espe', 9, 'HAMM Gaspard', '12:49', 12, 6, 0, 6, 0, 0, 0),
(2, 'espe', 10, 'SLAH Amine', '11:48', 4, 2, 0, 2, 0, 0, 1),
(2, 'espe', 11, 'FRANCART Diego', '17:59', 6, 3, 0, 3, 0, 0, 2),
(2, 'espe', 12, 'DELE Jonas', '08:22', 4, 2, 0, 2, 0, 0, 1),
(2, 'espe', 13, 'FALZON Marceau', '11:48', 6, 3, 0, 3, 0, 0, 1),
(2, 'espe', 14, 'FISCHESSER Robin', '08:22', 0, 0, 0, 0, 0, 0, 1);

-- Stats Adversaire — Match 2
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(2, 'adv', 4, 'THINES Alice', '11:50', 0, 0, 0, 0, 0, 0, 0),
(2, 'adv', 10, 'TESSIER Léo-paul', '22:08', 2, 1, 0, 1, 0, 0, 1),
(2, 'adv', 12, 'KLEIN Lyam', '12:07', 0, 0, 0, 0, 0, 0, 0),
(2, 'adv', 13, 'GAMIETTE Axel', '25:00', 0, 0, 0, 0, 0, 0, 1),
(2, 'adv', 14, 'VINGERT Victor', '15:39', 0, 0, 0, 0, 0, 0, 0),
(2, 'adv', 15, 'LALOUETTE Erine', '12:06', 0, 0, 0, 0, 0, 0, 0);

-- Match 3 : J4 — Cormontreuil (dom) — 24/01/2026
INSERT INTO match_results (id, journee, date, heure, lieu, dom_ext, equipe_a_nom, equipe_a_short, equipe_a_score, equipe_b_nom, equipe_b_short, equipe_b_score, espe_score, adv_score, win, qt1_a, qt1_b, qt2_a, qt2_b, qt3_a, qt3_b, qt4_a, qt4_b) VALUES
(3, 4, '24/01/2026', '11:45', 'Châlons-en-Champagne', 'dom', 'ESPE Basket Châlons', 'ESPE', 49, 'Assoc. Cormontreuil', 'CORMONTREUIL', 4, 49, 4, 1, 14, 3, 14, 0, 10, 0, 11, 1);

-- Stats ESPE — Match 3
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(3, 'espe', 6, 'HAUTION Malone', '07:04', 2, 1, 0, 1, 0, 0, 1),
(3, 'espe', 8, 'COLLARD Tristan', '14:23', 4, 2, 0, 0, 2, 0, 1),
(3, 'espe', 9, 'HAMM Gaspard', '17:13', 11, 5, 0, 1, 4, 1, 1),
(3, 'espe', 10, 'SLAH Amine', '12:17', 4, 2, 0, 2, 0, 0, 3),
(3, 'espe', 11, 'FRANCART Diego', '12:57', 14, 7, 0, 5, 2, 0, 1),
(3, 'espe', 12, 'DELE Jonas', '15:53', 8, 4, 0, 2, 2, 0, 2),
(3, 'espe', 13, 'FALZON Marceau', '09:59', 2, 1, 0, 1, 0, 0, 0),
(3, 'espe', 14, 'FISCHESSER Robin', '10:14', 4, 2, 0, 2, 0, 0, 0);

-- Stats Adversaire — Match 3
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(3, 'adv', 5, 'FASSOTTE Juan', '08:53', 1, 0, 0, 0, 0, 1, 1),
(3, 'adv', 7, 'BOMKE Joshua', '12:07', 0, 0, 0, 0, 0, 0, 1),
(3, 'adv', 8, 'AYALP Nolan', '16:35', 0, 0, 0, 0, 0, 0, 0),
(3, 'adv', 9, 'LORIC Arone', '05:57', 0, 0, 0, 0, 0, 0, 1),
(3, 'adv', 10, 'TEIXEIRA F. Léon', '08:37', 1, 0, 0, 0, 0, 1, 1),
(3, 'adv', 11, 'BILLET Louison', '15:23', 0, 0, 0, 0, 0, 0, 0),
(3, 'adv', 12, 'BILLET Leo', '14:21', 0, 0, 0, 0, 0, 0, 0),
(3, 'adv', 14, 'BERNARD Mathis', '18:26', 2, 1, 0, 1, 0, 0, 1);

-- Match 4 : J5 — Vitry (ext) — 31/01/2026
INSERT INTO match_results (id, journee, date, heure, lieu, dom_ext, equipe_a_nom, equipe_a_short, equipe_a_score, equipe_b_nom, equipe_b_short, equipe_b_score, espe_score, adv_score, win, qt1_a, qt1_b, qt2_a, qt2_b, qt3_a, qt3_b, qt4_a, qt4_b) VALUES
(4, 5, '31/01/2026', '11:00', 'Vitry-le-François', 'ext', 'Gauloise de Vitry', 'VITRY', 33, 'ESPE Basket Châlons', 'ESPE', 22, 22, 33, 0, 8, 6, 11, 6, 10, 5, 4, 5);

-- Stats ESPE — Match 4
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(4, 'espe', 6, 'HAUTION Malone', '13:19', 0, 0, 0, 0, 0, 0, 1),
(4, 'espe', 8, 'COLLARD Tristan', '05:00', 0, 0, 0, 0, 0, 0, 4),
(4, 'espe', 9, 'HAMM Gaspard', '16:28', 6, 3, 0, 3, 0, 0, 0),
(4, 'espe', 10, 'SLAH Amine', '11:19', 2, 1, 0, 1, 0, 0, 1),
(4, 'espe', 11, 'FRANCART Diego', '18:26', 12, 5, 0, 5, 0, 2, 0),
(4, 'espe', 12, 'DELE Jonas', '09:13', 2, 1, 0, 1, 0, 0, 1),
(4, 'espe', 13, 'FALZON Marceau', '09:20', 0, 0, 0, 0, 0, 0, 0),
(4, 'espe', 14, 'FISCHESSER Robin', '12:55', 0, 0, 0, 0, 0, 0, 3);

-- Stats Adversaire — Match 4
INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES
(4, 'adv', 5, 'TEBAI Noam', '12:12', 0, 0, 0, 0, 0, 0, 0),
(4, 'adv', 7, 'SANTIN Charli', '17:04', 14, 7, 0, 7, 0, 0, 3),
(4, 'adv', 8, 'FORMET Benoît', '13:12', 8, 4, 0, 3, 1, 0, 3),
(4, 'adv', 9, 'BENICY Maël', '16:37', 2, 1, 0, 1, 0, 0, 1),
(4, 'adv', 10, 'MARTY Liam', '13:21', 2, 1, 0, 1, 0, 0, 3),
(4, 'adv', 11, 'MATHIEU K. Dialy', '04:13', 0, 0, 0, 0, 0, 0, 1),
(4, 'adv', 12, 'AIME Loris', '07:47', 2, 1, 0, 1, 0, 0, 0),
(4, 'adv', 14, 'DEBOVE-NOËL Enaël', '11:05', 5, 2, 0, 2, 0, 1, 0);

-- Réinitialiser l'auto-increment pour les futurs matchs
ALTER TABLE match_results AUTO_INCREMENT = 5;

-- =============================================
-- 4) Réponses présence/absence aux convocations
-- =============================================
CREATE TABLE IF NOT EXISTS convocation_responses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    match_id INT NOT NULL,
    player_id INT NOT NULL,
    user_id INT NOT NULL,
    response ENUM('present','absent') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_response (match_id, player_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5) Lier les messages de convocation au match correspondant
ALTER TABLE messages ADD COLUMN related_match_id INT DEFAULT NULL;
