-- ============================================
-- ESPE BASKET U9 — Mise à jour v3 : Espace Membre
-- ============================================
-- Dans phpMyAdmin → Onglet SQL → Colle ceci → Exécuter
-- ============================================

-- Ajouter les colonnes pour lier parent → joueur
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `player_id` INT DEFAULT NULL;
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `parent_type` ENUM('papa', 'maman') DEFAULT NULL;
