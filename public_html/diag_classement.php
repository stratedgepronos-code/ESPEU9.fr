<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'config.php';

echo "<pre style='font-family:monospace;background:#111;color:#0f0;padding:20px;'>";
echo "=== DIAGNOSTIC CLASSEMENT ===\n\n";

$db = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME, DB_USER, DB_PASS);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// 1. Check ffbb_standings table
echo "--- Table ffbb_standings ---\n";
$r = $db->query("SHOW TABLES LIKE 'ffbb_standings'")->fetch();
if (!$r) { echo "❌ Table ffbb_standings N'EXISTE PAS\n"; }
else {
    $rows = $db->query("SELECT * FROM ffbb_standings ORDER BY rank_pos ASC")->fetchAll(PDO::FETCH_ASSOC);
    echo "✅ Table existe — " . count($rows) . " lignes\n";
    foreach ($rows as $row) {
        echo "  #" . $row['rank_pos'] . " " . str_pad($row['team_name'], 40) . " Pts:" . $row['points'] . " V:" . $row['wins'] . " D:" . $row['losses'] . "\n";
    }
    if (empty($rows)) echo "  ⚠️ TABLE VIDE — le classement affiché vient du code hardcodé\n";
}

// 2. Check FFBB URL config
echo "\n--- Config FFBB ---\n";
$r2 = $db->query("SHOW TABLES LIKE 'site_config'")->fetch();
if ($r2) {
    $st = $db->query("SELECT config_key, config_value FROM site_config WHERE config_key LIKE 'ffbb%' ORDER BY config_key");
    $configs = $st->fetchAll(PDO::FETCH_ASSOC);
    if (empty($configs)) echo "⚠️ Aucune config FFBB trouvée\n";
    foreach ($configs as $c) {
        echo "  " . $c['config_key'] . " = " . $c['config_value'] . "\n";
    }
} else { echo "❌ Table site_config n'existe pas\n"; }

// 3. Test live sync
echo "\n--- Test sync FFBB ---\n";
$st = $db->prepare("SELECT config_value FROM site_config WHERE config_key = 'ffbb_url'");
$st->execute();
$r3 = $st->fetch();
$ffbbUrl = $r3 ? $r3['config_value'] : '';
if (!$ffbbUrl) {
    echo "❌ URL FFBB non configurée — impossible de sync\n";
} else {
    echo "URL: $ffbbUrl\n";
    $ch = curl_init($ffbbUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    $finalUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    
    echo "HTTP: $code | Final URL: $finalUrl\n";
    if ($err) echo "❌ Curl error: $err\n";
    echo "Body length: " . strlen($body) . " chars\n";
    
    // Try parse standings
    $standings = [];
    
    // Method 1: links with href equipes
    if (preg_match_all('/<a[^>]*href="[^"]*equipes\/\d+"[^>]*>\s*(\d+)\s*([^<]+?)\s*(\d{1,3})\s*<\/a>/u', $body, $standM, PREG_SET_ORDER)) {
        echo "✅ Méthode 1 (liens equipes) : " . count($standM) . " lignes trouvées\n";
        foreach ($standM as $s) {
            $standings[] = ['rank' => (int)$s[1], 'team' => trim($s[2]), 'points' => (int)$s[3]];
        }
    } else {
        echo "⚠️ Méthode 1 (liens equipes) : 0 résultat\n";
    }
    
    // Method 2: __next_f.push
    if (empty($standings)) {
        $chunks = '';
        if (preg_match_all('/self\.__next_f\.push\(\[\d+,"((?:[^"\\\\]|\\\\.)*)"\]\)/s', $body, $chunkM)) {
            foreach ($chunkM[1] as $c) $chunks .= stripcslashes($c);
        }
        echo "Next.js chunks length: " . strlen($chunks) . "\n";
        
        if (preg_match('/"classement"\s*:\s*\[/su', $chunks)) {
            echo "✅ Trouvé 'classement' dans les chunks Next.js\n";
            if (preg_match('/"classement"\s*:\s*(\[.+?\])/su', $chunks, $cMatch)) {
                $arr = json_decode($cMatch[1], true);
                if ($arr) {
                    echo "✅ JSON décodé : " . count($arr) . " équipes\n";
                    foreach ($arr as $row) {
                        echo "  " . json_encode($row, JSON_UNESCAPED_UNICODE) . "\n";
                    }
                } else {
                    echo "❌ JSON invalide. Extrait: " . substr($cMatch[1], 0, 300) . "\n";
                }
            }
        } else {
            echo "⚠️ 'classement' non trouvé dans chunks Next.js\n";
        }
        
        // Show snippet of chunks for debug
        if ($chunks) {
            $pos = stripos($chunks, 'class');
            if ($pos !== false) {
                echo "Extrait chunks autour de 'class': " . substr($chunks, max(0,$pos-50), 300) . "\n";
            }
        }
    }
    
    // Method 3: fallback regex
    if (empty($standings)) {
        if (preg_match_all('/>(\d+)([A-Z\x{00C0}-\x{024F}][A-Z\x{00C0}-\x{024F}\s\-\'\.\d]+?)(\d{1,3})<\/(?:div|a|span)>/u', $body, $standM, PREG_SET_ORDER)) {
            echo "✅ Méthode 3 (fallback) : " . count($standM) . " lignes\n";
            foreach ($standM as $s) {
                $standings[] = ['rank' => (int)$s[1], 'team' => trim($s[2]), 'points' => (int)$s[3]];
            }
        } else {
            echo "⚠️ Méthode 3 (fallback) : 0 résultat\n";
        }
    }
    
    echo "\n--- Résultat final ---\n";
    if (!empty($standings)) {
        echo "✅ " . count($standings) . " équipes trouvées :\n";
        foreach ($standings as $s) {
            echo "  #" . $s['rank'] . " " . str_pad($s['team'], 40) . " " . $s['points'] . " pts\n";
        }
    } else {
        echo "❌ AUCUN CLASSEMENT TROUVÉ — le scraper ne fonctionne plus\n";
        echo "La FFBB a probablement changé le format de sa page.\n";
        echo "\nExtrait HTML (2000 chars) pour debug :\n";
        echo htmlspecialchars(substr($body, 0, 2000)) . "\n";
    }
    
    // Also try classement URL
    echo "\n--- Test URL classement dédiée ---\n";
    // Try /classement suffix
    $classUrl = rtrim($ffbbUrl, '/') . '/classement';
    echo "Test: $classUrl\n";
    $ch2 = curl_init($classUrl);
    curl_setopt_array($ch2, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => true, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_USERAGENT => 'Mozilla/5.0']);
    $body2 = curl_exec($ch2);
    $code2 = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
    curl_close($ch2);
    echo "HTTP: $code2 | Body: " . strlen($body2) . " chars\n";
}

echo "\n⚠️ SUPPRIME CE FICHIER APRÈS USAGE ⚠️\n</pre>";
