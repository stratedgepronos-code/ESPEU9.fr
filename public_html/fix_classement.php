<?php
error_reporting(E_ALL); ini_set('display_errors',1); require_once 'config.php';
echo "<pre style='font-family:monospace;background:#111;color:#0f0;padding:20px;'>";

$url = 'https://competitions.ffbb.com/ligues/ges/comites/0051/clubs/ges0051011/equipes/200000005162039/classement';
$ch = curl_init($url);
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20, CURLOPT_FOLLOWLOCATION=>true, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_USERAGENT=>'Mozilla/5.0']);
$body = curl_exec($ch); curl_close($ch);

preg_match_all('/<script[^>]*>(.*?)<\/script>/s', $body, $allScripts);
$rscContent = '';
foreach ($allScripts[1] as $sc) {
    if (stripos($sc, 'VITRY') !== false || stripos($sc, 'COURTISOLS') !== false || stripos($sc, 'CORMONTREUIL') !== false) {
        $rscContent = $sc; break;
    }
}
echo "RSC script: " . strlen($rscContent) . " chars\n\n";

// Decode
$decoded = str_replace('\\\\', "\x01", $rscContent);
$decoded = str_replace('\\"', '"', $decoded);
$decoded = str_replace('\\n', "\n", $decoded);
$decoded = str_replace("\x01", '\\', $decoded);

// Find team names with font-bold context
$teamPattern = '/"children"\s*:\s*"([A-Z][A-Z\s\-\'\x{00C0}-\x{024F}]{6,})"/u';
preg_match_all($teamPattern, $decoded, $allNames, PREG_OFFSET_CAPTURE);

$teamEntries = [];
foreach ($allNames[1] as $match) {
    $name = trim($match[0]);
    $offset = $match[1];
    if (strlen($name) < 8) continue;
    if (preg_match('/^(LA |LE |LES |COUPE|NATIONALE|LIGUE|BETCLIC|ELITE|ESPOIR|TROPHEE|FEMININE)/i', $name)) continue;
    
    $before = substr($decoded, max(0, $offset - 500), 500);
    if (stripos($before, 'font-bold') === false) continue;
    
    $after = substr($decoded, $offset + strlen($name), 2000);
    preg_match_all('/"children"\s*:\s*"(\d{1,3})"/u', $after, $nums);
    $values = array_map('intval', $nums[1] ?? []);
    
    $pts = $values[0] ?? 0;
    $played = $values[1] ?? 0;
    $wins = $values[2] ?? 0;
    $losses = $values[3] ?? 0;
    
    echo "Candidat: $name → Pts:$pts J:$played V:$wins D:$losses\n";
    
    if ($pts > 0 && ($wins + $losses) > 0) {
        $teamEntries[] = ['team'=>$name, 'points'=>$pts, 'played'=>$played, 'wins'=>$wins, 'losses'=>$losses];
    }
}

// Dedup + sort
usort($teamEntries, function($a,$b){ return $b['points'] - $a['points']; });
$seen = []; $standings = []; $rank = 1;
foreach ($teamEntries as $e) {
    if (isset($seen[$e['team']])) continue;
    $seen[$e['team']] = true;
    $standings[] = ['rank'=>$rank++, 'team'=>$e['team'], 'points'=>$e['points'], 'played'=>$e['played'], 'wins'=>$e['wins'], 'losses'=>$e['losses']];
}

echo "\n=== CLASSEMENT FINAL ===\n";
foreach ($standings as $s) {
    echo "#" . $s['rank'] . " " . str_pad($s['team'],45) . " Pts:" . $s['points'] . " J:" . $s['played'] . " V:" . $s['wins'] . " D:" . $s['losses'] . "\n";
}
echo "\nTotal: " . count($standings) . " équipes\n";

// INSERT INTO DB
if (!empty($standings)) {
    echo "\n=== INSERTION EN BASE ===\n";
    $db = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME, DB_USER, DB_PASS);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("CREATE TABLE IF NOT EXISTS ffbb_standings (id INT AUTO_INCREMENT PRIMARY KEY, rank_pos INT, team_name VARCHAR(255), points INT, played INT DEFAULT 0, wins INT DEFAULT 0, losses INT DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)");
    $db->exec("DELETE FROM ffbb_standings");
    $stIns = $db->prepare("INSERT INTO ffbb_standings (rank_pos, team_name, points, played, wins, losses) VALUES (:r,:t,:p,:j,:w,:l)");
    foreach ($standings as $s) {
        $stIns->execute([':r'=>$s['rank'], ':t'=>$s['team'], ':p'=>$s['points'], ':j'=>$s['played'], ':w'=>$s['wins'], ':l'=>$s['losses']]);
        echo "✅ Inséré #" . $s['rank'] . " " . $s['team'] . "\n";
    }
    $db->prepare("INSERT INTO site_config (config_key, config_value) VALUES ('ffbb_last_sync', :v) ON DUPLICATE KEY UPDATE config_value = :v2")
        ->execute([':v'=>date('Y-m-d H:i:s'), ':v2'=>date('Y-m-d H:i:s')]);
    echo "\n✅ Classement mis à jour dans la base !\n";
    
    // Verify
    echo "\n=== VÉRIFICATION ===\n";
    $rows = $db->query("SELECT * FROM ffbb_standings ORDER BY rank_pos")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as $r) echo "#" . $r['rank_pos'] . " " . $r['team_name'] . " → " . $r['points'] . "pts\n";
} else {
    echo "\n❌ Aucune équipe trouvée, rien inséré\n";
}

echo "\n\nSUPPRIME CE FICHIER</pre>";
