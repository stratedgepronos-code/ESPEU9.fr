<?php
error_reporting(E_ALL); ini_set('display_errors',1); require_once 'config.php';
echo "<pre style='font-family:monospace;background:#111;color:#0f0;padding:20px;'>";
echo "=== FIX CLASSEMENT FFBB ===\n\n";

function ffbb_fetch($url) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>25, CURLOPT_FOLLOWLOCATION=>true, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_USERAGENT=>'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']);
    $body = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return ['body'=>$body?:'', 'code'=>$code];
}

function ffbb_decode_rsc($raw) {
    $d = str_replace('\\\\', "\x01", $raw);
    $d = str_replace('\\"', '"', $d);
    $d = str_replace('\\n', "\n", $d);
    $d = str_replace('\\t', "\t", $d);
    $d = str_replace("\x01", '\\', $d);
    return $d;
}

function ffbb_parse_all($html) {
    $results = [];
    preg_match_all('/<script[^>]*>(.*?)<\/script>/s', $html, $scripts);
    
    // Find the right script - must contain team data (td elements with team names)
    $target = '';
    foreach ($scripts[1] as $sc) {
        if ((stripos($sc, 'VITRY') !== false || stripos($sc, 'COURTISOLS') !== false || stripos($sc, 'CORMONTREUIL') !== false) && strlen($sc) > 5000) {
            $target = $sc; break;
        }
    }
    // Fallback: biggest script with td + font-bold
    if (!$target) {
        $biggest = ''; $bigLen = 0;
        foreach ($scripts[1] as $sc) {
            if (strlen($sc) > $bigLen && stripos($sc, '"td"') !== false && stripos($sc, 'font-bold') !== false) {
                $biggest = $sc; $bigLen = strlen($sc);
            }
        }
        $target = $biggest;
    }
    if (!$target) return $results;
    
    $d = ffbb_decode_rsc($target);
    
    // STRATEGY: Find team name + stats blocks
    // In RSC classement table, each row has:
    //   td with link containing div with font-bold team name
    //   followed by multiple td cells with numeric children
    //
    // But ESPE's row may use different styling (highlighted)
    // So we use TWO approaches:
    
    // Approach A: font-bold children (works for most teams)
    // Approach B: find ALL uppercase strings that look like club names
    //             then check if followed by numeric td cells
    
    $candidates = [];
    
    // Approach A: font-bold pattern
    if (preg_match_all('/font-bold[^}]*?"children"\s*:\s*"([A-Z][A-Z\s\-\'\x{00C0}-\x{024F}]{6,}?)"/u', $d, $mA, PREG_OFFSET_CAPTURE)) {
        foreach ($mA[1] as $m) {
            $name = trim($m[0]); $off = $m[1];
            if (strlen($name) < 8) continue;
            if (preg_match('/^(L\'ACT|VOIR|DÉCOUV|COUPE|NATIONALE|LIGUE|BETCLIC|ELITE|ESPOIR|TROPHEE|FEMININE)/i', $name)) continue;
            $candidates[] = ['name'=>$name, 'offset'=>$off, 'method'=>'A'];
        }
    }
    
    // Approach B: ALL uppercase names > 15 chars containing BASKET/ESPE/CHAMPAGNE etc
    if (preg_match_all('/"children"\s*:\s*"((?:[A-Z\x{00C0}-\x{024F}][\sA-Z\x{00C0}-\x{024F}\-\']{10,}))"/u', $d, $mB, PREG_OFFSET_CAPTURE)) {
        foreach ($mB[1] as $m) {
            $name = trim($m[0]); $off = $m[1];
            // Must look like a basketball club
            if (!preg_match('/BASKET|ESPE|CHALONS|VITRY|COURTISOLS|CORMONTREUIL|REIMS|GAULOISE|AVENIR|ASSOCIATION|CHAMPAGNE/i', $name)) continue;
            // Skip if already found by approach A
            $already = false;
            foreach ($candidates as $c) { if ($c['name'] === $name) { $already = true; break; } }
            if (!$already) $candidates[] = ['name'=>$name, 'offset'=>$off, 'method'=>'B'];
        }
    }
    
    echo "  Candidats trouvés: " . count($candidates) . "\n";
    
    foreach ($candidates as &$c) {
        $after = substr($d, $c['offset'] + strlen($c['name']), 3000);
        // Extract numeric "children" values from following td cells
        // Pattern: "children":"N" where N is 1-3 digits
        preg_match_all('/"children"\s*:\s*"(\d{1,3})"/u', $after, $nums);
        $vals = array_map('intval', $nums[1] ?? []);
        
        // Filter: check for at least 3 numbers and stop at next team name
        $nextTeamPos = PHP_INT_MAX;
        if (preg_match('/font-bold[^}]*?"children"\s*:\s*"[A-Z]/u', $after, $nt, PREG_OFFSET_CAPTURE)) {
            $nextTeamPos = $nt[0][1];
        }
        // Only keep numbers that appear before the next team
        $filteredVals = [];
        foreach ($nums[0] as $i => $fullMatch) {
            $matchPos = strpos($after, $fullMatch);
            if ($matchPos !== false && $matchPos < $nextTeamPos) {
                $filteredVals[] = $vals[$i];
            }
        }
        
        $c['values'] = $filteredVals;
        $c['pts'] = $filteredVals[0] ?? 0;
        $c['played'] = $filteredVals[1] ?? 0;
        $c['wins'] = $filteredVals[2] ?? 0;
        $c['losses'] = $filteredVals[3] ?? 0;
        
        echo "  [{$c['method']}] {$c['name']} → Pts:{$c['pts']} J:{$c['played']} V:{$c['wins']} D:{$c['losses']} (raw: " . implode(',', array_slice($filteredVals, 0, 8)) . ")\n";
    }
    
    // Build standings: dedup, filter valid, sort by pts
    $valid = [];
    foreach ($candidates as $c) {
        if ($c['pts'] > 0 && ($c['wins'] + $c['losses']) > 0) {
            $valid[] = $c;
        }
    }
    usort($valid, function($a,$b){ return $b['pts'] - $a['pts']; });
    $seen = []; $rank = 1;
    foreach ($valid as $v) {
        if (isset($seen[$v['name']])) continue;
        $seen[$v['name']] = true;
        $results[] = ['rank'=>$rank++, 'team'=>$v['name'], 'points'=>$v['pts'], 'played'=>$v['played'], 'wins'=>$v['wins'], 'losses'=>$v['losses']];
    }
    
    return $results;
}

// ===== TRY URLS =====
$urls = [
    'Compétition classement' => 'https://competitions.ffbb.com/ligues/ges/comites/0051/competitions/dxu9/classement?poule=200000003020811&phase=200000002873963',
    'Équipe classement' => 'https://competitions.ffbb.com/ligues/ges/comites/0051/clubs/ges0051011/equipes/200000005162039/classement',
];

$best = [];
foreach ($urls as $label => $url) {
    echo "\n--- $label ---\n$url\n";
    $res = ffbb_fetch($url);
    echo "HTTP {$res['code']} | " . strlen($res['body']) . " chars\n";
    if ($res['code'] !== 200) { echo "SKIP\n"; continue; }
    
    $standings = ffbb_parse_all($res['body']);
    echo "→ " . count($standings) . " équipes extraites\n";
    foreach ($standings as $s) {
        echo "  #" . $s['rank'] . " " . str_pad($s['team'],45) . " {$s['points']}pts V:{$s['wins']} D:{$s['losses']}\n";
    }
    if (count($standings) > count($best)) $best = $standings;
}

// ===== IF STILL NOT ENOUGH, USE KNOWN DATA =====
if (count($best) < 3) {
    echo "\n⚠️ Scraper insuffisant (" . count($best) . " équipes). Utilisation données connues.\n";
    $best = [
        ['rank'=>1, 'team'=>'GAULOISE DE VITRY LE FRANCOIS', 'points'=>14, 'played'=>7, 'wins'=>7, 'losses'=>0],
        ['rank'=>2, 'team'=>'ESPE BASKET CHALONS EN CHAMPAGNE', 'points'=>11, 'played'=>7, 'wins'=>4, 'losses'=>3],
        ['rank'=>3, 'team'=>'REIMS CHAMPAGNE BASKET - 2', 'points'=>10, 'played'=>7, 'wins'=>3, 'losses'=>4],
        ['rank'=>4, 'team'=>'AVENIR SPORTIF COURTISOLS BASKET', 'points'=>9, 'played'=>7, 'wins'=>2, 'losses'=>5],
        ['rank'=>5, 'team'=>'ASSOCIATION CORMONTREUIL CHAMPAGNE BASKET', 'points'=>8, 'played'=>8, 'wins'=>0, 'losses'=>8],
    ];
    echo "⚠️ Données ESPE/REIMS approximatives — corrige via phpMyAdmin si besoin.\n";
}

// ===== INSERT =====
echo "\n=== INSERTION EN BASE ===\n";
$db = new PDO("mysql:host=".DB_HOST.";dbname=".DB_NAME, DB_USER, DB_PASS);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec("CREATE TABLE IF NOT EXISTS ffbb_standings (id INT AUTO_INCREMENT PRIMARY KEY, rank_pos INT, team_name VARCHAR(255), points INT, played INT DEFAULT 0, wins INT DEFAULT 0, losses INT DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)");
try { $db->exec("ALTER TABLE ffbb_standings ADD COLUMN played INT DEFAULT 0, ADD COLUMN wins INT DEFAULT 0, ADD COLUMN losses INT DEFAULT 0"); } catch(Exception $e) {}

$db->exec("DELETE FROM ffbb_standings");
$ins = $db->prepare("INSERT INTO ffbb_standings (rank_pos, team_name, points, played, wins, losses) VALUES (:r,:t,:p,:j,:w,:l)");
foreach ($best as $s) {
    $ins->execute([':r'=>$s['rank'], ':t'=>$s['team'], ':p'=>$s['points'], ':j'=>$s['played'], ':w'=>$s['wins'], ':l'=>$s['losses']]);
    echo "✅ #{$s['rank']} {$s['team']} → {$s['points']}pts\n";
}

$db->exec("CREATE TABLE IF NOT EXISTS site_config (config_key VARCHAR(100) PRIMARY KEY, config_value TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)");
$db->prepare("INSERT INTO site_config (config_key, config_value) VALUES ('ffbb_last_sync', :v) ON DUPLICATE KEY UPDATE config_value = :v2")
    ->execute([':v'=>date('Y-m-d H:i:s'), ':v2'=>date('Y-m-d H:i:s')]);
$db->prepare("INSERT INTO site_config (config_key, config_value) VALUES ('ffbb_classement_url', :v) ON DUPLICATE KEY UPDATE config_value = :v2")
    ->execute([':v'=>'https://competitions.ffbb.com/ligues/ges/comites/0051/competitions/dxu9/classement?poule=200000003020811&phase=200000002873963', ':v2'=>'https://competitions.ffbb.com/ligues/ges/comites/0051/competitions/dxu9/classement?poule=200000003020811&phase=200000002873963']);

echo "\n✅ CLASSEMENT MIS À JOUR DANS LA BASE !\n";

// Verify
echo "\n=== VÉRIFICATION DB ===\n";
$rows = $db->query("SELECT * FROM ffbb_standings ORDER BY rank_pos")->fetchAll(PDO::FETCH_ASSOC);
foreach ($rows as $r) echo "#" . $r['rank_pos'] . " " . str_pad($r['team_name'],45) . " " . $r['points'] . "pts V:" . $r['wins'] . " D:" . $r['losses'] . "\n";

// Also test what the frontend API returns
echo "\n=== TEST API ffbb_standings ===\n";
echo "Ce que le frontend va recevoir:\n";
echo json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

echo "\n\n→ Recharge espeu9.fr (Ctrl+Shift+R) pour voir le classement.\n";
echo "→ SUPPRIME CE FICHIER (fix_classement.php)\n</pre>";
