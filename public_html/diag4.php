<?php
error_reporting(E_ALL); ini_set('display_errors',1); require_once 'config.php';
echo "<pre style='font-family:monospace;background:#111;color:#0f0;padding:20px;'>";

$url = 'https://competitions.ffbb.com/ligues/ges/comites/0051/clubs/ges0051011/equipes/200000005162039/classement';
$ch = curl_init($url);
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20, CURLOPT_FOLLOWLOCATION=>true, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_USERAGENT=>'Mozilla/5.0']);
$body = curl_exec($ch); curl_close($ch);
echo "Page: " . strlen($body) . " chars\n\n";

preg_match_all('/<script[^>]*>(.*?)<\/script>/s', $body, $allScripts);
echo count($allScripts[1]) . " scripts trouvés\n\n";

// Find script containing actual team names (VITRY, COURTISOLS etc - not just BASKET/ESPE)
$rscContent = '';
$scriptIdx = -1;
foreach ($allScripts[1] as $i => $sc) {
    if (stripos($sc, 'VITRY') !== false || stripos($sc, 'COURTISOLS') !== false || stripos($sc, 'CORMONTREUIL') !== false) {
        echo "✅ Script #$i contient des noms d'équipes (" . strlen($sc) . " chars)\n";
        $rscContent = $sc;
        $scriptIdx = $i;
        break;
    }
}

if (!$rscContent) { echo "❌ Aucun script avec noms d'équipes\n</pre>"; exit; }

// Show raw content around VITRY (100 chars context)
echo "\n=== RAW autour de VITRY (non décodé) ===\n";
$vp = stripos($rscContent, 'VITRY');
echo htmlspecialchars(substr($rscContent, max(0,$vp-200), 500)) . "\n";

// Now decode - the content is inside self.__next_f.push([1,"..."]) with \" escaping
$decoded = $rscContent;
// Try multiple decode passes
$decoded = str_replace('\\\\', '⟨BS⟩', $decoded);
$decoded = str_replace('\\"', '"', $decoded);
$decoded = str_replace('\\n', "\n", $decoded);
$decoded = str_replace('⟨BS⟩', '\\', $decoded);

echo "\n=== DECODED autour de VITRY ===\n";
$vp2 = stripos($decoded, 'VITRY');
echo htmlspecialchars(substr($decoded, max(0,$vp2-200), 600)) . "\n";

// Extract ALL team names - look for uppercase names near "font-bold" in decoded
echo "\n=== Noms d'équipes trouvés ===\n";
// Pattern: "children":"TEAM NAME" where TEAM NAME is all caps and > 8 chars
preg_match_all('/"children"\s*:\s*"([A-Z][A-Z\s\-\x{00C0}-\x{024F}]{8,}?)"/u', $decoded, $tM);
$teams = [];
foreach ($tM[1] as $t) {
    $t = trim($t);
    // Filter: must contain BASKET or be a known pattern
    if (preg_match('/BASKET|ESPE|VITRY|COURTISOLS|CORMONTREUIL|REIMS|CHAMPAGNE|GAULOISE|AVENIR|ASSOCIATION/i', $t)) {
        $teams[] = $t;
        echo "  → $t\n";
    }
}
$teams = array_unique($teams);

echo "\n=== Extraction stats par équipe ===\n";
foreach ($teams as $team) {
    $pos = strpos($decoded, '"' . $team . '"');
    if ($pos === false) { echo "\n$team: pos non trouvé\n"; continue; }
    
    // Get context after the team name
    $after = substr($decoded, $pos + strlen($team) + 1, 2000);
    
    // Extract numeric "children" values
    preg_match_all('/"children"\s*:\s*"?(\d{1,3})"?/u', $after, $nums);
    
    echo "\n$team\n";
    echo "  Nombres après le nom: " . implode(', ', array_slice($nums[1], 0, 10)) . "\n";
    
    // Show first 500 chars of context
    echo "  Context: " . htmlspecialchars(substr($after, 0, 500)) . "\n";
}

echo "\n\nSUPPRIME CE FICHIER</pre>";
