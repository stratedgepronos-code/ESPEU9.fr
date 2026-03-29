<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'config.php';
echo "<pre style='font-family:monospace;background:#111;color:#0f0;padding:20px;'>";

$url = 'https://competitions.ffbb.com/ligues/ges/comites/0051/clubs/ges0051011/equipes/200000005162039/classement';
$ch = curl_init($url);
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20, CURLOPT_FOLLOWLOCATION=>true, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_USERAGENT=>'Mozilla/5.0']);
$body = curl_exec($ch);
curl_close($ch);
echo "Page: " . strlen($body) . " chars\n\n";

// Find the big script with team data
preg_match_all('/<script[^>]*>(.*?)<\/script>/s', $body, $allScripts);
$rscContent = '';
$scriptIdx = -1;
foreach ($allScripts[1] as $i => $sc) {
    if (strlen($sc) > 30000 && stripos($sc, 'font-bold') !== false && stripos($sc, 'BASKET') !== false) {
        $rscContent = $sc;
        $scriptIdx = $i;
        break;
    }
}
echo "RSC Script #$scriptIdx: " . strlen($rscContent) . " chars\n\n";

if (!$rscContent) { echo "❌ Script RSC non trouvé\n</pre>"; exit; }

// Decode
$decoded = str_replace(['\\"', '\\n', '\\t', '\\\\'], ['"', "\n", "\t", '\\'], $rscContent);

// Find team names
echo "=== Recherche noms d'équipes ===\n";
$teamPattern = '/font-bold["\s,}]*["\s,]*"children"\s*:\s*"([A-Z\x{00C0}-\x{024F}][A-Z\x{00C0}-\x{024F}\s\-\'\.\d]{4,}?)"/u';
preg_match_all($teamPattern, $decoded, $teamMatches);
echo "Trouvé: " . count($teamMatches[1]) . " noms\n";
foreach ($teamMatches[1] as $t) echo "  → $t\n";

// Also try alternative patterns
echo "\n=== Pattern alternatif 1: xs font-bold children ===\n";
$alt1 = '/text-xs\s+font-bold[^"]*"[,\s]*"children"\s*:\s*"([^"]{5,})"/u';
preg_match_all($alt1, $decoded, $alt1M);
echo count($alt1M[1]) . " trouvé\n";
foreach ($alt1M[1] as $t) echo "  → $t\n";

echo "\n=== Pattern alternatif 2: min-w bold children ===\n";
$alt2 = '/min-w-\[\d+px\]\s+text-\[#[a-f0-9]+\]\s+text-xs\s+font-bold[^"]*"[,\s]*"children"\s*:\s*"([^"]{5,})"/u';
preg_match_all($alt2, $decoded, $alt2M);
echo count($alt2M[1]) . " trouvé\n";
foreach ($alt2M[1] as $t) echo "  → $t\n";

// Show raw context around a known team name
echo "\n=== Contexte brut autour de VITRY ===\n";
$vpos = stripos($decoded, 'VITRY');
if ($vpos) {
    $ctx = substr($decoded, max(0,$vpos-300), 800);
    echo htmlspecialchars($ctx) . "\n";
}

echo "\n=== Contexte brut autour de ESPE ===\n";
// Find ESPE in uppercase context (not navigation)
$offset = 0;
$found = false;
while (($epos = stripos($decoded, 'ESPE BASKET', $offset)) !== false) {
    $ctx = substr($decoded, max(0,$epos-200), 600);
    if (stripos($ctx, 'font-bold') !== false || stripos($ctx, 'classement') !== false) {
        echo htmlspecialchars($ctx) . "\n";
        $found = true;
        break;
    }
    $offset = $epos + 10;
}
if (!$found) echo "Non trouvé dans contexte classement\n";

// Try to find ALL children values (numbers) near team names
echo "\n=== Extraction données brutes par équipe ===\n";
$teams = ['ESPE BASKET CHALONS EN CHAMPAGNE', 'GAULOISE DE VITRY LE FRANCOIS', 'AVENIR SPORTIF COURTISOLS BASKET', 'ASSOCIATION CORMONTREUIL CHAMPAGNE BASKET', 'REIMS CHAMPAGNE BASKET'];
foreach ($teams as $team) {
    $pos = strpos($decoded, $team);
    if ($pos === false) { 
        // Try partial
        $short = explode(' ', $team)[0];
        $pos = strpos($decoded, $team);
        if ($pos === false) { echo "\n$team: NON TROUVÉ\n"; continue; }
    }
    $after = substr($decoded, $pos + strlen($team), 1500);
    // Get all "children":"N" or "children":N patterns (numbers 0-99)
    preg_match_all('/"children"\s*:\s*"?(\d{1,3})"?\s*[,}\]]/u', $after, $nums);
    echo "\n$team:\n";
    echo "  Valeurs trouvées après le nom: " . implode(', ', $nums[1]) . "\n";
    echo "  (probablement: Pts, Joués, Gagnés, Perdus)\n";
    // Show first 300 chars after name
    echo "  Raw: " . htmlspecialchars(substr($after, 0, 400)) . "\n";
}

echo "\n\nSUPPRIME CE FICHIER</pre>";
