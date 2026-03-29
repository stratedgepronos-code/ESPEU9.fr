<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
require_once 'config.php';
echo "<pre style='font-family:monospace;background:#111;color:#0f0;padding:20px;max-height:90vh;overflow:auto;'>";

$url = 'https://competitions.ffbb.com/ligues/ges/comites/0051/clubs/ges0051011/equipes/200000005162039/classement';
echo "Fetching: $url\n\n";

$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 20,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
]);
$body = curl_exec($ch);
curl_close($ch);
echo "Body: " . strlen($body) . " chars\n\n";

// 1. Check for __NEXT_DATA__ script
echo "=== Method 1: __NEXT_DATA__ ===\n";
if (preg_match('/<script id="__NEXT_DATA__"[^>]*>(.*?)<\/script>/s', $body, $m)) {
    echo "Found! Length: " . strlen($m[1]) . "\n";
    $data = json_decode($m[1], true);
    if ($data) {
        echo "JSON valid. Keys: " . implode(', ', array_keys($data)) . "\n";
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    }
} else echo "Not found\n";

// 2. Check for RSC payload (React Server Components)
echo "\n=== Method 2: RSC / script type=application/json ===\n";
if (preg_match_all('/<script[^>]*type="application\/json"[^>]*>(.*?)<\/script>/s', $body, $ms)) {
    echo count($ms[1]) . " JSON scripts found\n";
    foreach ($ms[1] as $i => $js) {
        $d = json_decode($js, true);
        if ($d && (stripos(json_encode($d), 'classement') !== false || stripos(json_encode($d), 'ESPE') !== false)) {
            echo "Script #$i contains relevant data:\n" . substr($js, 0, 500) . "\n...\n";
        }
    }
} else echo "No JSON scripts\n";

// 3. Next.js self.__next_f.push (new format)
echo "\n=== Method 3: __next_f.push ===\n";
$pushCount = preg_match_all('/self\.__next_f\.push\(\[(\d+),"((?:[^"\\\\]|\\\\.)*)"\]\)/s', $body, $pushM);
echo "$pushCount push chunks found\n";
if ($pushCount > 0) {
    $allChunks = '';
    foreach ($pushM[2] as $c) $allChunks .= stripcslashes($c);
    echo "Total chunks length: " . strlen($allChunks) . "\n";
    if (stripos($allChunks, 'classement') !== false) {
        $pos = stripos($allChunks, 'classement');
        echo "Found 'classement' at pos $pos:\n" . substr($allChunks, max(0,$pos-100), 500) . "\n";
    }
}

// 4. Try all script tags for embedded data
echo "\n=== Method 4: All script contents with ESPE/classement ===\n";
preg_match_all('/<script[^>]*>(.*?)<\/script>/s', $body, $allScripts);
echo count($allScripts[1]) . " total script tags\n";
foreach ($allScripts[1] as $i => $sc) {
    if (strlen($sc) > 50 && (stripos($sc, 'ESPE') !== false || stripos($sc, 'classement') !== false || stripos($sc, 'Chalons') !== false || stripos($sc, 'Vitry') !== false)) {
        echo "\nScript #$i (" . strlen($sc) . " chars) contains relevant data:\n";
        // Find the relevant part
        foreach (['ESPE', 'Vitry', 'Courtisols', 'Cormontreuil', 'classement'] as $kw) {
            $p = stripos($sc, $kw);
            if ($p !== false) echo "  [$kw at $p]: ..." . substr($sc, max(0,$p-80), 300) . "...\n\n";
        }
    }
}

// 5. Try FFBB API directly
echo "\n=== Method 5: Direct FFBB API ===\n";
$apiUrls = [
    'https://api.ffbb.app/items/equipe/200000005162039?fields=id,nom,classement.*',
    'https://api.ffbb.app/items/equipe/200000005162039',
];
foreach ($apiUrls as $apiUrl) {
    echo "Trying: $apiUrl\n";
    $ch = curl_init($apiUrl);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>10, CURLOPT_SSL_VERIFYPEER=>false, CURLOPT_HTTPHEADER=>['Accept: application/json']]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    echo "HTTP $code — " . strlen($resp) . " chars\n";
    if ($code === 200 && $resp) echo substr($resp, 0, 500) . "\n";
    echo "\n";
}

// 6. Try FFBB config endpoint (public tokens)
echo "=== Method 6: FFBB config/tokens ===\n";
$cfgUrls = ['https://api.ffbb.app/cfg', 'https://competitions.ffbb.com/api/cfg', 'https://competitions.ffbb.com/_next/data'];
foreach ($cfgUrls as $cu) {
    $ch = curl_init($cu);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>5, CURLOPT_SSL_VERIFYPEER=>false]);
    $r = curl_exec($ch);
    $c = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    echo "$cu → HTTP $c (" . strlen($r) . " chars)\n";
    if ($c === 200 && strlen($r) < 2000) echo $r . "\n";
}

echo "\n\nSUPPRIME CE FICHIER\n</pre>";
