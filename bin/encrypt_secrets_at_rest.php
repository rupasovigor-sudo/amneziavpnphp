<?php
/**
 * One-off, idempotent migration: encrypt at-rest secrets that predate the
 * SecretBox-everywhere change.
 *
 *   - api_keys.api_key            (e.g. the Timeweb DNS token)
 *   - vpn_clients.private_key / preshared_key / config / qr_code
 *
 * Server SSH password/ssh_key were already encrypted. public_key is left
 * plaintext on purpose (it's indexed and matched by the metrics collector).
 * Rows already carrying the `enc:v1:` prefix are skipped, so this is safe to
 * run repeatedly. Requires APP_ENCRYPTION_KEY to be set.
 *
 *   docker exec amnezia-panel-web php /var/www/html/bin/encrypt_secrets_at_rest.php
 */

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../inc/Config.php';
require __DIR__ . '/../inc/DB.php';
require __DIR__ . '/../inc/SecretBox.php';
Config::load(__DIR__ . '/../.env');

$db = DB::conn();

// api_keys
$n = 0;
foreach ($db->query('SELECT id, api_key FROM api_keys')->fetchAll(PDO::FETCH_ASSOC) as $r) {
    if ($r['api_key'] !== null && $r['api_key'] !== '' && !SecretBox::isEncrypted($r['api_key'])) {
        $db->prepare('UPDATE api_keys SET api_key = ? WHERE id = ?')
            ->execute([SecretBox::encryptNullable($r['api_key']), $r['id']]);
        $n++;
    }
}
echo "api_keys: encrypted {$n} row(s)\n";

// vpn_clients
$fields = ['private_key', 'preshared_key', 'config', 'qr_code'];
$n = 0;
foreach ($db->query('SELECT id, private_key, preshared_key, config, qr_code FROM vpn_clients')->fetchAll(PDO::FETCH_ASSOC) as $r) {
    $set = [];
    $vals = [];
    foreach ($fields as $f) {
        if ($r[$f] !== null && $r[$f] !== '' && !SecretBox::isEncrypted($r[$f])) {
            $set[] = "$f = ?";
            $vals[] = SecretBox::encryptNullable($r[$f]);
        }
    }
    if ($set) {
        $vals[] = $r['id'];
        $db->prepare('UPDATE vpn_clients SET ' . implode(', ', $set) . ' WHERE id = ?')->execute($vals);
        $n++;
    }
}
echo "vpn_clients: encrypted {$n} row(s)\n";
echo "done.\n";
