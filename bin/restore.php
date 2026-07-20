<?php
declare(strict_types=1);

/**
 * DR restore CLI — works WITHOUT the panel UI (e.g. on a fresh host after the
 * panel/host was lost). Reads S3 creds + passphrase from env (falls back to the
 * stored settings when the DB is available).
 *
 * Env (for a fresh host where the DB settings are empty):
 *   S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_KEY, S3_SECRET, BACKUP_PASSPHRASE
 *
 * Usage:
 *   php bin/restore.php --list                       # list backups (newest first)
 *   php bin/restore.php --latest --show-key          # print APP_ENCRYPTION_KEY from the newest backup
 *   php bin/restore.php --key=<key> --show-env       # print the whole backed-up .env
 *   php bin/restore.php --latest --restore-db --yes  # restore the DB from the newest backup
 */

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
foreach (['Config', 'DB', 'Logger', 'SecretBox', 'BackupManager'] as $c) {
    @require_once $root . '/inc/' . $c . '.php';
}
Config::load($root . '/.env');

// If S3 creds/passphrase are supplied via env, persist them so BackupManager
// (which reads settings from the DB) can use them — needed on a fresh host.
$envMap = [
    'S3_ENDPOINT' => 's3_endpoint', 'S3_REGION' => 's3_region', 'S3_BUCKET' => 's3_bucket',
    'S3_KEY' => 's3_key', 'S3_SECRET' => 's3_secret', 'BACKUP_PASSPHRASE' => 'passphrase',
];
$seed = [];
foreach ($envMap as $e => $k) {
    $v = getenv($e);
    if ($v !== false && $v !== '') {
        $seed[$k] = $v;
    }
}
if ($seed) {
    BackupManager::saveSettings($seed);
}

$opts = getopt('', ['list', 'key:', 'latest', 'show-key', 'show-env', 'restore-db', 'yes']);

function pickLatest(): string {
    $l = BackupManager::listBackups();
    return $l[0]['key'] ?? '';
}

if (isset($opts['list'])) {
    foreach (BackupManager::listBackups() as $b) {
        echo str_pad($b['size_h'], 8) . '  ' . ($b['modified'] ?? '') . '  ' . $b['key'] . "\n";
    }
    exit(0);
}

$key = (string) ($opts['key'] ?? '');
if (isset($opts['latest'])) {
    $key = pickLatest();
}
if ($key === '') {
    fwrite(STDERR, "Укажи --key=<key> или --latest (см. --list)\n");
    exit(2);
}

if (isset($opts['show-key'])) {
    $i = BackupManager::inspectBackup($key);
    if (empty($i['success'])) { fwrite(STDERR, ($i['message'] ?? 'error') . "\n"); exit(1); }
    echo ($i['app_key'] ?: '(APP_ENCRYPTION_KEY не найден в бэкапе)') . "\n";
    exit(0);
}

if (isset($opts['show-env'])) {
    $e = BackupManager::getBackupEnv($key);
    if (empty($e['success'])) { fwrite(STDERR, ($e['message'] ?? 'error') . "\n"); exit(1); }
    echo $e['env'];
    exit(0);
}

if (isset($opts['restore-db'])) {
    if (!isset($opts['yes'])) {
        fwrite(STDERR, "Это ПЕРЕЗАПИШЕТ текущую БД. Повтори с --yes для подтверждения.\n");
        exit(2);
    }
    $r = BackupManager::restoreBackup($key);
    echo ($r['message'] ?? '') . "\n";
    exit($r['success'] ? 0 : 1);
}

fwrite(STDERR, "Нечего делать. Укажи --list / --show-key / --show-env / --restore-db\n");
exit(2);
