<?php
declare(strict_types=1);

// Scheduled backup runner. Run it frequently (e.g. hourly); it creates a backup
// only when the configured schedule interval has elapsed since the last one.
//
//   cron: 0 * * * * /usr/local/bin/php /var/www/html/bin/backup_cron.php

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
foreach (['Config', 'DB', 'Logger', 'SecretBox', 'BackupManager'] as $c) {
    @require_once $root . '/inc/' . $c . '.php';
}
Config::load($root . '/.env');

$s = BackupManager::getSettings();
$sched = (string) ($s['schedule'] ?? 'off');
$intervals = ['daily' => 86400, '12h' => 43200, '6h' => 21600];
if (!isset($intervals[$sched])) {
    exit(0); // scheduling off
}
if (trim((string) $s['s3_bucket']) === '' || trim((string) $s['passphrase']) === '') {
    fwrite(STDERR, "backup_cron: S3/passphrase not configured\n");
    exit(0);
}

$interval = $intervals[$sched];
$last = 0;
foreach (BackupManager::listBackups($s) as $b) {
    $ts = strtotime((string) ($b['modified'] ?? ''));
    if ($ts && $ts > $last) {
        $last = $ts;
    }
}
if ($last > 0 && (time() - $last) < $interval) {
    exit(0); // not due yet
}

$res = BackupManager::createBackup('scheduled');
error_log('backup_cron: ' . json_encode($res, JSON_UNESCAPED_UNICODE));
echo ($res['success'] ? 'OK ' : 'FAIL ') . ($res['message'] ?? '') . "\n";
exit($res['success'] ? 0 : 1);
