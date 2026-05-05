#!/usr/bin/env php
<?php

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

$backupDir = $argv[1] ?? (__DIR__ . '/../backups');
if (!is_dir($backupDir)) {
    echo "Backup directory not found: {$backupDir}\n";
    exit(0);
}

$files = glob(rtrim($backupDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '*.json') ?: [];
$checked = 0;
$withSecrets = [];

foreach ($files as $file) {
    $checked++;
    $decoded = json_decode((string) file_get_contents($file), true);
    if (!is_array($decoded)) {
        continue;
    }

    $server = $decoded['server'] ?? [];
    if (!is_array($server)) {
        continue;
    }

    $hasSecret = false;
    foreach (['password', 'ssh_key', 'ssh_password'] as $field) {
        if (!empty($server[$field])) {
            $hasSecret = true;
            break;
        }
    }

    if ($hasSecret) {
        $withSecrets[] = $file;
    }
}

echo "Backups checked: {$checked}\n";
echo "Backups with server SSH secrets: " . count($withSecrets) . "\n";
foreach ($withSecrets as $file) {
    echo $file . "\n";
}

exit(count($withSecrets) > 0 ? 2 : 0);
