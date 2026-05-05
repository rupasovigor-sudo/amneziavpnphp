#!/usr/bin/env php
<?php

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../inc/Config.php';
Config::load(__DIR__ . '/../.env');
require_once __DIR__ . '/../inc/DB.php';
require_once __DIR__ . '/../inc/SecretBox.php';

$apply = in_array('--apply', $argv, true);
$dryRun = in_array('--dry-run', $argv, true) || !$apply;

if (!$apply && !$dryRun) {
    $dryRun = true;
}

try {
    $pdo = DB::conn();
    $stmt = $pdo->query('SELECT id, password, ssh_key FROM vpn_servers ORDER BY id');
    $rows = $stmt->fetchAll();

    $stats = [
        'servers' => count($rows),
        'plaintext' => 0,
        'encrypted' => 0,
        'empty' => 0,
        'updated' => 0,
        'errors' => 0,
    ];

    foreach ($rows as $row) {
        $updates = [];
        $params = [];

        foreach (['password', 'ssh_key'] as $field) {
            $value = $row[$field] ?? null;
            if ($value === null || $value === '') {
                $stats['empty']++;
                continue;
            }

            if (SecretBox::isEncrypted($value)) {
                try {
                    SecretBox::decryptNullable($value);
                    $stats['encrypted']++;
                } catch (Throwable $e) {
                    $stats['errors']++;
                    fwrite(STDERR, "Server {$row['id']} has unreadable encrypted {$field}: {$e->getMessage()}\n");
                }
                continue;
            }

            $stats['plaintext']++;
            if ($apply) {
                $updates[] = $field . ' = ?';
                $params[] = SecretBox::encryptNullable($value);
            }
        }

        if ($apply && $updates) {
            $params[] = (int) $row['id'];
            $sql = 'UPDATE vpn_servers SET ' . implode(', ', $updates) . ' WHERE id = ?';
            $update = $pdo->prepare($sql);
            $update->execute($params);
            $stats['updated']++;
        }
    }

    echo ($apply ? "Apply mode\n" : "Dry-run mode\n");
    echo "Servers checked: {$stats['servers']}\n";
    echo "Plaintext secrets: {$stats['plaintext']}\n";
    echo "Encrypted secrets: {$stats['encrypted']}\n";
    echo "Empty secrets: {$stats['empty']}\n";
    echo "Servers updated: {$stats['updated']}\n";
    echo "Errors: {$stats['errors']}\n";

    exit($stats['errors'] > 0 ? 2 : 0);
} catch (Throwable $e) {
    fwrite(STDERR, "Failed: {$e->getMessage()}\n");
    exit(1);
}
