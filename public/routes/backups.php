<?php

// Backup management (admin). S3-backed encrypted panel backups — see BackupManager.

Router::get('/backups', function () {
    requireAdmin();
    $s = BackupManager::getSettings();
    $backups = [];
    $listError = '';
    if (trim((string) $s['s3_bucket']) !== '' && trim((string) $s['s3_secret']) !== '') {
        $backups = BackupManager::listBackups($s);
    }
    View::render('backups.twig', [
        'cfg' => [
            's3_endpoint'    => $s['s3_endpoint'],
            's3_region'      => $s['s3_region'],
            's3_bucket'      => $s['s3_bucket'],
            's3_key'         => $s['s3_key'],
            's3_secret_set'  => trim((string) $s['s3_secret']) !== '',
            'passphrase_set' => trim((string) $s['passphrase']) !== '',
            'retention'      => (int) $s['retention'],
            'schedule'       => $s['schedule'],
        ],
        'backups' => $backups,
    ]);
});

Router::post('/backups/settings', function () {
    requireAdmin();
    header('Content-Type: application/json');
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    try {
        BackupManager::saveSettings($in);
        echo json_encode(['success' => true, 'message' => 'Настройки бэкапа сохранены']);
    } catch (Throwable $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
});

Router::post('/backups/test', function () {
    requireAdmin();
    header('Content-Type: application/json');
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    // Test with posted (possibly unsaved) values merged over stored ones.
    $s = BackupManager::getSettings();
    foreach (['s3_endpoint', 's3_region', 's3_bucket', 's3_key'] as $k) {
        if (isset($in[$k]) && trim((string) $in[$k]) !== '') {
            $s[$k] = trim((string) $in[$k]);
        }
    }
    if (!empty($in['s3_secret'])) {
        $s['s3_secret'] = (string) $in['s3_secret'];
    }
    echo json_encode(BackupManager::testConnection($s), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});

Router::post('/backups/create', function () {
    requireAdmin();
    @set_time_limit(300);
    @ignore_user_abort(true);
    @session_write_close();
    header('Content-Type: application/json');
    echo json_encode(BackupManager::createBackup('manual'), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});

Router::post('/backups/list', function () {
    requireAdmin();
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'backups' => BackupManager::listBackups()], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});

Router::post('/backups/inspect', function () {
    requireAdmin();
    header('Content-Type: application/json');
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    echo json_encode(BackupManager::inspectBackup((string) ($in['key'] ?? '')), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});

Router::post('/backups/restore', function () {
    requireAdmin();
    @set_time_limit(300);
    @ignore_user_abort(true);
    @session_write_close();
    header('Content-Type: application/json');
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    echo json_encode(BackupManager::restoreBackup((string) ($in['key'] ?? '')), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});

Router::post('/backups/delete', function () {
    requireAdmin();
    header('Content-Type: application/json');
    $in = json_decode(file_get_contents('php://input'), true) ?: [];
    echo json_encode(BackupManager::deleteBackup((string) ($in['key'] ?? '')), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
});
