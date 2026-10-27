<?php
declare(strict_types=1);

// End-to-end check of every pool front from inside Russia (see FrontProbe):
// a real awg2 client in the panel's docker-in-docker connects through the
// front and downloads a few MB; repeated failure rotates the front -> member
// port. Cron, every 5 min. Usage: php bin/front_e2e_probe.php

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
require_once $root . '/inc/Config.php';
Config::load($root . '/.env');
@set_time_limit(0);

$lock = fopen(sys_get_temp_dir() . '/amnezia_front_e2e.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0); // previous run still going
}
foreach (FrontProbe::checkAll() as $r) {
    echo '[' . date('Y-m-d H:i:s') . '] front e2e pool ' . ($r['pool'] ?? '?') . ': '
        . (!empty($r['ok']) ? 'OK' : 'FAIL') . ' — ' . ($r['message'] ?? '') . "\n";
}
