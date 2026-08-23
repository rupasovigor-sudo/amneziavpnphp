<?php

/**
 * Centralised audit trail for state-changing admin actions.
 *
 * recordCurrentRequest() is registered as a shutdown function in
 * public/index.php, so it fires for every request regardless of how the
 * handler exits (many call exit()/redirect()). It logs mutating requests
 * only (POST/PUT/PATCH/DELETE) and skips a small set of read-only POST
 * endpoints (list/search/inspect/test/…). record() is also callable
 * directly for semantic events.
 */
class AuditLog
{
    /** Read-only POST endpoints that must not clutter the trail. */
    private const SKIP_SUFFIXES = [
        '/list', '/search', '/stats', '/inspect', '/test', '/test-install',
        '/probe', '/online', '/status',
    ];

    public static function record(
        string $action,
        ?string $method = null,
        ?string $path = null,
        ?int $status = null,
        ?int $userId = null,
        ?string $userEmail = null,
        ?string $ip = null
    ): void {
        try {
            $stmt = DB::conn()->prepare(
                'INSERT INTO audit_log (user_id, user_email, action, method, path, status, ip)
                 VALUES (?, ?, ?, ?, ?, ?, ?)'
            );
            $stmt->execute([$userId, $userEmail, $action, $method, $path, $status, $ip]);
        } catch (Throwable $e) {
            // Auditing must never break the request it is recording.
            error_log('AuditLog::record failed: ' . $e->getMessage());
        }
    }

    public static function recordCurrentRequest(): void
    {
        try {
            $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
            if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                return;
            }
            $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
            foreach (self::SKIP_SUFFIXES as $suffix) {
                if (str_ends_with($path, $suffix)) {
                    return;
                }
            }

            $userId = isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
            $userEmail = null;
            if ($userId) {
                try {
                    $st = DB::conn()->prepare('SELECT email FROM users WHERE id = ?');
                    $st->execute([$userId]);
                    $userEmail = $st->fetchColumn() ?: null;
                } catch (Throwable $e) {
                    // best-effort denormalisation
                }
            }

            $status = http_response_code();
            $ip = function_exists('clientIp') ? clientIp() : ($_SERVER['REMOTE_ADDR'] ?? null);

            self::record(
                self::deriveAction($method, $path),
                $method,
                $path,
                is_int($status) ? $status : null,
                $userId,
                $userEmail,
                $ip
            );
        } catch (Throwable $e) {
            error_log('AuditLog::recordCurrentRequest failed: ' . $e->getMessage());
        }
    }

    /** post /clients/42/revoke -> "post.clients.revoke" (ids stripped). */
    private static function deriveAction(string $method, string $path): string
    {
        $p = preg_replace('#/\d+#', '', $path);
        $p = trim((string) $p, '/');
        $p = preg_replace('#[^a-zA-Z0-9]+#', '.', (string) $p);
        return strtolower($method) . ($p !== '' ? '.' . $p : '');
    }

    /** @return array<int,array<string,mixed>> most recent entries first */
    public static function recent(int $limit = 200, int $offset = 0): array
    {
        try {
            $limit = max(1, min(1000, $limit));
            $offset = max(0, $offset);
            $stmt = DB::conn()->prepare(
                'SELECT created_at, user_email, action, method, path, status, ip
                 FROM audit_log ORDER BY id DESC LIMIT ' . $limit . ' OFFSET ' . $offset
            );
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC) ?: [];
        } catch (Throwable $e) {
            error_log('AuditLog::recent failed: ' . $e->getMessage());
            return [];
        }
    }
}
