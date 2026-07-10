<?php

class ProtocolService
{

    /**
     * Get all protocols with additional metadata
     */
    public static function getAllProtocolsWithStats(): array
    {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->query('
                SELECT p.*, 
                       COUNT(DISTINCT sp.server_id) as server_count,
                       COUNT(DISTINCT pt.id) as template_count,
                       COUNT(DISTINCT pv.id) as variable_count,
                       COUNT(DISTINCT ag.id) as ai_generation_count,
                       MAX(ag.created_at) as last_ai_generation
                FROM protocols p
                LEFT JOIN server_protocols sp ON p.id = sp.protocol_id
                LEFT JOIN protocol_templates pt ON p.id = pt.protocol_id
                LEFT JOIN protocol_variables pv ON p.id = pv.protocol_id
                LEFT JOIN ai_generations ag ON p.id = ag.protocol_id
                GROUP BY p.id
                ORDER BY p.name ASC
            ');

            return $stmt->fetchAll(PDO::FETCH_ASSOC);

        } catch (Exception $e) {
            error_log("Error in ProtocolService::getAllProtocolsWithStats: " . $e->getMessage());
            throw new Exception('Failed to get protocols with stats');
        }
    }

    /**
     * Get protocol with all related data (templates, variables, AI history)
     */
    public static function getProtocolWithDetails(int $protocolId): array
    {
        try {
            $pdo = DB::conn();

            // Get protocol
            $stmt = $pdo->prepare('SELECT * FROM protocols WHERE id = ?');
            $stmt->execute([$protocolId]);
            $protocol = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$protocol) {
                throw new Exception('Protocol not found');
            }

            // Get templates
            $stmt = $pdo->prepare('SELECT * FROM protocol_templates WHERE protocol_id = ? ORDER BY is_default DESC, template_name ASC');
            $stmt->execute([$protocolId]);
            $protocol['templates'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get variables
            $stmt = $pdo->prepare('SELECT * FROM protocol_variables WHERE protocol_id = ? ORDER BY variable_name ASC');
            $stmt->execute([$protocolId]);
            $protocol['variables'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get AI generation history (last 10)
            $stmt = $pdo->prepare('
                SELECT ag.*, p.name as protocol_name
                FROM ai_generations ag
                LEFT JOIN protocols p ON ag.protocol_id = p.id
                WHERE ag.protocol_id = ?
                ORDER BY ag.created_at DESC
                LIMIT 10
            ');
            $stmt->execute([$protocolId]);
            $protocol['ai_history'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get server usage
            $stmt = $pdo->prepare('
                SELECT sp.*, vs.name as server_name, vs.host as server_host
                FROM server_protocols sp
                JOIN vpn_servers vs ON sp.server_id = vs.id
                WHERE sp.protocol_id = ?
                ORDER BY sp.applied_at DESC
            ');
            $stmt->execute([$protocolId]);
            $protocol['server_usage'] = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return $protocol;

        } catch (Exception $e) {
            error_log("Error in ProtocolService::getProtocolWithDetails: " . $e->getMessage());
            throw new Exception('Failed to get protocol details');
        }
    }

    /**
     * Validate protocol data before saving
     */
    public static function validateProtocolData(array $data): array
    {
        $errors = [];

        // Validate name
        if (empty($data['name'])) {
            $errors[] = 'Protocol name is required';
        } elseif (strlen($data['name']) > 255) {
            $errors[] = 'Protocol name must be less than 255 characters';
        }

        // Validate slug
        if (empty($data['slug'])) {
            $errors[] = 'Protocol slug is required';
        } elseif (!preg_match('/^[a-z0-9_-]+$/i', $data['slug'])) {
            $errors[] = 'Slug may contain only letters, numbers, dashes, and underscores';
        } elseif (strlen($data['slug']) > 100) {
            $errors[] = 'Protocol slug must be less than 100 characters';
        }

        // Validate description length
        if (isset($data['description']) && strlen($data['description']) > 65535) {
            $errors[] = 'Description is too long';
        }

        // Validate install script
        if (isset($data['install_script']) && strlen($data['install_script']) > 16777215) { // MEDIUMTEXT limit
            $errors[] = 'Installation script is too long';
        }

        // Validate output template
        if (isset($data['output_template']) && strlen($data['output_template']) > 16777215) { // MEDIUMTEXT limit
            $errors[] = 'Output template is too long';
        }

        // Validate ubuntu_compatible
        if (isset($data['ubuntu_compatible']) && !is_bool($data['ubuntu_compatible']) && !in_array($data['ubuntu_compatible'], [0, 1, '0', '1'])) {
            $errors[] = 'Ubuntu compatible must be a boolean value';
        }

        // Validate is_active
        if (isset($data['is_active']) && !is_bool($data['is_active']) && !in_array($data['is_active'], [0, 1, '0', '1'])) {
            $errors[] = 'Active status must be a boolean value';
        }

        // Validate QR code template
        if (isset($data['qr_code_template']) && strlen($data['qr_code_template']) > 16777215) {
            $errors[] = 'QR code template is too long';
        }

        // Validate QR code format
        if (isset($data['qr_code_format']) && !in_array($data['qr_code_format'], ['raw', 'amnezia_compressed'])) {
            $errors[] = 'Invalid QR code format';
        }

        return $errors;
    }

    /**
     * Check if slug is unique
     */
    public static function isSlugUnique(string $slug, ?int $excludeId = null): bool
    {
        try {
            $pdo = DB::conn();

            if ($excludeId) {
                $stmt = $pdo->prepare('SELECT COUNT(*) FROM protocols WHERE slug = ? AND id != ?');
                $stmt->execute([$slug, $excludeId]);
            } else {
                $stmt = $pdo->prepare('SELECT COUNT(*) FROM protocols WHERE slug = ?');
                $stmt->execute([$slug]);
            }

            return (int) $stmt->fetchColumn() === 0;

        } catch (Exception $e) {
            error_log("Error in ProtocolService::isSlugUnique: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if protocol can be deleted
     */
    public static function canDeleteProtocol(int $protocolId): array
    {
        try {
            $pdo = DB::conn();

            // Check if protocol is used by any servers
            $stmt = $pdo->prepare('SELECT COUNT(*) FROM server_protocols WHERE protocol_id = ?');
            $stmt->execute([$protocolId]);
            $serverCount = (int) $stmt->fetchColumn();

            $canDelete = $serverCount === 0;
            $reason = '';

            if (!$canDelete) {
                $reason = "Protocol is currently used by $serverCount server(s)";
            }

            return [
                'can_delete' => $canDelete,
                'reason' => $reason,
                'server_count' => $serverCount
            ];

        } catch (Exception $e) {
            error_log("Error in ProtocolService::canDeleteProtocol: " . $e->getMessage());
            return [
                'can_delete' => false,
                'reason' => 'Database error occurred',
                'server_count' => 0
            ];
        }
    }

    /**
     * Generate protocol template with variables
     */
    public static function generateProtocolOutput(array $protocol, array $variables): string
    {
        try {
            $template = $protocol['output_template'] ?? '';

            if (empty($template)) {
                return '';
            }

            foreach ($variables as $key => $value) {
                $template = str_replace('{{' . $key . '}}', $value ?? '', $template);
            }
            $template = preg_replace('/(\w+:\/\/[^\/:]+):(?=\/|\?|$)/', '$1', $template);
            $template = preg_replace('/(@[^\/:]+):(?=\/|\?|$)/', '$1', $template);
            $template = preg_replace('/(\w+:\/\/)@(?=[^\/]{1})/', '$1', $template);
            $template = preg_replace('/\{\{[^}]+\}\}/', '', $template);

            // Check for unreplaced variables
            if (preg_match('/\{\{([^}]+)\}\}/', $template, $matches)) {
                error_log("Unreplaced variables in protocol template: " . implode(', ', $matches));
            }

            return $template;

        } catch (Exception $e) {
            error_log("Error in ProtocolService::generateProtocolOutput: " . $e->getMessage());
            return '';
        }
    }

    /**
     * Generate QR code payload from template
     */
    public static function generateQrCodePayload(array $protocol, array $variables): string
    {
        try {
            $template = $protocol['qr_code_template'] ?? '';
            $format = $protocol['qr_code_format'] ?? 'amnezia_compressed';

            if (empty($template)) {
                return '';
            }

            // Render template using the same logic as output template
            // We temporarily wrap it to use the existing method
            $rendered = self::generateProtocolOutput(['output_template' => $template], $variables);

            if ($format === 'amnezia_compressed') {
                require_once __DIR__ . '/QrUtil.php';
                return QrUtil::encodeOldPayloadFromJson($rendered);
            }

            // For 'raw' and 'text' formats, return rendered template directly
            return $rendered;

        } catch (Exception $e) {
            error_log("Error in ProtocolService::generateQrCodePayload: " . $e->getMessage());
            return '';
        }
    }

}