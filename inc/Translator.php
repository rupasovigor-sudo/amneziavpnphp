<?php
/**
 * Translator class for multi-language support
 * Supports automatic translation using external services
 */
class Translator {
    private static ?string $currentLanguage = null;
    private static array $translations = [];
    private static array $fallback = [];
    private static array $supportedLanguages = [];
    
    /**
     * Initialize translator
     */
    public static function init(): void {
        // Load supported languages
        self::loadSupportedLanguages();
        
        // Detect language from session, cookie, or browser
        self::detectLanguage();
        
        // Load translations for current language
        self::loadTranslations(self::$currentLanguage);
    }
    
    /**
     * Load supported languages from database
     */
    private static function loadSupportedLanguages(): void {
        $pdo = DB::conn();
        $stmt = $pdo->query('SELECT code, name, native_name FROM languages WHERE is_active = 1');
        self::$supportedLanguages = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    /**
     * Detect user's preferred language
     */
    private static function detectLanguage(): void {
        // 1. Check session
        if (isset($_SESSION['language'])) {
            self::$currentLanguage = $_SESSION['language'];
            return;
        }
        
        // 2. Check cookie
        if (isset($_COOKIE['language'])) {
            self::$currentLanguage = $_COOKIE['language'];
            $_SESSION['language'] = self::$currentLanguage;
            return;
        }
        
        // 3. Check browser language
        if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $browserLang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
            if (self::isSupported($browserLang)) {
                self::$currentLanguage = $browserLang;
                $_SESSION['language'] = self::$currentLanguage;
                return;
            }
        }
        
        // 4. Default to English
        self::$currentLanguage = 'en';
        $_SESSION['language'] = 'en';
    }
    
    /**
     * Check if language is supported
     */
    public static function isSupported(string $code): bool {
        foreach (self::$supportedLanguages as $lang) {
            if ($lang['code'] === $code) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Load translations for specific language
     */
    private static function loadTranslations(string $languageCode): void {
        $pdo = DB::conn();
        $stmt = $pdo->prepare('SELECT CONCAT(category, ".", key_name) as trans_key, translation FROM translations WHERE locale = ?');
        $stmt->execute([$languageCode]);

        $translations = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
        self::$translations = $translations ?: [];

        // English fallback so a key missing in a partially-translated locale
        // degrades to English instead of showing the raw key.
        if ($languageCode === 'en') {
            self::$fallback = self::$translations;
        } elseif (empty(self::$fallback)) {
            $stmt = $pdo->prepare('SELECT CONCAT(category, ".", key_name) as trans_key, translation FROM translations WHERE locale = ?');
            $stmt->execute(['en']);
            self::$fallback = $stmt->fetchAll(PDO::FETCH_KEY_PAIR) ?: [];
        }
    }
    
    /**
     * Translate a key
     * 
     * @param string $key Translation key
     * @param array $params Parameters for sprintf
     * @return string Translated text
     */
    public static function translate(string $key, array $params = []): string {
        $translation = self::$translations[$key] ?? self::$fallback[$key] ?? $key;

        if (!empty($params)) {
            return sprintf($translation, ...$params);
        }
        
        return $translation;
    }
    
    /**
     * Short alias for translate()
     */
    public static function t(string $key, array $params = []): string {
        return self::translate($key, $params);
    }
    
    /**
     * Get current language code
     */
    public static function getCurrentLanguage(): string {
        return self::$currentLanguage ?? 'en';
    }
    
    /**
     * Set current language
     */
    public static function setLanguage(string $code): bool {
        if (!self::isSupported($code)) {
            return false;
        }
        
        self::$currentLanguage = $code;
        $_SESSION['language'] = $code;
        setcookie('language', $code, time() + 31536000, '/'); // 1 year
        
        // Reload translations
        self::loadTranslations($code);
        
        return true;
    }
    
    /**
     * Get all supported languages
     */
    public static function getSupportedLanguages(): array {
        return self::$supportedLanguages;
    }
    /**
     * Save API key for translation service
     */
    public static function saveApiKey(string $serviceName, string $apiKey): bool {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare('
                INSERT INTO api_keys (service_name, api_key, is_active)
                VALUES (?, ?, 1)
                ON DUPLICATE KEY UPDATE api_key = VALUES(api_key), updated_at = NOW()
            ');
            return $stmt->execute([$serviceName, $apiKey]);
        } catch (Exception $e) {
            error_log('Failed to save API key: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get API key for service
     */
    public static function getApiKey(string $serviceName): ?string {
        try {
            $pdo = DB::conn();
            $stmt = $pdo->prepare("SELECT api_key FROM api_keys WHERE service_name = ? AND is_active = 1 LIMIT 1");
            $stmt->execute([$serviceName]);
            return $stmt->fetchColumn() ?: null;
        } catch (Exception $e) {
            return null;
        }
    }
}
