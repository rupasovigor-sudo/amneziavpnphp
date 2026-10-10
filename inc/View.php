<?php
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;
use Twig\TwigFilter;

class View {
  private static ?Environment $twig = null;

  public static function init(string $templatesPath, array $globals = []): void {
    if (!class_exists(Environment::class)) {
      throw new RuntimeException('Twig is not installed. Run composer require twig/twig');
    }
    $loader = new FilesystemLoader($templatesPath);
    self::$twig = new Environment($loader, [
      'cache' => false,
      'autoescape' => 'html',
    ]);

    // Add translation function
    $tFunc = new TwigFunction('t', function (string $key, array $params = []) {
      return Translator::t($key, $params);
    });
    self::$twig->addFunction($tFunc);

    // Add flag emoji function
    $flagFunc = new TwigFunction('getFlag', function (string $langCode) {
      $flags = [
        'en' => '🇬🇧',
        'ru' => '🇷🇺',
        'es' => '🇪🇸',
        'de' => '🇩🇪',
        'fr' => '🇫🇷',
        'zh' => '🇨🇳',
      ];
      return $flags[$langCode] ?? '🌐';
    });
    self::$twig->addFunction($flagFunc);

    // Add bytes format filter
    $bytesFilter = new TwigFilter('bytes_format', function (int $bytes, int $precision = 2): string {
      $units = ['B', 'KB', 'MB', 'GB', 'TB'];
      for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
      }
      return round($bytes, $precision) . ' ' . $units[$i];
    });
    self::$twig->addFilter($bytesFilter);

    // Add translation filter (alias: trans)
    $transFilter = new TwigFilter('trans', function (string $key, array $params = []) {
      return Translator::t($key, $params);
    });
    self::$twig->addFilter($transFilter);

    // Add globals
    foreach ($globals as $k => $v) self::$twig->addGlobal($k, $v);
  }

  public static function render(string $template, array $vars = []): void {
    if (!self::$twig) throw new RuntimeException('Twig is not initialized');
    $vars['flash_messages'] = self::takeFlash();
    echo self::$twig->render($template, $vars);
  }

  /**
   * One-shot messages for the layout to show as toasts: the session keys the
   * routes set before a redirect, plus ?success= / ?error= redirect params.
   * Several pages never rendered these, so e.g. a failed client creation or a
   * refused server delete just reloaded with no explanation.
   */
  private static function takeFlash(): array {
    $flash = [];
    if (session_status() === PHP_SESSION_ACTIVE) {
      foreach (['success_message' => 'success', 'error_message' => 'error'] as $key => $type) {
        if (!empty($_SESSION[$key]) && is_string($_SESSION[$key])) {
          $flash[] = ['type' => $type, 'text' => $_SESSION[$key]];
          unset($_SESSION[$key]);
        }
      }
    }
    foreach (['success', 'error'] as $type) {
      if (isset($_GET[$type]) && is_string($_GET[$type]) && trim($_GET[$type]) !== '') {
        $flash[] = ['type' => $type, 'text' => mb_substr(trim($_GET[$type]), 0, 300)];
      }
    }
    return $flash;
  }
}