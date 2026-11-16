<?php
class Config {
  protected static array $env = [];

  public static function load(string $path): void {
    foreach (self::readFile($path) as $key => $value) {
      // Real environment wins over .env: don't clobber variables that are
      // already exported (docker -e, systemd Environment=, CI, etc.).
      if (getenv($key) !== false) {
        self::$env[$key] = getenv($key);
        continue;
      }
      self::$env[$key] = $value;
      @putenv($key . '=' . $value);
    }
  }

  /**
   * Re-read a mutable .env file into an already-running daemon.
   *
   * load() deliberately lets the process environment win.  Values loaded by
   * load() are themselves exported with putenv(), though, so calling load()
   * again can never observe an edited file.  Long-running workers use reload()
   * at a safe cycle boundary, where the file is the authoritative live config.
   */
  public static function reload(string $path, array $onlyKeys = []): void {
    foreach (self::readFile($path) as $key => $value) {
      if ($onlyKeys !== [] && !in_array($key, $onlyKeys, true)) {
        continue;
      }
      self::$env[$key] = $value;
      @putenv($key . '=' . $value);
    }
  }

  /** @return array<string,string> */
  private static function readFile(string $path): array {
    if (!file_exists($path)) {
      return [];
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
      return [];
    }
    $values = [];
    foreach ($lines as $line) {
      if (str_starts_with(trim($line), '#')) continue;
      $parts = explode('=', $line, 2);
      if (count($parts) !== 2) continue;
      $key = trim($parts[0]);
      if ($key === '') continue;
      $value = trim($parts[1]);
      $values[$key] = trim($value, "\"' ");
    }
    return $values;
  }

  public static function get(string $key, $default = null) {
    $env = getenv($key);
    if ($env !== false && $env !== null) return $env;
    return self::$env[$key] ?? $default;
  }
}
