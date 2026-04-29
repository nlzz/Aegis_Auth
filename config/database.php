<?php
/**
 * Aegis Auth - Configuração do Banco de Dados
 * 
 * ATENÇÃO: Credenciais devem ser definidas via variáveis de ambiente (.env).
 * Default values removidos para forçar configuração segura.
 */

define('DB_HOST', getenv('DB_HOST') ?: throw new Exception('DB_HOST não definido.'));
define('DB_NAME', getenv('DB_NAME') ?: throw new Exception('DB_NAME não definido.'));
define('DB_USER', getenv('DB_USER') ?: throw new Exception('DB_USER não definido.'));
define('DB_PASS', getenv('DB_PASS') ?? throw new Exception('DB_PASS não definido.'));
define('DB_CHARSET', 'utf8mb4');

// Cloudflare Turnstile
define('TURNSTILE_SITE_KEY', getenv('TURNSTILE_SITE_KEY') ?: '');
define('TURNSTILE_SECRET_KEY', getenv('TURNSTILE_SECRET_KEY') ?: '');

define('MAX_LOGIN_ATTEMPTS', 5);
define('MAX_ACCOUNT_ATTEMPTS', 10);
define('CAPTCHA_THRESHOLD', 3);
define('LOCKOUT_DURATION', 15 * 60);
define('REMEMBER_ME_DURATION', 30 * 24 * 3600);
define('PASSWORD_RESET_EXPIRY', 3600);
define('CSRF_TOKEN_EXPIRY', 3600);
define('SESSION_LIFETIME', 1800);
define('MIN_PASSWORD_LENGTH', 8);

function getDBConnection(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::ATTR_PERSISTENT         => false,
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            error_log('Aegis Auth DB Error: ' . $e->getMessage());
            throw new PDOException('Erro ao conectar com o banco de dados.');
        }
    }
    return $pdo;
}
