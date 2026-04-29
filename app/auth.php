<?php
/**
 * Aegis Auth - Módulo de Autenticação
 */

require_once __DIR__ . '/../config/database.php';

// ── Cabeçalhos de Segurança ─────────────────────────────────────
function setSecurityHeaders(): void
{
    if (!headers_sent()) {
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';");
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
        
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
        }
    }
}

// ── Logs de Auditoria ───────────────────────────────────────────
function logSecurityEvent(string $type, string $description, ?int $userId = null, string $severity = 'INFO'): void
{
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare(
            "INSERT INTO security_logs (user_id, event_type, severity, description, ip_address, user_agent) 
             VALUES (:uid, :type, :sev, :desc, :ip, :ua)"
        );
        $stmt->execute([
            'uid'   => $userId,
            'type'  => $type,
            'sev'   => $severity,
            'desc'  => $description,
            'ip'    => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'ua'    => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        ]);
    } catch (Exception $e) {
        error_log("Security Log Error: " . $e->getMessage());
    }
}

// ── Sessão Segura ───────────────────────────────────────────────
function initSecureSession(): void
{
    setSecurityHeaders();
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.gc_maxlifetime', (string) SESSION_LIFETIME);
        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']),
            'httponly'  => true,
            'samesite'  => 'Strict',
        ]);
        session_start();
    }
    // Regenera ID periodicamente
    if (!isset($_SESSION['_created'])) {
        $_SESSION['_created'] = time();
    } elseif (time() - $_SESSION['_created'] > 300) {
        session_regenerate_id(true);
        $_SESSION['_created'] = time();
    }
}

// ── CSRF (Database Backed) ──────────────────────────────────────
function generateCSRFToken(): string
{
    $token = bin2hex(random_bytes(32));
    $hash = hash('sha256', $token);
    $expires = date('Y-m-d H:i:s', time() + CSRF_TOKEN_EXPIRY);
    $sessionId = session_id();

    $pdo = getDBConnection();
    
    // Limpa tokens expirados desta sessão para economizar espaço
    $stmt = $pdo->prepare("DELETE FROM csrf_tokens WHERE session_id = :sid AND expires_at < NOW()");
    $stmt->execute(['sid' => $sessionId]);

    $stmt = $pdo->prepare(
        "INSERT INTO csrf_tokens (session_id, token_hash, expires_at) VALUES (:sid, :hash, :exp)"
    );
    $stmt->execute(['sid' => $sessionId, 'hash' => $hash, 'exp' => $expires]);

    return $token;
}

function validateCSRFToken(string $token): bool
{
    if (empty($token)) return false;
    
    $hash = hash('sha256', $token);
    $sessionId = session_id();
    $pdo = getDBConnection();

    $stmt = $pdo->prepare(
        "SELECT id FROM csrf_tokens 
         WHERE session_id = :sid AND token_hash = :hash AND expires_at > NOW()"
    );
    $stmt->execute(['sid' => $sessionId, 'hash' => $hash]);
    $row = $stmt->fetch();

    if ($row) {
        // Token de uso único (Single-use)
        $del = $pdo->prepare("DELETE FROM csrf_tokens WHERE id = :id");
        $del->execute(['id' => $row['id']]);
        return true;
    }

    return false;
}

// ── Validações ──────────────────────────────────────────────────
function validateEmail(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function validatePasswordStrength(string $password): array
{
    $errors = [];
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        $errors[] = "A senha deve ter no mínimo " . MIN_PASSWORD_LENGTH . " caracteres.";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "A senha deve conter pelo menos uma letra maiúscula.";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "A senha deve conter pelo menos uma letra minúscula.";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "A senha deve conter pelo menos um número.";
    }
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "A senha deve conter pelo menos um caractere especial.";
    }
    return $errors;
}

function sanitizeInput(string $input): string
{
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// ── Utilitários ────────────────────────────────────────────────
function generateUUID(): string
{
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // v4
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // variant
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

// ── Brute Force & CAPTCHA ───────────────────────────────────────
function recordLoginAttempt(string $ip, string $email): void
{
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("INSERT INTO login_attempts (ip_address, email) VALUES (:ip, :email)");
    $stmt->execute(['ip' => $ip, 'email' => $email]);
}

function isLockedOut(string $ip, string $email): bool
{
    $pdo = getDBConnection();
    $cutoff = date('Y-m-d H:i:s', time() - LOCKOUT_DURATION);
    
    // Bloqueio por IP
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_address = :ip AND attempted_at > :cutoff"
    );
    $stmt->execute(['ip' => $ip, 'cutoff' => $cutoff]);
    if ((int) $stmt->fetchColumn() >= MAX_LOGIN_ATTEMPTS) return true;

    // Bloqueio por Conta (Prevenção contra Distributed Brute Force)
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM login_attempts WHERE email = :email AND attempted_at > :cutoff"
    );
    $stmt->execute(['email' => $email, 'cutoff' => $cutoff]);
    if ((int) $stmt->fetchColumn() >= MAX_ACCOUNT_ATTEMPTS) return true;

    return false;
}

function clearLoginAttempts(string $ip, string $email): void
{
    $pdo = getDBConnection();
    $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE ip_address = :ip OR email = :email");
    $stmt->execute(['ip' => $ip, 'email' => $email]);
}

function shouldShowCaptcha(string $ip, string $email): bool
{
    $pdo = getDBConnection();
    $cutoff = date('Y-m-d H:i:s', time() - LOCKOUT_DURATION);
    
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM login_attempts WHERE (ip_address = :ip OR email = :email) AND attempted_at > :cutoff"
    );
    $stmt->execute(['ip' => $ip, 'email' => $email, 'cutoff' => $cutoff]);
    
    return (int) $stmt->fetchColumn() >= CAPTCHA_THRESHOLD;
}

function getRemainingAttempts(string $ip, string $email): int
{
    $pdo = getDBConnection();
    $cutoff = date('Y-m-d H:i:s', time() - LOCKOUT_DURATION);
    
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_address = :ip AND attempted_at > :cutoff"
    );
    $stmt->execute(['ip' => $ip, 'cutoff' => $cutoff]);
    $attempts = (int) $stmt->fetchColumn();
    
    return max(0, MAX_LOGIN_ATTEMPTS - $attempts);
}

// ── Cadastro ────────────────────────────────────────────────────
function registerUser(string $name, string $email, string $password): array
{
    $name = trim($name);
    $email = strtolower(trim($email));

    if (empty($name) || strlen($name) < 2) {
        return ['success' => false, 'error' => 'Nome deve ter pelo menos 2 caracteres.'];
    }
    if (!validateEmail($email)) {
        return ['success' => false, 'error' => 'E-mail inválido.'];
    }
    $pwErrors = validatePasswordStrength($password);
    if (!empty($pwErrors)) {
        return ['success' => false, 'error' => implode(' ', $pwErrors)];
    }

    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    if ($stmt->fetch()) {
        return ['success' => false, 'error' => 'Este e-mail já está cadastrado.'];
    }

    $uuid = generateUUID();
    $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $pdo->prepare(
        "INSERT INTO users (uuid, name, email, password_hash) VALUES (:uuid, :name, :email, :hash)"
    );
    $stmt->execute(['uuid' => $uuid, 'name' => $name, 'email' => $email, 'hash' => $hash]);

    return ['success' => true, 'message' => 'Conta criada com sucesso!'];
}

// ── Login ───────────────────────────────────────────────────────
function loginUser(string $email, string $password, bool $remember = false, string $captchaToken = ''): array
{
    $email = strtolower(trim($email));
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if (isLockedOut($ip, $email)) {
        logSecurityEvent('LOGIN_LOCKOUT', "Bloqueio temporário para IP: $ip ou Email: $email", null, 'WARNING');
        $mins = ceil(LOCKOUT_DURATION / 60);
        return [
            'success' => false,
            'error' => "Muitas tentativas. Sua conta ou IP foram bloqueados temporariamente."
        ];
    }

    // Validação de CAPTCHA
    if (shouldShowCaptcha($ip, $email)) {
        if (empty($captchaToken)) {
            return ['success' => false, 'error' => 'Por favor, complete o desafio de segurança.', 'captcha' => true];
        }
        
        if (!verifyTurnstile($captchaToken)) {
            logSecurityEvent('CAPTCHA_FAIL', "Falha na validação do Turnstile para: $email", null, 'WARNING');
            return ['success' => false, 'error' => 'Falha na verificação de segurança. Tente novamente.', 'captcha' => true];
        }
    }

    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT id, uuid, name, email, password_hash FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password_hash'])) {
        recordLoginAttempt($ip, $email);
        $remaining = getRemainingAttempts($ip, $email);
        $msg = 'Credenciais inválidas.';
        if ($remaining > 0 && $remaining <= 2) {
            $msg .= " {$remaining} tentativa(s) restante(s).";
        }
        return [
            'success' => false, 
            'error' => $msg, 
            'captcha' => shouldShowCaptcha($ip, $email)
        ];
    }

    // Login bem-sucedido
    clearLoginAttempts($ip, $email);
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_uuid'] = $user['uuid'];
    $_SESSION['user_name'] = $user['name'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['logged_in'] = true;
    $_SESSION['login_time'] = time();

    if (password_needs_rehash($user['password_hash'], PASSWORD_BCRYPT, ['cost' => 12])) {
        $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $pdo->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
        $stmt->execute(['hash' => $newHash, 'id' => $user['id']]);
    }

    if ($remember) {
        setRememberToken($user['id']);
    }

    return ['success' => true, 'message' => 'Login realizado com sucesso!'];
}

// ── Remember Me ─────────────────────────────────────────────────
function setRememberToken(int $userId): void
{
    $selector = bin2hex(random_bytes(8));
    $validator = bin2hex(random_bytes(32));
    $hash = hash('sha256', $validator);
    $expires = date('Y-m-d H:i:s', time() + REMEMBER_ME_DURATION);

    $pdo = getDBConnection();
    $stmt = $pdo->prepare(
        "INSERT INTO remember_tokens (user_id, selector, token_hash, expires_at) VALUES (:uid, :selector, :hash, :exp)"
    );
    $stmt->execute(['uid' => $userId, 'selector' => $selector, 'hash' => $hash, 'exp' => $expires]);

    setcookie('remember_me', "$selector:$validator", [
        'expires'  => time() + REMEMBER_ME_DURATION,
        'path'     => '/',
        'secure'   => isset($_SERVER['HTTPS']),
        'httponly'  => true,
        'samesite'  => 'Strict',
    ]);
}

function checkRememberToken(): bool
{
    if (!empty($_SESSION['logged_in'])) return true;
    if (empty($_COOKIE['remember_me'])) return false;

    $parts = explode(':', $_COOKIE['remember_me']);
    if (count($parts) !== 2) return false;

    [$selector, $validator] = $parts;
    $hash = hash('sha256', $validator);

    $pdo = getDBConnection();
    $stmt = $pdo->prepare(
        "SELECT rt.id, u.id AS uid, u.uuid, u.name, u.email, rt.token_hash
         FROM remember_tokens rt
         JOIN users u ON u.id = rt.user_id
         WHERE rt.selector = :selector AND rt.expires_at > NOW()"
    );
    $stmt->execute(['selector' => $selector]);
    $row = $stmt->fetch();

    if (!$row || !hash_equals($row['token_hash'], $hash)) {
        clearRememberCookies();
        return false;
    }

    $del = $pdo->prepare("DELETE FROM remember_tokens WHERE id = :id");
    $del->execute(['id' => $row['id']]);

    session_regenerate_id(true);
    $_SESSION['user_id'] = $row['uid'];
    $_SESSION['user_uuid'] = $row['uuid'];
    $_SESSION['user_name'] = $row['name'];
    $_SESSION['user_email'] = $row['email'];
    $_SESSION['logged_in'] = true;
    $_SESSION['login_time'] = time();

    setRememberToken($row['uid']);
    return true;
}

function clearRememberCookies(): void
{
    setcookie('remember_me', '', ['expires' => time() - 3600, 'path' => '/']);
}

// ── Proteção de Páginas ─────────────────────────────────────────
function requireAuth(): void
{
    initSecureSession();
    if (empty($_SESSION['logged_in'])) {
        if (!checkRememberToken()) {
            header('Location: login.php');
            exit;
        }
    }
}

function isLoggedIn(): bool
{
    return !empty($_SESSION['logged_in']);
}

// ── Logout ──────────────────────────────────────────────────────
function logoutUser(): void
{
    initSecureSession();

    if (!empty($_COOKIE['remember_me'])) {
        $parts = explode(':', $_COOKIE['remember_me']);
        if (count($parts) === 2) {
            $pdo = getDBConnection();
            $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE selector = :selector");
            $stmt->execute(['selector' => $parts[0]]);
        }
    }

    clearRememberCookies();
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly'  => $p['httponly'],
        ]);
    }
    session_destroy();
}

// ── Recuperação de Senha ────────────────────────────────────────
function requestPasswordReset(string $email): array
{
    $email = strtolower(trim($email));
    $genericMsg = 'Se o e-mail estiver cadastrado, você receberá um link de recuperação.';

    $pdo = getDBConnection();
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    if (!$user) {
        usleep(rand(100000, 300000));
        return ['success' => true, 'message' => $genericMsg];
    }

    $stmt = $pdo->prepare(
        "UPDATE password_resets SET used_at = NOW() WHERE user_id = :uid AND used_at IS NULL"
    );
    $stmt->execute(['uid' => $user['id']]);

    $token = bin2hex(random_bytes(32));
    $hash = hash('sha256', $token);
    $expires = date('Y-m-d H:i:s', time() + PASSWORD_RESET_EXPIRY);

    $stmt = $pdo->prepare(
        "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (:uid, :hash, :exp)"
    );
    $stmt->execute(['uid' => $user['id'], 'hash' => $hash, 'exp' => $expires]);

    return ['success' => true, 'message' => $genericMsg, 'token' => $token];
}

function resetPassword(string $token, string $newPassword): array
{
    $pwErrors = validatePasswordStrength($newPassword);
    if (!empty($pwErrors)) {
        return ['success' => false, 'error' => implode(' ', $pwErrors)];
    }

    $hash = hash('sha256', $token);
    $pdo = getDBConnection();

    $stmt = $pdo->prepare(
        "SELECT pr.id, pr.user_id FROM password_resets pr
         WHERE pr.token_hash = :hash AND pr.expires_at > NOW() AND pr.used_at IS NULL"
    );
    $stmt->execute(['hash' => $hash]);
    $reset = $stmt->fetch();

    if (!$reset) {
        return ['success' => false, 'error' => 'Token inválido ou expirado.'];
    }

    $newHash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
        $stmt->execute(['hash' => $newHash, 'id' => $reset['user_id']]);

        $stmt = $pdo->prepare("UPDATE password_resets SET used_at = NOW() WHERE id = :id");
        $stmt->execute(['id' => $reset['id']]);

        $stmt = $pdo->prepare("DELETE FROM remember_tokens WHERE user_id = :uid");
        $stmt->execute(['uid' => $reset['user_id']]);

        logSecurityEvent('PASSWORD_RESET', "Senha alterada via token de recuperação", $reset['user_id'], 'WARNING');

        $pdo->commit();
    } catch (Exception $e) {
        $pdo->rollBack();
        return ['success' => false, 'error' => 'Erro ao redefinir senha.'];
    }

    return ['success' => true, 'message' => 'Senha redefinida com sucesso!'];
}
