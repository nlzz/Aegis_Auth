<?php
/**
 * Aegis Auth - Página de Login
 */

require_once __DIR__ . '/../app/auth.php';
initSecureSession();

// Se já logado, redireciona
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Token de segurança inválido. Recarregue a página.';
    } else {
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $remember = isset($_POST['remember']);

        $result = loginUser($email, $password, $remember);

        if ($result['success']) {
            header('Location: dashboard.php');
            exit;
        } else {
            $error = $result['error'];
        }
    }
}

// Mensagem de sucesso vinda do cadastro
if (isset($_SESSION['register_success'])) {
    $success = $_SESSION['register_success'];
    unset($_SESSION['register_success']);
}

// Mensagem de reset de senha
if (isset($_SESSION['password_reset_success'])) {
    $success = $_SESSION['password_reset_success'];
    unset($_SESSION['password_reset_success']);
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Aegis Auth - Acesse sua conta com segurança">
    <title>Login — Aegis Auth</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="auth-bg"></div>

    <div class="auth-wrapper">
        <div class="auth-card">
            <!-- Brand -->
            <div class="auth-brand">
                <div class="shield-icon">🛡️</div>
                <h1>Aegis Auth</h1>
                <p>Acesse sua conta com segurança</p>
            </div>

            <!-- Alerts -->
            <?php if ($error): ?>
                <div class="alert alert-error" id="alert-error">
                    <span>⚠️</span> <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success" id="alert-success">
                    <span>✅</span> <?= htmlspecialchars($success) ?>
                </div>
            <?php endif; ?>

            <!-- Login Form -->
            <form method="POST" action="" id="login-form" autocomplete="on">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

                <div class="form-group">
                    <label for="email">E-mail</label>
                    <div class="input-wrapper">
                        <span class="input-icon">✉️</span>
                        <input 
                            type="email" 
                            id="email" 
                            name="email" 
                            class="form-input" 
                            placeholder="seu@email.com"
                            value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                            required 
                            autofocus
                            autocomplete="email"
                        >
                    </div>
                </div>

                <div class="form-group">
                    <label for="password">Senha</label>
                    <div class="input-wrapper">
                        <span class="input-icon">🔒</span>
                        <input 
                            type="password" 
                            id="password" 
                            name="password" 
                            class="form-input" 
                            placeholder="Sua senha"
                            required
                            autocomplete="current-password"
                        >
                        <button type="button" class="password-toggle" onclick="togglePassword('password', this)" aria-label="Mostrar senha">
                            👁️
                        </button>
                    </div>
                </div>

                <div class="form-options">
                    <div class="form-check">
                        <input type="checkbox" id="remember" name="remember">
                        <label for="remember">Lembrar de mim</label>
                    </div>
                    <a href="forgot-password.php" class="auth-link">Esqueceu a senha?</a>
                </div>

                <?php if ($showCaptcha): ?>
                    <div class="captcha-container" style="margin-bottom: 1.5rem; display: flex; justify-content: center;">
                        <div class="cf-turnstile" data-sitekey="<?= htmlspecialchars(TURNSTILE_SITE_KEY) ?>" data-theme="light"></div>
                    </div>
                <?php endif; ?>

                <button type="submit" class="btn btn-primary" id="btn-login">
                    Entrar
                </button>
            </form>

            <div class="auth-footer">
                <p>Não tem uma conta? <a href="register.php">Criar conta</a></p>
            </div>
        </div>
    </div>

    <script>
    function togglePassword(inputId, btn) {
        const input = document.getElementById(inputId);
        if (input.type === 'password') {
            input.type = 'text';
            btn.textContent = '🙈';
        } else {
            input.type = 'password';
            btn.textContent = '👁️';
        }
    }
    </script>
</body>
</html>
>
                <p>Não tem uma conta? <a href="register.php">Criar conta</a></p>
            </div>
        </div>
    </div>

    <script>
    function togglePassword(inputId, btn) {
        const input = document.getElementById(inputId);
        if (input.type === 'password') {
            input.type = 'text';
            btn.textContent = '🙈';
        } else {
            input.type = 'password';
            btn.textContent = '👁️';
        }
    }
    </script>
</body>
</html>
