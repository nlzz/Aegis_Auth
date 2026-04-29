<?php
/**
 * Aegis Auth - Página de Cadastro
 */

require_once __DIR__ . '/../app/auth.php';
initSecureSession();

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
        $name = $_POST['name'] ?? '';
        $email = $_POST['email'] ?? '';
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['password_confirm'] ?? '';

        if ($password !== $confirm) {
            $error = 'As senhas não coincidem.';
        } else {
            $result = registerUser($name, $email, $password);
            if ($result['success']) {
                $_SESSION['register_success'] = 'Conta criada com sucesso! Faça login.';
                header('Location: login.php');
                exit;
            } else {
                $error = $result['error'];
            }
        }
    }
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Aegis Auth - Crie sua conta segura">
    <title>Cadastro — Aegis Auth</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="auth-bg"></div>

    <div class="auth-wrapper">
        <div class="auth-card">
            <div class="auth-brand">
                <div class="shield-icon">🛡️</div>
                <h1>Criar Conta</h1>
                <p>Preencha os dados para se cadastrar</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <span>⚠️</span> <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="" id="register-form" autocomplete="on">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

                <div class="form-group">
                    <label for="name">Nome completo</label>
                    <div class="input-wrapper">
                        <span class="input-icon">👤</span>
                        <input 
                            type="text" 
                            id="name" 
                            name="name" 
                            class="form-input" 
                            placeholder="Seu nome"
                            value="<?= htmlspecialchars($_POST['name'] ?? '') ?>"
                            required 
                            autofocus
                            autocomplete="name"
                            minlength="2"
                            maxlength="100"
                        >
                    </div>
                </div>

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
                            placeholder="Crie uma senha forte"
                            required
                            autocomplete="new-password"
                            minlength="8"
                        >
                        <button type="button" class="password-toggle" onclick="togglePassword('password', this)" aria-label="Mostrar senha">
                            👁️
                        </button>
                    </div>
                    <div class="password-strength" id="pw-strength">
                        <div class="strength-bar">
                            <div class="strength-fill" id="strength-fill"></div>
                        </div>
                        <span class="strength-text" id="strength-text"></span>
                    </div>
                </div>

                <div class="form-group">
                    <label for="password_confirm">Confirmar senha</label>
                    <div class="input-wrapper">
                        <span class="input-icon">🔒</span>
                        <input 
                            type="password" 
                            id="password_confirm" 
                            name="password_confirm" 
                            class="form-input" 
                            placeholder="Repita a senha"
                            required
                            autocomplete="new-password"
                        >
                    </div>
                </div>

                <button type="submit" class="btn btn-primary" id="btn-register">
                    Criar Conta
                </button>
            </form>

            <div class="auth-footer">
                <p>Já tem uma conta? <a href="login.php">Fazer login</a></p>
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

    // Password strength meter
    const pwInput = document.getElementById('password');
    const fill = document.getElementById('strength-fill');
    const text = document.getElementById('strength-text');

    pwInput.addEventListener('input', function() {
        const pw = this.value;
        let score = 0;
        if (pw.length >= 8) score++;
        if (/[A-Z]/.test(pw)) score++;
        if (/[a-z]/.test(pw)) score++;
        if (/[0-9]/.test(pw)) score++;
        if (/[^A-Za-z0-9]/.test(pw)) score++;

        fill.className = 'strength-fill';
        if (pw.length === 0) {
            text.textContent = '';
        } else if (score <= 1) {
            fill.classList.add('weak');
            text.textContent = 'Fraca';
            text.style.color = '#ef4444';
        } else if (score <= 2) {
            fill.classList.add('fair');
            text.textContent = 'Razoável';
            text.style.color = '#f59e0b';
        } else if (score <= 3) {
            fill.classList.add('good');
            text.textContent = 'Boa';
            text.style.color = '#3b82f6';
        } else {
            fill.classList.add('strong');
            text.textContent = 'Forte';
            text.style.color = '#10b981';
        }
    });
    </script>
</body>
</html>
