<?php
/**
 * Aegis Auth - Redefinir Senha
 */

require_once __DIR__ . '/../app/auth.php';
initSecureSession();

if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';
$token = $_GET['token'] ?? $_POST['token'] ?? '';

if (empty($token)) {
    header('Location: forgot-password.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Token de segurança inválido.';
    } else {
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['password_confirm'] ?? '';

        if ($password !== $confirm) {
            $error = 'As senhas não coincidem.';
        } else {
            $result = resetPassword($token, $password);
            if ($result['success']) {
                $_SESSION['password_reset_success'] = 'Senha redefinida! Faça login.';
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
    <meta name="description" content="Aegis Auth - Criar nova senha">
    <title>Nova Senha — Aegis Auth</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="auth-bg"></div>

    <div class="auth-wrapper">
        <div class="auth-card">
            <div class="auth-brand">
                <div class="shield-icon">🔄</div>
                <h1>Nova Senha</h1>
                <p>Defina sua nova senha segura</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <span>⚠️</span> <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="" id="reset-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">

                <div class="form-group">
                    <label for="password">Nova senha</label>
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
                        <button type="button" class="password-toggle" onclick="togglePassword('password', this)">👁️</button>
                    </div>
                    <div class="password-strength">
                        <div class="strength-bar">
                            <div class="strength-fill" id="strength-fill"></div>
                        </div>
                        <span class="strength-text" id="strength-text"></span>
                    </div>
                </div>

                <div class="form-group">
                    <label for="password_confirm">Confirmar nova senha</label>
                    <div class="input-wrapper">
                        <span class="input-icon">🔒</span>
                        <input 
                            type="password" 
                            id="password_confirm" 
                            name="password_confirm" 
                            class="form-input" 
                            placeholder="Repita a nova senha"
                            required
                            autocomplete="new-password"
                        >
                    </div>
                </div>

                <button type="submit" class="btn btn-primary">
                    Redefinir Senha
                </button>
            </form>

            <div class="auth-footer">
                <p><a href="login.php">Voltar ao login</a></p>
            </div>
        </div>
    </div>

    <script>
    function togglePassword(inputId, btn) {
        const input = document.getElementById(inputId);
        input.type = input.type === 'password' ? 'text' : 'password';
        btn.textContent = input.type === 'password' ? '👁️' : '🙈';
    }

    const pw = document.getElementById('password');
    const fill = document.getElementById('strength-fill');
    const text = document.getElementById('strength-text');
    pw.addEventListener('input', function() {
        const v = this.value;
        let s = 0;
        if (v.length >= 8) s++;
        if (/[A-Z]/.test(v)) s++;
        if (/[a-z]/.test(v)) s++;
        if (/[0-9]/.test(v)) s++;
        if (/[^A-Za-z0-9]/.test(v)) s++;
        fill.className = 'strength-fill';
        const map = [
            ['', '', ''],
            ['weak', 'Fraca', '#ef4444'],
            ['fair', 'Razoável', '#f59e0b'],
            ['good', 'Boa', '#3b82f6'],
            ['strong', 'Forte', '#10b981'],
            ['strong', 'Forte', '#10b981']
        ];
        if (v.length === 0) { text.textContent = ''; return; }
        fill.classList.add(map[s][0]);
        text.textContent = map[s][1];
        text.style.color = map[s][2];
    });
    </script>
</body>
</html>
