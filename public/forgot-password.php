<?php
/**
 * Aegis Auth - Esqueceu a Senha
 */

require_once __DIR__ . '/../app/auth.php';
initSecureSession();

if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$success = '';
$resetToken = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Token de segurança inválido.';
    } else {
        $email = $_POST['email'] ?? '';
        if (!validateEmail($email)) {
            $error = 'E-mail inválido.';
        } else {
            $result = requestPasswordReset($email);
            $success = $result['message'];
            if (isset($result['token'])) {
                $resetToken = $result['token'];
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
    <meta name="description" content="Aegis Auth - Recuperar senha">
    <title>Recuperar Senha — Aegis Auth</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="auth-bg"></div>

    <div class="auth-wrapper">
        <div class="auth-card">
            <div class="auth-brand">
                <div class="shield-icon">🔑</div>
                <h1>Recuperar Senha</h1>
                <p>Informe seu e-mail para receber o link</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-error">
                    <span>⚠️</span> <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <?php if ($success): ?>
                <div class="alert alert-success">
                    <span>✅</span> <?= htmlspecialchars($success) ?>
                </div>
            <?php endif; ?>

            <?php if ($resetToken): ?>
                <div class="alert alert-info">
                    <span>ℹ️</span>
                    <div>
                        <strong>Demo:</strong> Em produção, o link seria enviado por e-mail.<br>
                        <a href="reset-password.php?token=<?= htmlspecialchars($resetToken) ?>" class="auth-link" style="font-size: 0.75rem; word-break: break-all;">
                            Clique aqui para redefinir →
                        </a>
                    </div>
                </div>
            <?php endif; ?>

            <form method="POST" action="" id="forgot-form">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

                <div class="form-group">
                    <label for="email">E-mail cadastrado</label>
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
                        >
                    </div>
                </div>

                <button type="submit" class="btn btn-primary" id="btn-forgot">
                    Enviar Link de Recuperação
                </button>
            </form>

            <div class="auth-footer">
                <p>Lembrou a senha? <a href="login.php">Voltar ao login</a></p>
            </div>
        </div>
    </div>
</body>
</html>
