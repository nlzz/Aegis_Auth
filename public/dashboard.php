<?php
/**
 * Aegis Auth - Dashboard Privado
 */

require_once __DIR__ . '/../app/auth.php';
initSecureSession();
requireAuth();

$userName = $_SESSION['user_name'] ?? 'Usuário';
$userEmail = $_SESSION['user_email'] ?? '';
$loginTime = $_SESSION['login_time'] ?? time();
$initials = strtoupper(substr($userName, 0, 1));

// Dados para exibição
$sessionDuration = time() - $loginTime;
$sessionMinutes = floor($sessionDuration / 60);
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Aegis Auth - Painel de controle seguro">
    <title>Dashboard — Aegis Auth</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="auth-bg"></div>

    <div class="dashboard-layout">
        <!-- Navbar -->
        <nav class="navbar">
            <a href="dashboard.php" class="navbar-brand">
                <div class="brand-icon">🛡️</div>
                <span>Aegis Auth</span>
            </a>
            <div class="navbar-actions">
                <div class="user-info">
                    <div class="user-details">
                        <span class="name"><?= htmlspecialchars($userName) ?></span>
                        <span class="email"><?= htmlspecialchars($userEmail) ?></span>
                        <small style="opacity: 0.5; font-size: 0.7rem;">ID: <?= htmlspecialchars($_SESSION['user_uuid'] ?? 'N/A') ?></small>
                    </div>
                    <div class="user-avatar"><?= htmlspecialchars($initials) ?></div>
                </div>
                <a href="logout.php" class="btn btn-danger" id="btn-logout" style="padding: 0.5rem 1rem; font-size: 0.8125rem;">
                    Sair
                </a>
            </div>
        </nav>

        <!-- Content -->
        <main class="dashboard-content">
            <div class="welcome-section">
                <h2>Bem-vindo, <?= htmlspecialchars(explode(' ', $userName)[0]) ?>! 👋</h2>
                <p>Seu painel de controle está seguro e protegido.</p>
            </div>

            <!-- Stats -->
            <div class="stats-grid">
                <div class="stat-card" style="animation-delay: 0.1s;">
                    <div class="stat-icon purple">🔐</div>
                    <div class="stat-value">Ativa</div>
                    <div class="stat-label">Sessão atual</div>
                </div>
                <div class="stat-card" style="animation-delay: 0.2s;">
                    <div class="stat-icon green">⏱️</div>
                    <div class="stat-value" id="session-time"><?= $sessionMinutes ?>min</div>
                    <div class="stat-label">Tempo de sessão</div>
                </div>
                <div class="stat-card" style="animation-delay: 0.3s;">
                    <div class="stat-icon blue">🛡️</div>
                    <div class="stat-value">Bcrypt</div>
                    <div class="stat-label">Hash da senha</div>
                </div>
                <div class="stat-card" style="animation-delay: 0.4s;">
                    <div class="stat-icon amber">🔄</div>
                    <div class="stat-value">CSRF</div>
                    <div class="stat-label">Token ativo</div>
                </div>
            </div>

            <!-- Security Features -->
            <div class="info-card">
                <h3>🔒 Recursos de Segurança Ativos</h3>
                <ul class="security-list">
                    <li><span class="check">✅</span> Senha protegida com <strong>bcrypt</strong> (cost 12)</li>
                    <li><span class="check">✅</span> Proteção <strong>CSRF</strong> em todos os formulários</li>
                    <li><span class="check">✅</span> Sessão segura com <strong>HttpOnly</strong> e <strong>SameSite</strong></li>
                    <li><span class="check">✅</span> <strong>PDO Prepared Statements</strong> contra SQL Injection</li>
                    <li><span class="check">✅</span> Bloqueio após <strong><?= MAX_LOGIN_ATTEMPTS ?> tentativas</strong> falhas</li>
                    <li><span class="check">✅</span> Regeneração automática do <strong>Session ID</strong></li>
                    <li><span class="check">✅</span> Validação de <strong>força da senha</strong> no cadastro</li>
                    <li><span class="check">✅</span> Mensagens de erro <strong>genéricas</strong> no login</li>
                    <li><span class="check">✅</span> Token <strong>"Lembrar-me"</strong> com rotação e hash SHA-256</li>
                    <li><span class="check">✅</span> Recuperação de senha com <strong>token temporário</strong></li>
                </ul>
            </div>
        </main>
    </div>

    <script>
    // Atualiza o tempo de sessão em tempo real
    let seconds = <?= $sessionDuration ?>;
    const timeEl = document.getElementById('session-time');
    setInterval(() => {
        seconds++;
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        timeEl.textContent = m + 'min ' + (s < 10 ? '0' : '') + s + 's';
    }, 1000);
    </script>
</body>
</html>
