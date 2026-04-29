# 🛡️ Aegis Auth

**Sistema Seguro de Autenticação em PHP**

Um sistema de autenticação completo construído com PHP puro, focado em boas práticas de segurança. O nome "Aegis" vem do escudo de Zeus na mitologia grega — proteção em primeiro lugar.

---

## ✨ Funcionalidades

### Core
- ✅ **Cadastro** de usuários com validação completa
- ✅ **Login** seguro com sessão protegida
- ✅ **Dashboard** privado (área autenticada)
- ✅ **Logout** com destruição completa da sessão

### Segurança
- 🔐 **Hash de senha** com `password_hash()` (bcrypt, cost 12)
- 🔐 **Verificação** com `password_verify()`
- 🔐 **CSRF Token** em todos os formulários
- 🔐 **PDO Prepared Statements** contra SQL Injection
- 🔐 **Sessão segura** (HttpOnly, SameSite, Strict Mode)
- 🔐 **Regeneração de Session ID** periódica
- 🔐 **Mensagens genéricas** no login (não revela se email existe)
- 🔐 **Sanitização** de todos os inputs

### Extras
- 🔄 **Lembrar-me** com token rotativo (SHA-256)
- 🚫 **Bloqueio** após 5 tentativas falhas (15 min)
- 📧 **Recuperação de senha** com token temporário
- 💪 **Validação de força da senha** em tempo real
- 🔄 **Rehash automático** quando o algoritmo muda

---

## 📁 Estrutura

```
aegis-auth/
├── public/
│   ├── assets/
│   │   └── css/
│   │       └── style.css         # Design system premium
│   ├── login.php                 # Página de login
│   ├── register.php              # Página de cadastro
│   ├── dashboard.php             # Painel privado
│   ├── logout.php                # Handler de logout
│   ├── forgot-password.php       # Solicitar reset
│   └── reset-password.php        # Redefinir senha
├── config/
│   └── database.php              # Configuração PDO
├── app/
│   └── auth.php                  # Módulo de autenticação
├── database/
│   └── schema.sql                # Schema do banco
├── README.md
└── LICENSE
```

---

## 🚀 Instalação

### Pré-requisitos
- PHP 8.0+
- MySQL 5.7+ ou MariaDB 10.3+
- Servidor web (Apache/Nginx) ou PHP built-in server

### Passo a passo

1. **Clone o repositório**
```bash
git clone https://github.com/seu-usuario/aegis-auth.git
cd aegis-auth
```

2. **Crie o banco de dados**
```bash
mysql -u root -p < database/schema.sql
```

3. **Configure as credenciais** em `config/database.php`
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'aegis_auth');
define('DB_USER', 'root');
define('DB_PASS', 'sua_senha');
```

4. **Inicie o servidor**
```bash
php -S localhost:8000 -t public
```

5. **Acesse** → `http://localhost:8000/register.php`

---

## 🗄️ Banco de Dados

### Tabela `users`
| Campo | Tipo | Descrição |
|-------|------|-----------|
| id | INT (PK) | Identificador |
| name | VARCHAR(100) | Nome do usuário |
| email | VARCHAR(255) | E-mail (unique) |
| password_hash | VARCHAR(255) | Hash bcrypt |
| created_at | TIMESTAMP | Data de criação |

### Tabela `remember_tokens`
Armazena tokens "lembrar-me" com rotação a cada uso.

### Tabela `login_attempts`
Registra tentativas para proteção contra brute force.

### Tabela `password_resets`
Tokens temporários para recuperação de senha.

---

## 🔐 Fluxo de Segurança

```
Cadastro → Validação → Hash (bcrypt) → Salva no DB
Login → Verifica bloqueio → Busca user → password_verify() → Sessão segura
Dashboard → requireAuth() → Checa sessão + remember token
Logout → Destroi sessão + cookies + tokens
Reset → Token SHA-256 → Link temporário → Nova senha com hash
```

---

## ⚙️ Configurações de Segurança

| Constante | Valor | Descrição |
|-----------|-------|-----------|
| MAX_LOGIN_ATTEMPTS | 5 | Tentativas antes do bloqueio |
| LOCKOUT_DURATION | 900s | Tempo de bloqueio (15 min) |
| REMEMBER_ME_DURATION | 30 dias | Validade do "lembrar-me" |
| PASSWORD_RESET_EXPIRY | 3600s | Validade do link de reset |
| SESSION_LIFETIME | 1800s | Tempo da sessão (30 min) |
| MIN_PASSWORD_LENGTH | 8 | Tamanho mínimo da senha |

---

## 📋 Licença

MIT License — veja [LICENSE](LICENSE).
