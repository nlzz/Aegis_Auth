# Aegis Auth

**Sistema de Autenticação Segura em PHP**

O Aegis Auth é uma solução de autenticação robusta desenvolvida em PHP puro, projetada sob princípios de "Security by Design". O sistema implementa múltiplas camadas de proteção contra os vetores de ataque mais comuns na web, priorizando a integridade dos dados e a privacidade dos usuários.

---

## Funcionalidades Principais

### Gerenciamento de Identidade
- **Cadastro e Login:** Fluxos completos com validação rigorosa de dados.
- **Área Restrita:** Dashboard protegido com verificação persistente de estado.
- **Recuperação de Senha:** Processo seguro via tokens temporários e proteção contra ataques de temporização (Timing Attacks).
- **Lembrar-me:** Persistência de sessão utilizando o padrão Selector/Validator para evitar a exposição de IDs de usuário.

### Camadas de Segurança
- **Criptografia:** Armazenamento de senhas utilizando `password_hash()` com algoritmo Bcrypt (cost 12).
- **Proteção de Sessão:** Cookies configurados com `HttpOnly`, `SameSite=Strict` e regeneração periódica de IDs.
- **Defesa contra Injeção:** Uso exclusivo de PDO com Prepared Statements (Emulação desativada).
- **CSRF Protection:** Tokens de segurança persistidos em banco de dados, suportando navegação em múltiplas abas.
- **Auditoria:** Log detalhado de eventos críticos (registros, logins, trocas de senha e bloqueios).
- **Segurança de Navegador:** Implementação de cabeçalhos CSP, HSTS, X-Frame-Options e Referrer-Policy.

### Infraestrutura Defensiva
- **Bloqueio Híbrido:** Monitoramento de tentativas falhas por endereço IP e por conta de e-mail.
- **CAPTCHA Inteligente:** Integração com Cloudflare Turnstile, ativado dinamicamente após detecção de comportamento suspeito.
- **Identificadores Únicos:** Uso de UUID v4 para identificação pública, ocultando chaves primárias sequenciais.

---

## Arquitetura do Projeto

```
aegis-auth/
├── app/
│   └── auth.php           # Núcleo de lógica e funções de segurança
├── config/
│   └── database.php       # Configurações globais e constantes
├── database/
│   └── schema.sql         # Definição das tabelas e índices
├── public/                # Diretório raiz do servidor web
│   ├── assets/            # Recursos estáticos (CSS, JS, Imagens)
│   ├── dashboard.php      # Painel administrativo
│   ├── login.php          # Interface de autenticação
│   └── register.php       # Interface de cadastro
├── .env.example           # Modelo para variáveis de ambiente
└── README.md
```

---

## Requisitos e Instalação

### Pré-requisitos
- PHP 8.0 ou superior
- MySQL 5.7+ ou MariaDB 10.3+
- Extensão `php-curl` habilitada para integração com Turnstile

### Guia de Instalação

1. **Configuração do Banco de Dados:**
   Importe o schema localizado em `database/schema.sql` para o seu servidor MySQL.

2. **Variáveis de Ambiente:**
   Crie um arquivo `.env` na raiz do projeto seguindo o modelo `.env.example`. É obrigatório definir as credenciais do banco para que o sistema funcione.

3. **Configuração do CAPTCHA (Opcional):**
   Obtenha as chaves no painel do Cloudflare Turnstile e adicione-as ao arquivo `.env`. Se não configuradas, o sistema operará apenas com o bloqueio por IP/Conta.

4. **Execução:**
   Inicie o servidor PHP apontando para o diretório `public/`:
   ```bash
   php -S localhost:8000 -t public
   ```

---

## Licença

Este projeto está licenciado sob a MIT License. Consulte o arquivo [LICENSE](LICENSE) para obter detalhes.
