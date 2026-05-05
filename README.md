# Operation Zero Trust — IAM Lab

![Status](https://img.shields.io/badge/status-conclu%C3%ADdo-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-Microsoft%20Entra%20ID-0078D4?logo=microsoft)
![License](https://img.shields.io/badge/license-MIT-green)

Laboratório de **Identity and Access Management (IAM)** que simula e previne
o [ataque Uber 2022](docs/01-caso-uber-2022.md) usando **Microsoft Entra ID**
e a **Microsoft Graph API**.

---

## Por que o Uber 2022?

Em setembro de 2022, um invasor de 18 anos comprometeu completamente a Uber em
menos de 8 horas — acessando AWS, GCP, GitHub, Slack e o cofre de senhas corporativo.
O vetor inicial foi um único contratado com credenciais fracas, sem MFA resistente
a phishing e com acesso excessivo aos sistemas internos.

Este laboratório reconstrói os 3 perfis de identidade do ataque e demonstra,
com código real chamando a Graph API, quais controles de IAM teriam bloqueado
cada fase da cadeia de comprometimento.

---

## Arquitetura do Lab

```
operation-zero-trust-iam-lab/
├── .env.example              ← Template de variáveis de ambiente
├── .gitignore                ← Protege .env de ser commitado
├── requirements.txt          ← Dependências Python
├── README.md                 ← Este arquivo
├── screenshots/              ← Evidências de execução real
├── scripts/
│   ├── 01_auth_and_list_users.py   ← OAuth 2.0 + Inventário de identidades
│   ├── 02_create_test_users.py     ← Provisionamento de usuários por perfil de risco
│   ├── 03_assign_rbac_roles.py     ← RBAC + Princípio do Menor Privilégio
│   └── 04_audit_log_report.py      ← Auditoria contínua + Postura Zero Trust
└── docs/
    └── 01-caso-uber-2022.md        ← Análise técnica do ataque com NIST CSF / ISO 27001
```

---

## Pré-requisitos

- **Python 3.11+**
- **Conta Microsoft Azure** (conta gratuita funciona para o lab)
- **App registrado no Microsoft Entra ID** com as permissões abaixo

### Permissões necessárias no Azure AD

| Permissão | Tipo | Script que usa | Por quê |
|-----------|------|---------------|---------|
| `User.Read.All` | Application | 01, 02, 03, 04 | Listar e buscar usuários |
| `User.ReadWrite.All` | Application | 02 | Criar usuários de teste |
| `RoleManagement.ReadWrite.Directory` | Application | 03 | Atribuir papéis RBAC |
| `AuditLog.Read.All` | Application | 04 | Consultar logs de auditoria |

> **Todas as permissões devem ser do tipo "Application"** (não Delegated), pois
> os scripts rodam sem usuário presente (Client Credentials Flow).
> Um administrador do tenant deve conceder consentimento via "Grant admin consent".

---

## Configuração

### 1. Clone o repositório

```bash
git clone https://github.com/DevHefesto/operation-zero-trust-iam-lab.git
cd operation-zero-trust-iam-lab
```

### 2. Crie o ambiente virtual e instale as dependências

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure as variáveis de ambiente

```bash
cp .env.example .env
```

Edite o arquivo `.env` com os valores do seu app registrado no Azure:

```env
TENANT_ID=ab9583df-0000-0000-0000-000000000000
CLIENT_ID=a1fbd815-0000-0000-0000-000000000000
CLIENT_SECRET=seu-client-secret-aqui
TENANT_DOMAIN=seudominio.onmicrosoft.com
```

**Onde encontrar esses valores:**
- `TENANT_ID` → Azure Portal → Entra ID → Overview → **Tenant ID**
- `CLIENT_ID` → Azure Portal → Entra ID → App Registrations → seu app → **Application (client) ID**
- `CLIENT_SECRET` → Azure Portal → Entra ID → App Registrations → seu app → **Certificates & secrets**
- `TENANT_DOMAIN` → Azure Portal → Entra ID → Overview → **Primary domain**

---

## Executando os Scripts

Execute os scripts **em ordem** — cada um constrói sobre o resultado do anterior.

### Script 01 — Autenticação e Inventário de Identidades

```bash
python scripts/01_auth_and_list_users.py
```

**O que faz:** Autentica via OAuth 2.0 (Client Credentials Flow) e lista todos
os usuários do tenant formatados em tabela.

**Conceito IAM demonstrado:** Visibilidade de identidades (NIST CSF — Identify).
Em Zero Trust, não é possível proteger o que não se conhece.

**Output real obtido:**

```
======================================================================
  OPERATION ZERO TRUST — Script 01: Auth + Inventário de Identidades
======================================================================
[*] Solicitando token de acesso ao Microsoft Entra ID...
[OK] Token obtido com sucesso.
     Tipo: Bearer
     Expira em: 3599 segundos (~59 minutos)
[*] Consultando usuários via Graph API...

======================================================================
  INVENTÁRIO DE IDENTIDADES — 1 usuário(s) encontrado(s)
======================================================================
╭──────────────────┬──────────────────────────────────────────────────┬───────╮
│ Nome             │ UPN (Login)                                      │ Status│
├──────────────────┼──────────────────────────────────────────────────┼───────┤
│ pedro Macedo     │ pedromacedo51_hotmail.com#EXT#@[tenant].onmicro… │ ATIVO │
╰──────────────────┴──────────────────────────────────────────────────┴───────╯
```

> **Observação técnica:** O `#EXT#` no UPN indica **External User** — conta Microsoft
> pessoal (Hotmail) federada no tenant via B2B. Este formato replica exatamente o
> modelo de identidade de contratados externos, análogo ao vetor inicial do ataque
> Uber 2022. Identidades externas exigem controles adicionais de Conditional Access.

---

### Script 02 — Criação de Usuários (Perfis de Risco Uber 2022)

```bash
python scripts/02_create_test_users.py
```

**O que faz:** Cria 3 usuários que simulam os perfis de identidade do ataque Uber:

| Usuário | Perfil de Risco | Analogia com Uber 2022 |
|---------|----------------|------------------------|
| `uber-admin@[tenant]` | CRÍTICO | Admin com acesso global comprometido |
| `uber-contractor@[tenant]` | ALTO | Contratado — vetor inicial do ataque |
| `uber-readonly@[tenant]` | BAIXO | Modelo de Least Privilege (correto) |

**Conceito IAM demonstrado:** Provisionamento de identidades com consciência
de perfil de risco (IGA — Identity Governance & Administration).

**Output real obtido:** 3 usuários criados com sucesso via `POST /v1.0/users`.
Senhas temporárias geradas com `secrets.choice()` (CSPRNG) — nunca `random()`.

---

### Script 03 — Atribuição de Papéis RBAC

```bash
python scripts/03_assign_rbac_roles.py
```

**O que faz:** Atribui papéis do Entra ID aos usuários de teste, reduzindo
a superfície de ataque de cada identidade:

| Usuário | Papel Atribuído | Risco Antes | Risco Depois |
|---------|----------------|------------|--------------|
| uber-admin | Global Reader | CRÍTICO | MÉDIO |
| uber-contractor | Helpdesk Administrator | ALTO | BAIXO |
| uber-readonly | Nenhum (padrão) | BAIXO | MÍNIMO |

**Conceito IAM demonstrado:** Princípio do Menor Privilégio (PoLP) —
limitar o blast radius em caso de comprometimento de credencial.

**Conexão com Uber 2022:** O contratado comprometido tinha acesso a sistemas
que não eram necessários para sua função. Com RBAC granular, mesmo com a
credencial comprometida, o invasor não teria chegado ao Thycotic.

**O que realmente aconteceu na execução:**

- **1ª execução:** papéis não encontrados via API — ainda não estavam ativados
  no tenant. Comportamento esperado do Entra ID: papéis built-in existem no
  catálogo global mas precisam ser instanciados no tenant antes de serem gerenciados.
- **Solução aplicada:** papéis ativados manualmente no portal Entra ID:
  *Leitor Global* → `uber-admin` · *Administrador da Assistência Técnica* → `uber-contractor`
- **2ª execução:** retornou HTTP 400 "already exists" — as atribuições já estavam
  corretas no tenant. O script interpretou como falha, mas o estado real estava certo.
- **Lição:** a fonte de verdade em automações IAM é sempre a API de leitura, não
  o código de status da operação de escrita. Queries de verificação são mais
  confiáveis que respostas de `POST`/`PATCH`.

---

### Script 04 — Relatório de Auditoria IAM

```bash
python scripts/04_audit_log_report.py
```

**O que faz:** Consulta os logs de auditoria e autenticações das últimas 24h
e gera um relatório de postura Zero Trust do lab.

**Conceito IAM demonstrado:** Monitoramento contínuo e detecção de anomalias
(NIST CSF — Detect). Auditorias proativas são a diferença entre detectar um
ataque em 8 horas (Uber) e em 8 minutos.

**Output real obtido:**

- **52 eventos de auditoria** capturados — linha do tempo forense completa:
  registro do app, configuração de permissões, criação dos 3 usuários, atribuição
  de papéis. Toda a cadeia de ações do lab rastreada pelo Entra ID.
- **Sign-in logs indisponíveis** — `AuditLog.Read.All` concedida como Application,
  mas logs de autenticação exigem licença **Entra ID P1 ou P2**. Limitação
  documentada; em produção, P1 é o mínimo recomendado para segurança.
- **Postura Zero Trust:** 4 controles `IMPLEMENTADO`, 4 `NÃO TESTADO`.

---

## O Que Este Lab Demonstra para Recrutadores de IAM

Este projeto demonstra, com código funcional e execução real documentada,
as competências centrais de um profissional de IAM / Cybersecurity:

| Competência | Onde é demonstrada |
|-------------|-------------------|
| **OAuth 2.0 / OIDC** | Script 01 — Client Credentials Flow com MSAL |
| **Microsoft Graph API** | Scripts 01–04 — chamadas REST autenticadas |
| **RBAC Design** | Script 03 — atribuição de papéis por perfil de risco |
| **Identity Governance** | Script 02 — provisionamento controlado com PoLP |
| **Audit & Compliance** | Script 04 — relatório alinhado a NIST CSF e ISO 27001 |
| **Threat Modeling** | `docs/01-caso-uber-2022.md` — análise de ataque real |
| **Security by Design** | Todo o código — sem credenciais hardcoded, sem over-provisioning |
| **Zero Trust Principles** | Arquitetura geral — never trust, always verify |

---

## Lições Aprendidas

Situações reais encontradas durante a execução do lab — parte integrante
do aprendizado prático de IAM.

**Permissões Delegated vs. Application**
Client Credentials Flow exige permissões do tipo `Application`, não `Delegated`.
A tentativa inicial com permissões Delegadas gerou erro silencioso de autenticação
sem mensagem clara. Este é um dos erros mais comuns na integração com a Graph API
e um conceito central para qualquer automação IAM.

**Ativação de papéis built-in no Entra ID**
Papéis como *Global Reader* e *Helpdesk Administrator* existem no catálogo global
do Entra ID, mas precisam ser **instanciados** no tenant antes de serem gerenciáveis
via API. Em produção, times de IAM mantêm um catálogo de papéis pré-ativados como
parte do processo de onboarding de tenant.

**Idempotência em automações IAM**
HTTP 400 "already exists" não é um erro — é confirmação de estado desejado.
Automações robustas de IAM devem **verificar o estado atual antes de escrever**,
não interpretar respostas de escrita como indicadores de sucesso ou falha.
O padrão correto: `GET` para verificar → `POST`/`PATCH` apenas se necessário.

**Timeout em queries de auditoria**
`GET /auditLogs/directoryAudits` pode ultrapassar 30s em tenants com muitos eventos.
Em produção: use filtros de data mais curtos, paginação agressiva e considere
streaming via Microsoft Graph Change Notifications para volumes altos.

**External User (`#EXT#`) como modelo de contratado**
Conta Microsoft pessoal (Hotmail) federada via B2B gera UPN com sufixo `#EXT#` —
replicando exatamente o modelo de identidade externa do ataque Uber 2022.
Identidades externas requerem políticas de Conditional Access específicas,
revisões de acesso mais frequentes e escopo de convite explicitamente limitado.

---

## Próximos Passos (Roadmap)

**Fase 1 — Concluída**
- [x] Script 01 — OAuth 2.0 + Inventário de identidades
- [x] Script 02 — Provisionamento por perfil de risco
- [x] Script 03 — RBAC + Least Privilege
- [x] Script 04 — Auditoria contínua + Postura Zero Trust

**Fase 2 — Em desenvolvimento**
- [ ] Script 05 — Conditional Access Policies via Graph API
- [ ] Script 06 — Simulação de MFA Fatigue + alertas
- [ ] Script 07 — Access Review automatizado

**Fase 3 — Planejada**
- [ ] Integração com Microsoft Sentinel (SIEM)
- [ ] Terraform para provisionamento da infra do lab

---

## Screenshots do Lab

| Script | Evidência |
|--------|-----------|
| Script 01 — Token OAuth + Inventário | [screenshots/01_auth_inventario.jpg](screenshots/01_auth_inventario.jpg) |
| Script 02 — Criação de usuários por perfil de risco | [screenshots/02_criacao_usuarios.jpg](screenshots/02_criacao_usuarios.jpg) |
| Script 03 — 2ª execução (idempotência HTTP 400) | [screenshots/06_rbac_segunda_execucao.jpg](screenshots/06_rbac_segunda_execucao.jpg) |
| Script 03 — Leitor Global atribuído no Entra ID | [screenshots/04_leitor_global.jpg](screenshots/04_leitor_global.jpg) |
| Script 03 — Helpdesk Admin atribuído no Entra ID | [screenshots/05_helpdesk_admin.jpg](screenshots/05_helpdesk_admin.jpg) |
| Script 04 — Postura Zero Trust | [screenshots/07_postura_zero_trust.jpg](screenshots/07_postura_zero_trust.jpg) |
| Script 04 — Log de auditoria | [screenshots/08_audit_log.jpg](screenshots/08_audit_log.jpg) |

---

## Aviso de Segurança

> Este laboratório foi criado para fins **educacionais e de portfólio**.
> Os usuários de teste criados devem ser removidos após o uso.
> **Nunca execute scripts de criação/modificação de usuários em tenants de produção.**

---

## Licença

MIT — veja [LICENSE](LICENSE) para detalhes.

---

*Pedro Macedo · Projeto de portfólio IAM*
