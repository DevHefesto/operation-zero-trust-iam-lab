# Análise Técnica: Ataque Uber 2022

> **Referências normativas:** NIST CSF v1.1 · ISO/IEC 27001:2022 · MITRE ATT&CK for Enterprise

---

## 1. O Que Aconteceu — Linha do Tempo

### Contexto

Em setembro de 2022, um agente de ameaça identificado como "teapotuberhacker"
comprometeu completamente a infraestrutura interna da Uber. O invasor, com
aproximadamente 18 anos à época, obteve acesso a sistemas críticos incluindo
AWS, Google Cloud, GitHub, Slack, HackerOne e o painel de administração do
Thycotic (cofre de senhas corporativo).

### Linha do Tempo do Ataque

| Fase | MITRE ATT&CK | O que aconteceu |
|------|-------------|-----------------|
| **T+0: Obtenção de credenciais** | T1078 (Valid Accounts) | O invasor comprou (ou obteve via phishing) as credenciais VPN de um contratado (contractor) em um marketplace na dark web. |
| **T+1: MFA Fatigue Attack** | T1621 (Multi-Factor Authentication Request Generation) | Enviou dezenas de notificações push MFA para o telefone do contratado durante ~1 hora. O contratado, cansado, aprovou uma delas. |
| **T+2: Acesso à VPN** | T1133 (External Remote Services) | Com credencial + aprovação MFA, o invasor entrou na rede interna da Uber sem obstáculos adicionais. |
| **T+3: Escalada de Privilégios** | T1078.004 (Cloud Accounts) | Encontrou um script PowerShell em share de rede interno contendo **credenciais hardcoded** do Thycotic (PAM). |
| **T+4: Comprometimento Total** | T1555 (Credentials from Password Stores) | Com acesso ao Thycotic, extraiu senhas de dezenas de sistemas: AWS, GCP, GitHub, Google Workspace, Slack. |
| **T+5: Exfiltração e Exposição** | T1537 (Transfer Data to Cloud Account) | Acessou dados sensíveis, relatórios HackerOne (vulnerabilidades não corrigidas) e tirou screenshots de painéis internos. |
| **T+6: Detecção** | — | Um engenheiro percebeu mensagens no Slack enviadas pelo invasor ("I announce I am a hacker and Uber has suffered a data breach"). |

**Duração total antes da detecção: aproximadamente 8 horas.**

---

## 2. Controles de IAM Ausentes

### 2.1 MFA Resistente a Phishing (ausente)

**Problema:** O sistema MFA usado (Duo com aprovação por push) é vulnerável
a MFA Fatigue — o usuário pode aprovar acidentalmente após múltiplas tentativas.

**Controle correto:**
- FIDO2 / Passkeys (hardware keys como YubiKey) — resistentes a phishing por design
- Number Matching no Microsoft Authenticator — o usuário confirma um número exibido
  na tela de login, tornando aprovações acidentais impossíveis

**Referência normativa:**
- ISO 27001:2022 — A.8.5 (Autenticação Segura)
- NIST CSF — PR.AC-7 (Autenticação baseada em risco)

---

### 2.2 Princípio do Menor Privilégio — PoLP (ausente)

**Problema:** O contratado comprometido tinha acesso a sistemas muito além
do necessário para sua função. Um contratado de suporte não deveria ter acesso
à infraestrutura de nuvem crítica.

**Controle correto:**
- Contas de contratados com escopos explicitamente limitados ao projeto
- Revisões de acesso trimestrais (Access Reviews)
- Expiração automática de acessos temporários

**Referência normativa:**
- ISO 27001:2022 — A.8.2 (Direitos de Acesso Privilegiado)
- NIST CSF — PR.AC-4 (Permissões gerenciadas com PoLP)

---

### 2.3 Credenciais Hardcoded (ausente / vulnerabilidade crítica)

**Problema:** Um script PowerShell em share de rede interno continha
as credenciais do Thycotic em texto plano. Isso transformou uma credencial
de contratado em acesso total ao cofre de senhas corporativo.

**Controle correto:**
- Proibição de credenciais hardcoded — verificada via SAST e pre-commit hooks
- Gerenciamento de segredos via Azure Key Vault, HashiCorp Vault ou AWS Secrets Manager
- Rotação automática de credenciais

**Referência normativa:**
- ISO 27001:2022 — A.8.24 (Uso de Criptografia)
- OWASP — A02:2021 Cryptographic Failures

---

### 2.4 Monitoramento e Detecção de Anomalias (ausente)

**Problema:** O invasor permaneceu no ambiente por ~8 horas sem ser detectado
automaticamente. A detecção foi acidental — via mensagem no Slack do próprio invasor.

**Controles corretos:**
- SIEM (ex: Microsoft Sentinel) com regras para:
  - Múltiplas aprovações MFA em sequência (MFA Fatigue indicator)
  - Login de IP anômalo combinado com acesso a sistemas críticos
  - Acesso a cofre de senhas fora do horário comercial
- Microsoft Entra ID Protection para detecção de identidades em risco

**Referência normativa:**
- ISO 27001:2022 — A.8.16 (Monitoramento de Atividades)
- NIST CSF — DE.AE (Anomalies and Events)

---

### 2.5 Privileged Access Management — PAM (ausente ou mal configurado)

**Problema:** O Thycotic estava em uso, mas suas credenciais estavam expostas
em script de texto plano — indicando que o próprio PAM não estava adequadamente
protegido ou auditado.

**Controle correto:**
- Microsoft Entra Privileged Identity Management (PIM): acesso JIT com aprovação
- Sessões privilegiadas gravadas (Privileged Access Workstations — PAW)
- Auditoria de cada acesso ao cofre de senhas

**Referência normativa:**
- ISO 27001:2022 — A.8.2 (Privileged Access Rights)
- NIST SP 800-53 — AC-6 (Least Privilege)

---

## 3. Como Este Laboratório Teria Impedido o Ataque

### Fase 1: Obtenção de credenciais → **Mitigação Parcial**

Mesmo com credenciais obtidas externamente, o **Conditional Access** configurado
bloquearia o login de IPs desconhecidos ou países não autorizados.

*Script relacionado:* `03_assign_rbac_roles.py` demonstra como limitar o escopo
de cada identidade para reduzir o valor das credenciais comprometidas.

---

### Fase 2: MFA Fatigue → **Bloqueio Total**

Com FIDO2/Passkeys (configurável no Entra ID), o MFA Fatigue é impossível —
não há aprovação por push; exige presença física da chave de hardware.

*Próximo passo sugerido:* Configurar Authentication Strength no Entra ID para
exigir Passkeys para contas privilegiadas.

---

### Fase 3: Acesso à rede interna → **Detecção e Bloqueio**

O **Entra ID Sign-in Log** (`04_audit_log_report.py`) capturaria o login de
IP anômalo. Integrado ao Sentinel, geraria alerta automático e bloqueio
via Conditional Access.

---

### Fase 4: Escalada pelo Thycotic → **Bloqueio Total**

- Credenciais hardcoded seriam detectadas por pre-commit hooks (git-secrets / trufflehog)
- PIM exigiria aprovação explícita para acessar o PAM
- Auditoria de acessos ao cofre de senhas geraria alerta para acesso fora do horário

*Script relacionado:* `04_audit_log_report.py` demonstra como auditar ações
administrativas em tempo real.

---

### Fase 5: Comprometimento Total → **Impossibilitado**

Com RBAC granular (`03_assign_rbac_roles.py`), cada conta teria acesso somente
aos sistemas necessários para sua função — o contratado comprometido não teria
acesso a AWS, GCP ou GitHub mesmo com a credencial obtida.

---

## 4. Mapeamento NIST CSF vs. Controles Implementados

| Função NIST CSF | Subcategoria | Controle Implementado | Script |
|-----------------|-------------|----------------------|--------|
| **Identify** | PR.AC-1 (Identidades gerenciadas) | Inventário completo via Graph API | Script 01 |
| **Protect** | PR.AC-4 (Menor Privilégio) | RBAC granular por função | Script 03 |
| **Protect** | PR.AC-7 (Autenticação forte) | Client Credentials + MSAL | Script 01 |
| **Detect** | DE.AE-1 (Baseline de atividade) | Auditoria de sign-ins e ações | Script 04 |
| **Detect** | DE.CM-3 (Monitoramento de pessoal) | Directory Audit Log | Script 04 |
| **Respond** | RS.RP-1 (Plano de resposta) | Relatório de postura Zero Trust | Script 04 |

---

## 5. Mapeamento ISO/IEC 27001:2022

| Controle ISO | Descrição | Implementado neste Lab |
|-------------|-----------|----------------------|
| A.5.15 | Controle de Acesso | RBAC via Entra ID (Script 03) |
| A.5.16 | Gerenciamento de Identidade | Provisionamento controlado (Script 02) |
| A.5.18 | Direitos de Acesso | Menor Privilégio por perfil (Script 03) |
| A.8.2 | Acesso Privilegiado | Simulação de papéis elevados (Scripts 02-03) |
| A.8.5 | Autenticação Segura | OAuth 2.0 + MSAL (Script 01) |
| A.8.16 | Monitoramento | Audit Log + Sign-in Report (Script 04) |

---

## 6. Referências

- [Uber Cybersecurity Incident 2022 — Official Statement](https://www.uber.com/newsroom/security-update/)
- [NIST Cybersecurity Framework v1.1](https://www.nist.gov/cyberframework)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [MITRE ATT&CK — MFA Fatigue (T1621)](https://attack.mitre.org/techniques/T1621/)
- [Microsoft Entra ID — Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/)
- [Microsoft Graph API — Audit Logs](https://learn.microsoft.com/graph/api/resources/directoryaudit)
- [OWASP Top 10 — A07:2021 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

*Documento criado para o projeto Operation Zero Trust — laboratório didático de IAM.*
*Uso exclusivo para fins educacionais e de portfólio profissional.*
