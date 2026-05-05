"""
Script 02 — Criação de Usuários de Teste (Simulação Uber 2022)
==============================================================
Conceito IAM: Perfis de Risco e Princípio do Menor Privilégio (PoLP)

No ataque Uber 2022, o invasor comprometeu a conta de um contratado
(contractor) que tinha acesso excessivo ao Thycotic (cofre de senhas).
A partir daí, escalou privilégios lateralmente até obter acesso a
praticamente todos os sistemas.

Este script cria 3 usuários que simulam os 3 perfis de risco do incidente:

  1. uber-admin   → Conta com privilégios elevados (comprometida no ataque real)
  2. uber-contractor → Contratado com acesso mais amplo do que o necessário
  3. uber-readonly   → Usuário modelado com Least Privilege (o que deveria existir)

Pré-requisito: a permissão User.ReadWrite.All (Application) deve estar
concedida no portal Azure pelo administrador do tenant.
"""

import sys
import os
import secrets
import string
from dotenv import load_dotenv
import msal
import requests
from tabulate import tabulate

load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
TENANT_DOMAIN = os.getenv("TENANT_DOMAIN")

SCOPES = ["https://graph.microsoft.com/.default"]
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


def validar_configuracao() -> None:
    """Verifica se todas as variáveis de ambiente necessárias estão definidas."""
    variaveis = {
        "TENANT_ID": TENANT_ID,
        "CLIENT_ID": CLIENT_ID,
        "CLIENT_SECRET": CLIENT_SECRET,
        "TENANT_DOMAIN": TENANT_DOMAIN,
    }
    ausentes = [k for k, v in variaveis.items() if not v]
    if ausentes:
        print(f"[ERRO] Variáveis ausentes no .env: {', '.join(ausentes)}")
        sys.exit(1)


def obter_token_acesso() -> str:
    """
    Conceito IAM: Reutilização segura de tokens via MSAL cache.

    O MSAL armazena tokens em memória durante a execução. Se o token ainda
    for válido (< 1h), ele é reutilizado — evitando round-trips desnecessários
    ao Entra ID e reduzindo a superfície de exposição de credenciais.
    """
    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    )
    resultado = app.acquire_token_for_client(scopes=SCOPES)
    if "access_token" not in resultado:
        erro = resultado.get("error_description", "desconhecido")
        print(f"[ERRO] Autenticação falhou: {erro}")
        sys.exit(1)
    return resultado["access_token"]


def gerar_senha_forte(tamanho: int = 20) -> str:
    """
    Conceito IAM: Geração de senhas temporárias seguras.

    Usa o módulo `secrets` (CSPRNG — Cryptographically Secure Pseudo-Random
    Number Generator) em vez de `random`. O Python `random` é previsível e
    não deve ser usado para fins de segurança.

    Requisitos de complexidade do Entra ID:
    - Mínimo 8 caracteres
    - Letras maiúsculas, minúsculas, números e símbolos
    """
    alfabeto = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        senha = "".join(secrets.choice(alfabeto) for _ in range(tamanho))
        # Verifica que a senha atende os requisitos de complexidade
        tem_maiuscula = any(c.isupper() for c in senha)
        tem_minuscula = any(c.islower() for c in senha)
        tem_numero = any(c.isdigit() for c in senha)
        tem_simbolo = any(c in "!@#$%^&*" for c in senha)
        if tem_maiuscula and tem_minuscula and tem_numero and tem_simbolo:
            return senha


# Definição dos perfis de usuário de teste
# Cada perfil representa um nível de exposição diferente ao risco IAM
USUARIOS_DE_TESTE = [
    {
        "displayName": "Uber Admin (Simulação)",
        "mailNickname": "uber-admin",
        # Perfil de risco: CRÍTICO
        # No Uber 2022, o invasor obteve acesso a uma conta com privilégios
        # administrativos, o que lhe permitiu acessar o Thycotic (cofre de senhas)
        # e de lá extrair credenciais de dezenas de sistemas.
        # Contas admin devem ter: MFA obrigatório, PAM (Privileged Access Management),
        # acesso just-in-time (JIT) e sessões gravadas.
        "perfil_risco": "CRÍTICO",
        "justificativa": (
            "Simula o admin comprometido no Uber 2022. "
            "Deveria ter acesso JIT + MFA + PAM obrigatório."
        ),
        "jobTitle": "System Administrator",
    },
    {
        "displayName": "Uber Contractor (Simulação)",
        "mailNickname": "uber-contractor",
        # Perfil de risco: ALTO
        # O vetor inicial do ataque Uber 2022 foi a conta de um contratado
        # (terceiro) que tinha acesso a sistemas internos sem MFA adequado.
        # O invasor usou MFA Fatigue Attack: bombardeou o contratado com
        # notificações push do Duo até que ele acidentalmente aprovasse.
        # Contratados devem ter: escopo de acesso limitado ao projeto,
        # duração temporária de conta, revisões de acesso periódicas.
        "perfil_risco": "ALTO",
        "justificativa": (
            "Simula o contratado vazado (vetor inicial do ataque). "
            "Acesso excessivo + ausência de MFA resistente a phishing."
        ),
        "jobTitle": "External Contractor",
    },
    {
        "displayName": "Uber ReadOnly (Simulação)",
        "mailNickname": "uber-readonly",
        # Perfil de risco: BAIXO (modelo correto)
        # Este usuário representa como os contratados DEVERIAM ser configurados:
        # acesso somente-leitura, escopo mínimo, sem acesso a sistemas críticos.
        # Mesmo que comprometido, o raio de impacto (blast radius) é mínimo.
        # Conceito: Least Privilege + Need-to-Know + Blast Radius Minimization.
        "perfil_risco": "BAIXO",
        "justificativa": (
            "Modelo de Least Privilege. Mesmo comprometido, o blast radius é mínimo."
        ),
        "jobTitle": "Read-Only Analyst",
    },
]


def criar_usuario(token: str, usuario: dict, dominio: str) -> dict:
    """
    Conceito IAM: Provisionamento controlado de identidades (IGA — Identity Governance).

    Cria um usuário via POST /v1.0/users. Em produção, o provisionamento deve
    ser feito via fluxo de aprovação (workflow) com rastreabilidade completa —
    nunca manualmente ou por script ad-hoc sem auditoria.

    Retorna o objeto do usuário criado ou raise em caso de erro.
    """
    cabecalhos = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    senha_temp = gerar_senha_forte()
    upn = f"{usuario['mailNickname']}@{dominio}"

    payload = {
        "accountEnabled": True,
        "displayName": usuario["displayName"],
        "mailNickname": usuario["mailNickname"],
        "userPrincipalName": upn,
        "jobTitle": usuario.get("jobTitle", ""),
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,  # boas práticas: força troca no primeiro login
            "password": senha_temp,
        },
    }

    resposta = requests.post(
        f"{GRAPH_BASE_URL}/users",
        headers=cabecalhos,
        json=payload,
        timeout=30,
    )

    if resposta.status_code == 201:
        dados = resposta.json()
        dados["_senha_temporaria"] = senha_temp  # guardamos para exibir ao operador
        return dados

    if resposta.status_code == 409:
        print(f"  [!] Usuário {upn} já existe — pulando criação.")
        return {"userPrincipalName": upn, "id": "JÁ EXISTE", "_senha_temporaria": "N/A"}

    if resposta.status_code == 403:
        print(f"[ERRO] Sem permissão para criar usuários.")
        print("       Adicione a permissão User.ReadWrite.All (Application) no portal Azure.")
        sys.exit(1)

    print(f"[ERRO] Falha ao criar {upn}: HTTP {resposta.status_code}")
    print(f"       {resposta.text}")
    sys.exit(1)


def main() -> None:
    """
    Cria os 3 usuários de simulação e exibe um relatório com perfis de risco.

    ATENÇÃO: Os usuários criados são para fins de laboratório.
    Remova-os após os testes para não aumentar a superfície de ataque do tenant.
    """
    print("=" * 70)
    print("  OPERATION ZERO TRUST — Script 02: Criação de Usuários de Teste")
    print("=" * 70)
    print()
    print("[AVISO] Este script criará usuários reais no seu tenant Azure.")
    print("        Use apenas em ambientes de laboratório/desenvolvimento.")
    print()

    validar_configuracao()
    token = obter_token_acesso()

    resultados = []
    for usuario in USUARIOS_DE_TESTE:
        upn = f"{usuario['mailNickname']}@{TENANT_DOMAIN}"
        print(f"[*] Criando usuário: {upn}")
        dados_criados = criar_usuario(token, usuario, TENANT_DOMAIN)
        resultados.append({
            "UPN": dados_criados.get("userPrincipalName", upn),
            "ID": dados_criados.get("id", "N/A")[:8] + "...",
            "Perfil de Risco": usuario["perfil_risco"],
            "Senha Temporária": dados_criados.get("_senha_temporaria", "N/A"),
        })
        print(f"  [OK] {dados_criados.get('userPrincipalName')} criado.")

    print(f"\n{'='*70}")
    print("  RELATÓRIO DE CRIAÇÃO — Perfis de Risco IAM")
    print(f"{'='*70}")
    print(tabulate(resultados, headers="keys", tablefmt="rounded_outline"))

    print()
    print("[IMPORTANTE] Guarde as senhas temporárias acima com segurança.")
    print("             Os usuários serão obrigados a trocar no primeiro login.")
    print()
    print("PRÓXIMO PASSO: Execute o script 03_assign_rbac_roles.py para")
    print("               atribuir papéis diferentes a cada perfil.")
    print()
    print("[FIM] Script 02 executado com sucesso.")


if __name__ == "__main__":
    main()
