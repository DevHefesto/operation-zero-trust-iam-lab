"""
Script 03 — Atribuição de Papéis RBAC (Role-Based Access Control)
==================================================================
Conceito IAM: RBAC + Princípio do Menor Privilégio (PoLP)

No ataque Uber 2022, o contratado comprometido tinha acesso a sistemas
além do necessário para seu trabalho. A ausência de RBAC granular
permitiu que o invasor se movesse lateralmente com as credenciais obtidas.

Este script demonstra como atribuir papéis do Entra ID de forma controlada:
  - uber-admin     → Global Reader (leitura ampla, sem escrita — demonstra
                     que mesmo admins devem ter o mínimo necessário)
  - uber-contractor → Helpdesk Administrator (escopo limitado ao suporte)
  - uber-readonly   → Sem papel atribuído (acesso padrão de usuário comum)

Referência: https://learn.microsoft.com/entra/identity/role-based-access-control/

Pré-requisito: permissão RoleManagement.ReadWrite.Directory (Application).
"""

import sys
import os
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

# IDs de papéis built-in do Entra ID (estes IDs são globais — iguais em todos os tenants)
# Fonte: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
ROLES_BUILTIN = {
    "Global Reader": "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "Helpdesk Administrator": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    # Papel de usuário comum — todos os usuários têm por padrão, sem atribuição explícita
    "User (padrão)": None,
}

# Mapeamento de usuário para papel de risco
ATRIBUICOES = [
    {
        "mailNickname": "uber-admin",
        "papel": "Global Reader",
        "nivel_risco_sem_rbac": "CRÍTICO",
        "nivel_risco_com_rbac": "MÉDIO",
        "justificativa": (
            "Global Reader: leitura de todo o tenant, sem permissão de escrita. "
            "No ataque Uber, o admin tinha Full Admin — aqui modelamos o mínimo necessário."
        ),
    },
    {
        "mailNickname": "uber-contractor",
        "papel": "Helpdesk Administrator",
        "nivel_risco_sem_rbac": "ALTO",
        "nivel_risco_com_rbac": "BAIXO",
        "justificativa": (
            "Helpdesk Admin: escopo limitado a reset de senhas e suporte básico. "
            "Contratados não devem ter acesso a infraestrutura crítica."
        ),
    },
    {
        "mailNickname": "uber-readonly",
        "papel": "User (padrão)",
        "nivel_risco_sem_rbac": "BAIXO",
        "nivel_risco_com_rbac": "MÍNIMO",
        "justificativa": (
            "Nenhum papel elevado. Acesso padrão de usuário comum. "
            "Blast radius mínimo mesmo se comprometido."
        ),
    },
]


def validar_configuracao() -> None:
    """Verifica configuração de ambiente antes de qualquer chamada de rede."""
    ausentes = [k for k, v in {
        "TENANT_ID": TENANT_ID,
        "CLIENT_ID": CLIENT_ID,
        "CLIENT_SECRET": CLIENT_SECRET,
        "TENANT_DOMAIN": TENANT_DOMAIN,
    }.items() if not v]
    if ausentes:
        print(f"[ERRO] Variáveis ausentes: {', '.join(ausentes)}")
        sys.exit(1)


def obter_token_acesso() -> str:
    """Autentica via Client Credentials e retorna Bearer token."""
    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    )
    resultado = app.acquire_token_for_client(scopes=SCOPES)
    if "access_token" not in resultado:
        print(f"[ERRO] {resultado.get('error_description', 'Autenticação falhou')}")
        sys.exit(1)
    return resultado["access_token"]


def buscar_usuario_id(token: str, upn: str) -> str | None:
    """
    Conceito IAM: Resolução de identidade por UPN.

    O Graph API usa IDs internos (GUID) para todas as operações de atribuição.
    O UPN (user@dominio.com) é o identificador humano — precisamos converter.
    """
    cabecalhos = {"Authorization": f"Bearer {token}"}
    resposta = requests.get(
        f"{GRAPH_BASE_URL}/users/{upn}",
        headers=cabecalhos,
        params={"$select": "id,displayName,userPrincipalName"},
        timeout=30,
    )
    if resposta.status_code == 200:
        return resposta.json().get("id")
    if resposta.status_code == 404:
        print(f"  [!] Usuário {upn} não encontrado — execute o script 02 primeiro.")
        return None
    print(f"  [ERRO] Falha ao buscar {upn}: HTTP {resposta.status_code}")
    return None


def listar_atribuicoes_atuais(token: str, user_id: str) -> list[str]:
    """
    Conceito IAM: Revisão de Acessos (Access Review).

    Antes de atribuir um papel, auditamos o que o usuário já possui.
    Isso evita duplicações e permite detectar papéis excessivos pré-existentes.
    """
    cabecalhos = {"Authorization": f"Bearer {token}"}
    resposta = requests.get(
        f"{GRAPH_BASE_URL}/users/{user_id}/memberOf/microsoft.graph.directoryRole",
        headers=cabecalhos,
        timeout=30,
    )
    if resposta.status_code == 200:
        return [r.get("displayName", "") for r in resposta.json().get("value", [])]
    return []


def atribuir_papel_diretorio(token: str, user_id: str, role_id: str, nome_papel: str) -> bool:
    """
    Conceito IAM: Role Assignment via Graph API.

    Atribui um papel de diretório (Directory Role) ao usuário.
    Em produção, use Privileged Identity Management (PIM) para atribuições
    just-in-time com aprovação e duração limitada — nunca permanentes.

    POST /v1.0/directoryRoles/{roleId}/members/$ref
    """
    cabecalhos = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Primeiro: ativa o papel no tenant (papéis built-in precisam ser ativados)
    ativar_url = f"{GRAPH_BASE_URL}/directoryRoles/roleTemplateId={role_id}"
    r_ativar = requests.post(
        ativar_url,
        headers=cabecalhos,
        json={"roleTemplateId": role_id},
        timeout=30,
    )
    # 201 = criado, 409 = já existe (ambos são OK)
    if r_ativar.status_code not in (201, 409):
        # Tenta buscar pelo template ID diretamente
        pass

    # Busca o objectId do papel ativado
    r_papel = requests.get(
        f"{GRAPH_BASE_URL}/directoryRoles",
        headers=cabecalhos,
        params={"$filter": f"roleTemplateId eq '{role_id}'"},
        timeout=30,
    )
    if r_papel.status_code != 200 or not r_papel.json().get("value"):
        print(f"  [ERRO] Não foi possível localizar o papel '{nome_papel}' no tenant.")
        return False

    papel_object_id = r_papel.json()["value"][0]["id"]

    # Atribui o usuário ao papel
    payload = {"@odata.id": f"{GRAPH_BASE_URL}/directoryObjects/{user_id}"}
    r_assign = requests.post(
        f"{GRAPH_BASE_URL}/directoryRoles/{papel_object_id}/members/$ref",
        headers=cabecalhos,
        json=payload,
        timeout=30,
    )

    if r_assign.status_code == 204:
        return True
    if r_assign.status_code == 400 and "already exists" in r_assign.text.lower():
        print(f"  [!] Usuário já possui o papel '{nome_papel}'.")
        return True
    if r_assign.status_code == 403:
        print(f"  [ERRO] Sem permissão para atribuir papéis.")
        print("         Adicione RoleManagement.ReadWrite.Directory no portal Azure.")
        return False

    print(f"  [ERRO] HTTP {r_assign.status_code}: {r_assign.text[:200]}")
    return False


def main() -> None:
    """
    Atribui papéis RBAC aos 3 usuários de simulação e exibe relatório de risco.
    """
    print("=" * 70)
    print("  OPERATION ZERO TRUST — Script 03: Atribuição de Papéis RBAC")
    print("=" * 70)

    validar_configuracao()
    token = obter_token_acesso()

    relatorio = []

    for atribuicao in ATRIBUICOES:
        upn = f"{atribuicao['mailNickname']}@{TENANT_DOMAIN}"
        papel = atribuicao["papel"]
        role_id = ROLES_BUILTIN.get(papel)

        print(f"\n[*] Processando: {upn}")
        print(f"    Papel alvo: {papel}")

        user_id = buscar_usuario_id(token, upn)
        if not user_id:
            relatorio.append({
                "UPN": upn, "Papel": papel,
                "Status": "USUÁRIO NÃO ENCONTRADO",
                "Risco Antes": atribuicao["nivel_risco_sem_rbac"],
                "Risco Depois": "N/A",
            })
            continue

        papeis_atuais = listar_atribuicoes_atuais(token, user_id)
        if papeis_atuais:
            print(f"    Papéis atuais: {', '.join(papeis_atuais)}")

        if role_id is None:
            # Usuário de menor privilégio — não atribuímos nada
            print(f"    [OK] Nenhum papel elevado atribuído (acesso padrão).")
            status = "SEM PAPEL ELEVADO (correto)"
        else:
            sucesso = atribuir_papel_diretorio(token, user_id, role_id, papel)
            status = "ATRIBUÍDO" if sucesso else "FALHOU"
            if sucesso:
                print(f"    [OK] Papel '{papel}' atribuído com sucesso.")

        relatorio.append({
            "UPN": upn,
            "Papel Atribuído": papel,
            "Status": status,
            "Risco Sem RBAC": atribuicao["nivel_risco_sem_rbac"],
            "Risco Com RBAC": atribuicao["nivel_risco_com_rbac"],
        })

    print(f"\n{'='*70}")
    print("  RELATÓRIO RBAC — Redução de Superfície de Ataque")
    print(f"{'='*70}")
    print(tabulate(relatorio, headers="keys", tablefmt="rounded_outline"))

    print()
    print("LIÇÃO DO UBER 2022:")
    print("  O invasor escalou privilégios porque identidades tinham MAIS acesso")
    print("  do que precisavam. RBAC granular limita o blast radius de qualquer")
    print("  comprometimento de credencial.")
    print()
    print("PRÓXIMO PASSO: Execute o script 04_audit_log_report.py para gerar")
    print("               o relatório de auditoria das ações realizadas.")
    print()
    print("[FIM] Script 03 executado com sucesso.")


if __name__ == "__main__":
    main()
