"""
Script 01 — Autenticação OAuth 2.0 e Listagem de Usuários
==========================================================
Conceito IAM: Client Credentials Flow (OAuth 2.0)

No ataque Uber 2022, o invasor usou credenciais de um contratado para
autenticar-se nos sistemas internos sem qualquer desafio adicional.
Este script demonstra como a autenticação via Client Credentials funciona
e como auditar quem existe no tenant — primeiro passo de qualquer revisão
de postura Zero Trust.

Fluxo OAuth 2.0 — Client Credentials:
  1. Aplicação envia client_id + client_secret para o token endpoint
  2. Entra ID valida as credenciais do app (não do usuário)
  3. Entra ID devolve um Bearer token com validade de ~1h
  4. Aplicação usa o token para chamar a Graph API
"""

import sys
import os
from dotenv import load_dotenv
import msal
import requests
from tabulate import tabulate

# Carrega variáveis do .env sem expor credenciais no código-fonte
load_dotenv()

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# Escopo exigido pelo Client Credentials Flow — sempre o padrão .default
SCOPES = ["https://graph.microsoft.com/.default"]

# Endpoint base da Microsoft Graph API v1.0
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


def validar_configuracao() -> None:
    """
    Conceito IAM: Fail Fast na configuração de credenciais.

    Garante que nenhuma credencial esteja ausente antes de qualquer chamada
    de rede. Em produção, use Azure Key Vault em vez de variáveis de ambiente.
    """
    variaveis_ausentes = [
        nome
        for nome, valor in [
            ("TENANT_ID", TENANT_ID),
            ("CLIENT_ID", CLIENT_ID),
            ("CLIENT_SECRET", CLIENT_SECRET),
        ]
        if not valor
    ]
    if variaveis_ausentes:
        print(f"[ERRO] Variáveis de ambiente não configuradas: {', '.join(variaveis_ausentes)}")
        print("       Copie .env.example para .env e preencha os valores.")
        sys.exit(1)


def obter_token_acesso() -> str:
    """
    Conceito IAM: Client Credentials Flow (RFC 6749, Section 4.4).

    Autentica a aplicação (não o usuário) usando client_id + client_secret.
    Retorna um Bearer token JWT para uso nas chamadas à Graph API.

    Por que Client Credentials e não Authorization Code?
    → Em scripts de backend e automações não há usuário presente para
      consentir interativamente. O app age por conta própria com permissões
      de aplicação (Application permissions), não delegadas.
    """
    # MSAL cria um app confidencial — tem segredo, ao contrário de apps públicas
    app = msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
    )

    print("[*] Solicitando token de acesso ao Microsoft Entra ID...")
    resultado = app.acquire_token_for_client(scopes=SCOPES)

    # O token pode estar no cache MSAL (evita requisições desnecessárias)
    if "access_token" not in resultado:
        erro = resultado.get("error_description", resultado.get("error", "desconhecido"))
        print(f"[ERRO] Falha na autenticação: {erro}")
        print()
        print("Causas comuns:")
        print("  → CLIENT_SECRET expirado (verifique no portal Azure)")
        print("  → Permissões insuficientes (User.Read.All não concedida como Application)")
        print("  → TENANT_ID incorreto")
        sys.exit(1)

    print("[OK] Token obtido com sucesso.")
    print(f"     Tipo: {resultado.get('token_type')}")
    print(f"     Expira em: {resultado.get('expires_in')} segundos (~{resultado.get('expires_in', 0) // 60} minutos)")
    return resultado["access_token"]


def listar_usuarios(token: str) -> list[dict]:
    """
    Conceito IAM: Princípio da Visibilidade (NIST CSF — Identify).

    Consulta GET /v1.0/users para obter todos os usuários do tenant.
    Em Zero Trust, ter visibilidade completa dos identities é o passo zero:
    não é possível proteger o que não se conhece.

    A paginação via @odata.nextLink é tratada aqui para tenants grandes.
    """
    cabecalhos = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Seleciona apenas os campos necessários — princípio do menor privilégio
    # para dados também: não busque o que não vai usar.
    params = {
        "$select": "displayName,userPrincipalName,accountEnabled,createdDateTime,jobTitle",
        "$top": 100,  # máximo por página suportado pelo Graph API
        "$orderby": "displayName",
    }

    usuarios: list[dict] = []
    url = f"{GRAPH_BASE_URL}/users"

    print("\n[*] Consultando usuários via Graph API...")

    # Loop de paginação — o Graph API retorna no máximo 100 usuários por vez
    while url:
        resposta = requests.get(url, headers=cabecalhos, params=params, timeout=30)

        if resposta.status_code == 403:
            print("[ERRO] Acesso negado (HTTP 403).")
            print("       A permissão User.Read.All (Application) precisa ser concedida")
            print("       por um admin no portal Azure.")
            sys.exit(1)

        if resposta.status_code != 200:
            print(f"[ERRO] Resposta inesperada: HTTP {resposta.status_code}")
            print(f"       Detalhe: {resposta.text}")
            sys.exit(1)

        dados = resposta.json()
        usuarios.extend(dados.get("value", []))

        # @odata.nextLink existe quando há mais páginas
        url = dados.get("@odata.nextLink")
        # Limpa params para não duplicar na URL de nextLink
        params = {}

    return usuarios


def exibir_usuarios(usuarios: list[dict]) -> None:
    """
    Conceito IAM: Inventário de Identidades.

    Formata e exibe os usuários de forma legível. Em um contexto real de IAM,
    este relatório seria o ponto de partida para uma revisão de acessos (Access Review).
    """
    if not usuarios:
        print("[AVISO] Nenhum usuário encontrado no tenant.")
        return

    linhas = []
    for u in usuarios:
        status = "ATIVO" if u.get("accountEnabled") else "DESABILITADO"
        criado = (u.get("createdDateTime") or "")[:10]  # apenas AAAA-MM-DD
        linhas.append([
            u.get("displayName", "N/A"),
            u.get("userPrincipalName", "N/A"),
            u.get("jobTitle") or "—",
            status,
            criado,
        ])

    cabecalhos_tabela = ["Nome", "UPN (Login)", "Cargo", "Status", "Criado em"]
    print(f"\n{'='*70}")
    print(f"  INVENTÁRIO DE IDENTIDADES — {len(usuarios)} usuário(s) encontrado(s)")
    print(f"{'='*70}")
    print(tabulate(linhas, headers=cabecalhos_tabela, tablefmt="rounded_outline"))

    # Alerta de usuários desabilitados — identidades zumbis são risco de segurança
    desabilitados = [u for u in usuarios if not u.get("accountEnabled")]
    if desabilitados:
        print(f"\n[!] ALERTA: {len(desabilitados)} conta(s) desabilitada(s) encontrada(s).")
        print("    Contas desabilitadas mas não removidas são um risco IAM — revisar.")


def main() -> None:
    """
    Ponto de entrada do script 01.

    Demonstra o fluxo completo:
      1. Validação da configuração local
      2. Autenticação via Client Credentials (OAuth 2.0)
      3. Consulta de usuários via Graph API
      4. Exibição formatada do inventário de identidades
    """
    print("=" * 70)
    print("  OPERATION ZERO TRUST — Script 01: Auth + Inventário de Identidades")
    print("=" * 70)

    validar_configuracao()
    token = obter_token_acesso()
    usuarios = listar_usuarios(token)
    exibir_usuarios(usuarios)

    print(f"\n[FIM] Script executado com sucesso.")


if __name__ == "__main__":
    main()
