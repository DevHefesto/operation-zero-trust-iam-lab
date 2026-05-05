"""
Script 04 — Relatório de Auditoria (Audit Log + Sign-in Report)
===============================================================
Conceito IAM: Monitoramento Contínuo e Detecção de Anomalias (NIST CSF — Detect)

No ataque Uber 2022, os invasores permaneceram no ambiente por horas
sem serem detectados. A ausência de monitoramento ativo e alertas em
tempo real foi um dos fatores críticos que permitiu a extensão do dano.

Este script consulta dois endpoints do Graph API:
  1. /auditLogs/directoryAudits → ações administrativas (criação de usuários,
     atribuição de papéis, mudanças de configuração)
  2. /auditLogs/signIns → histórico de autenticações (sucessos e falhas)

O objetivo é demonstrar como gerar evidências auditáveis das ações
realizadas nos scripts anteriores — base para compliance e forense.

Pré-requisito: permissão AuditLog.Read.All (Application) no portal Azure.
"""

import sys
import os
from datetime import datetime, timezone, timedelta
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

# Janela de auditoria: eventos das últimas N horas
JANELA_HORAS = 24


def validar_configuracao() -> None:
    """Verifica configuração de ambiente."""
    ausentes = [k for k, v in {
        "TENANT_ID": TENANT_ID, "CLIENT_ID": CLIENT_ID,
        "CLIENT_SECRET": CLIENT_SECRET, "TENANT_DOMAIN": TENANT_DOMAIN,
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


def formatar_data_iso(dt_str: str) -> str:
    """Converte timestamp ISO 8601 para formato legível em PT-BR."""
    if not dt_str:
        return "N/A"
    try:
        # Remove o 'Z' e parseia como UTC
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return dt_str[:19].replace("T", " ")


def buscar_audit_logs_diretorio(token: str, horas: int = 24) -> list[dict]:
    """
    Conceito IAM: Trilha de Auditoria (Audit Trail).

    Consulta o log de auditoria de diretório — registra TODAS as mudanças
    administrativas: criação/deleção de usuários, atribuição de papéis,
    mudanças em aplicações, etc.

    Por que isso importa no contexto Uber 2022?
    → Os invasores criaram contas, adicionaram MFA e alteraram configurações.
      Com auditoria ativa, essas ações seriam visíveis em tempo real para
      um SIEM (ex: Microsoft Sentinel).

    Filtra por: últimas N horas, ordenado do mais recente.
    """
    cabecalhos = {"Authorization": f"Bearer {token}"}

    # Calcula o início da janela de tempo em formato ISO 8601
    inicio = datetime.now(timezone.utc) - timedelta(hours=horas)
    inicio_iso = inicio.strftime("%Y-%m-%dT%H:%M:%SZ")

    params = {
        "$filter": f"activityDateTime ge {inicio_iso}",
        "$orderby": "activityDateTime desc",
        "$top": 50,
        "$select": "activityDateTime,activityDisplayName,category,initiatedBy,targetResources,result",
    }

    resposta = requests.get(
        f"{GRAPH_BASE_URL}/auditLogs/directoryAudits",
        headers=cabecalhos,
        params=params,
        timeout=30,
    )

    if resposta.status_code == 403:
        print("[AVISO] Sem permissão para AuditLog.Read.All — logs de diretório indisponíveis.")
        print("        Adicione a permissão no portal Azure para ativar esta funcionalidade.")
        return []

    if resposta.status_code != 200:
        print(f"[AVISO] Audit log de diretório indisponível: HTTP {resposta.status_code}")
        return []

    return resposta.json().get("value", [])


def buscar_sign_in_logs(token: str, horas: int = 24) -> list[dict]:
    """
    Conceito IAM: Monitoramento de Autenticações (Sign-in Risk).

    Consulta o histórico de sign-ins. Autenticações falhadas em sequência,
    logins de IPs anômalos ou fora do horário comercial são indicadores
    de comprometimento de credencial.

    No Uber 2022, o MFA Fatigue passou despercebido porque não havia
    alerta configurado para múltiplas aprovações MFA em sequência.
    """
    cabecalhos = {"Authorization": f"Bearer {token}"}

    inicio = datetime.now(timezone.utc) - timedelta(hours=horas)
    inicio_iso = inicio.strftime("%Y-%m-%dT%H:%M:%SZ")

    params = {
        "$filter": f"createdDateTime ge {inicio_iso}",
        "$orderby": "createdDateTime desc",
        "$top": 50,
        "$select": (
            "createdDateTime,userPrincipalName,appDisplayName,"
            "ipAddress,status,conditionalAccessStatus,riskLevelAggregated"
        ),
    }

    resposta = requests.get(
        f"{GRAPH_BASE_URL}/auditLogs/signIns",
        headers=cabecalhos,
        params=params,
        timeout=30,
    )

    if resposta.status_code == 403:
        print("[AVISO] Sem permissão para AuditLog.Read.All — sign-in logs indisponíveis.")
        return []

    if resposta.status_code != 200:
        print(f"[AVISO] Sign-in log indisponível: HTTP {resposta.status_code}")
        return []

    return resposta.json().get("value", [])


def exibir_audit_logs(logs: list[dict]) -> None:
    """Formata e exibe os logs de auditoria de diretório."""
    if not logs:
        print("  Nenhum evento de auditoria encontrado na janela de tempo.")
        return

    linhas = []
    for log in logs:
        # Extrai o iniciador da ação (quem fez)
        iniciador = log.get("initiatedBy", {})
        if "user" in iniciador and iniciador["user"]:
            quem = iniciador["user"].get("userPrincipalName") or iniciador["user"].get("displayName", "N/A")
        elif "app" in iniciador and iniciador["app"]:
            quem = f"App: {iniciador['app'].get('displayName', 'N/A')}"
        else:
            quem = "Sistema"

        # Extrai o alvo da ação (quem foi afetado)
        alvos = log.get("targetResources", [])
        alvo = alvos[0].get("userPrincipalName") or alvos[0].get("displayName", "N/A") if alvos else "N/A"

        resultado = log.get("result", "N/A").upper()
        resultado_fmt = f"[OK] {resultado}" if resultado == "SUCCESS" else f"[!] {resultado}"

        linhas.append([
            formatar_data_iso(log.get("activityDateTime", "")),
            log.get("activityDisplayName", "N/A")[:40],
            quem[:30],
            alvo[:30],
            resultado_fmt,
        ])

    print(tabulate(
        linhas,
        headers=["Data/Hora", "Ação", "Iniciado por", "Alvo", "Resultado"],
        tablefmt="rounded_outline",
    ))


def exibir_sign_in_logs(logs: list[dict]) -> None:
    """Formata e exibe os logs de autenticação com indicadores de risco."""
    if not logs:
        print("  Nenhum evento de autenticação encontrado na janela de tempo.")
        return

    linhas = []
    alertas = []

    for log in logs:
        status = log.get("status", {})
        sucesso = status.get("errorCode", 0) == 0
        status_fmt = "OK" if sucesso else f"FALHA ({status.get('failureReason', 'N/A')[:25]})"

        risco = log.get("riskLevelAggregated", "none").upper()
        if risco not in ("NONE", ""):
            alertas.append({
                "UPN": log.get("userPrincipalName", "N/A"),
                "Risco": risco,
                "IP": log.get("ipAddress", "N/A"),
                "Data": formatar_data_iso(log.get("createdDateTime", "")),
            })

        linhas.append([
            formatar_data_iso(log.get("createdDateTime", "")),
            (log.get("userPrincipalName") or "N/A")[:35],
            (log.get("appDisplayName") or "N/A")[:25],
            log.get("ipAddress", "N/A"),
            status_fmt[:35],
            risco or "NONE",
        ])

    print(tabulate(
        linhas,
        headers=["Data/Hora", "Usuário", "Aplicação", "IP", "Status", "Risco"],
        tablefmt="rounded_outline",
    ))

    # Exibe alertas de risco elevado separadamente
    if alertas:
        print(f"\n[!!!] ALERTAS DE RISCO DETECTADOS ({len(alertas)} evento(s)):")
        print(tabulate(alertas, headers="keys", tablefmt="rounded_outline"))
        print("\n  AÇÃO RECOMENDADA: Investigar imediatamente e considerar bloqueio preventivo.")
        print("  Em produção: integrar ao Microsoft Sentinel para alertas automáticos.")


def exibir_resumo_zero_trust(n_audit: int, n_signin: int) -> None:
    """
    Exibe um resumo do posicionamento Zero Trust com base nos dados coletados.

    Conceito: Zero Trust = "Never Trust, Always Verify" — cada acesso deve
    ser verificado, cada ação deve ser registrada, cada anomalia deve gerar alerta.
    """
    print(f"\n{'='*70}")
    print("  POSTURA ZERO TRUST — RESUMO DO LABORATÓRIO")
    print(f"{'='*70}")

    controles = [
        ["Inventário de Identidades (Script 01)", "IMPLEMENTADO", "Visibilidade total dos usuários"],
        ["Provisionamento Controlado (Script 02)", "IMPLEMENTADO", "Usuários criados com PoLP"],
        ["RBAC Granular (Script 03)", "IMPLEMENTADO", "Papéis mínimos por função"],
        ["Auditoria Contínua (Script 04)", "IMPLEMENTADO", f"{n_audit} ações / {n_signin} logins auditados"],
        ["MFA Resistente a Phishing", "NÃO TESTADO", "Configurar Passkeys/FIDO2 no Entra ID"],
        ["Conditional Access (CA Policies)", "NÃO TESTADO", "Bloquear acesso fora da rede corporativa"],
        ["PIM — Acesso Just-in-Time", "NÃO TESTADO", "Exige aprovação para papéis elevados"],
        ["SIEM Integration (Sentinel)", "NÃO TESTADO", "Alertas automáticos de anomalias"],
    ]

    print(tabulate(
        controles,
        headers=["Controle IAM", "Status", "Observação"],
        tablefmt="rounded_outline",
    ))

    print()
    print("SOBRE O UBER 2022:")
    print("  Nenhum dos controles acima existia no momento do ataque.")
    print("  Este laboratório demonstra como cada um teria bloqueado o invasor.")
    print("  Veja docs/01-caso-uber-2022.md para análise completa.")


def main() -> None:
    """
    Ponto de entrada do script 04.

    Gera relatório consolidado de auditoria das últimas 24h e exibe
    o posicionamento Zero Trust do laboratório.
    """
    print("=" * 70)
    print("  OPERATION ZERO TRUST — Script 04: Relatório de Auditoria IAM")
    print("=" * 70)
    print(f"  Janela de análise: últimas {JANELA_HORAS} horas")
    print()

    validar_configuracao()
    token = obter_token_acesso()

    print(f"\n{'─'*70}")
    print("  SEÇÃO 1: LOG DE AUDITORIA DE DIRETÓRIO")
    print(f"{'─'*70}")
    print("[*] Consultando eventos administrativos...")
    audit_logs = buscar_audit_logs_diretorio(token, JANELA_HORAS)
    print(f"    {len(audit_logs)} evento(s) encontrado(s)\n")
    exibir_audit_logs(audit_logs)

    print(f"\n{'─'*70}")
    print("  SEÇÃO 2: LOG DE AUTENTICAÇÕES (SIGN-INS)")
    print(f"{'─'*70}")
    print("[*] Consultando histórico de autenticações...")
    signin_logs = buscar_sign_in_logs(token, JANELA_HORAS)
    print(f"    {len(signin_logs)} evento(s) encontrado(s)\n")
    exibir_sign_in_logs(signin_logs)

    exibir_resumo_zero_trust(len(audit_logs), len(signin_logs))

    print()
    print("[FIM] Script 04 executado com sucesso.")
    print()
    print("Laboratório completo! Consulte o README.md para próximos passos.")


if __name__ == "__main__":
    main()
