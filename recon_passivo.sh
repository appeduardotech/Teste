#!/usr/bin/env bash
# ==============================================================================
# Ferramenta de Reconhecimento Passivo (OSINT & Auditoria de Superfície DNS/IP)
# Uso exclusivo em ambientes autorizados e auditorias de segurança.
# Nenhuma requisição direta é enviada ao servidor web do domínio analisado.
# ==============================================================================

set -euo pipefail

# Cores para formatação no terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 1. Validação de argumentos
if [ "$#" -ne 1 ]; then
    echo -e "${RED}[!] Uso incorreto.${NC}"
    echo -e "Sintaxe: $0 <dominio.com.br>"
    exit 1
fi

# Limpa protocolo (http/https) ou barras caso o usuário digite uma URL
DOMAIN=$(echo "$1" | sed -e 's|^[^/]*//||' -e 's|/.*$||' | tr '[:upper:]' '[:lower:]')
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="recon_${DOMAIN}_${TIMESTAMP}"

# 2. Verificação de dependências
DEPS=("dig" "whois" "curl" "jq")
for dep in "${DEPS[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
        echo -e "${RED}[!] Dependência ausente: ${dep}.${NC} Instale antes de continuar."
        exit 1
    fi
done

mkdir -p "$OUTDIR"

echo -e "${BLUE}=================================================================${NC}"
echo -e "${BLUE}[*] Iniciando Reconhecimento Passivo para:${NC} ${YELLOW}${DOMAIN}${NC}"
echo -e "${BLUE}[*] Diretório de saída:${NC} ${OUTDIR}"
echo -e "${BLUE}=================================================================${NC}\n"

# ------------------------------------------------------------------------------
# Etapa 1: Consulta WHOIS (Titularidade, ASN e Name Servers registrados)
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] 1/5 Coletando dados WHOIS...${NC}"
whois "$DOMAIN" > "${OUTDIR}/whois.txt" 2>/dev/null || echo "Falha parcial ao consultar WHOIS" >> "${OUTDIR}/whois.txt"
echo -e "    Salvo em: ${OUTDIR}/whois.txt"

# ------------------------------------------------------------------------------
# Etapa 2: Enumeração de Registros DNS e Postura de Segurança de E-mail
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] 2/5 Consultando registros DNS públicos (A, AAAA, MX, NS, TXT, SOA)...${NC}"
DNS_FILE="${OUTDIR}/dns_records.txt"
{
    echo "=== REGISTROS A (IPv4) ==="
    dig +short A "$DOMAIN"
    echo -e "\n=== REGISTROS AAAA (IPv6) ==="
    dig +short AAAA "$DOMAIN"
    echo -e "\n=== REGISTROS MX (Servidores de E-mail) ==="
    dig +short MX "$DOMAIN"
    echo -e "\n=== REGISTROS NS (Servidores de Nome) ==="
    dig +short NS "$DOMAIN"
    echo -e "\n=== REGISTROS TXT (SPF, Verificações de Domínio) ==="
    dig +short TXT "$DOMAIN"
    echo -e "\n=== REGISTRO DMARC (_dmarc.${DOMAIN}) ==="
    dig +short TXT "_dmarc.${DOMAIN}"
    echo -e "\n=== REGISTRO SOA ==="
    dig +short SOA "$DOMAIN"
} > "$DNS_FILE"
echo -e "    Salvo em: ${DNS_FILE}"

# ------------------------------------------------------------------------------
# Etapa 3: Resolução de IP Principal e Consulta de Metadados / ASN (ipinfo.io)
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] 3/5 Identificando endereço IP principal e informações de ASN/Rede...${NC}"
MAIN_IP=$(dig +short A "$DOMAIN" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n 1 || true)

if [ -n "$MAIN_IP" ]; then
    echo -e "    IP Principal detectado: ${YELLOW}${MAIN_IP}${NC}"
    curl -s "https://ipinfo.io/${MAIN_IP}/json" | jq . > "${OUTDIR}/ip_asn_info.json" || true

    # Consulta passiva no InternetDB (Shodan) para verificar portas/CVEs já indexadas publicamente
    echo -e "    Consultando base passiva Shodan InternetDB para o IP ${MAIN_IP}..."
    curl -s "https://internetdb.shodan.io/${MAIN_IP}" | jq . > "${OUTDIR}/shodan_internetdb.json" || true
    echo -e "    Salvo em: ${OUTDIR}/ip_asn_info.json e ${OUTDIR}/shodan_internetdb.json"
else
    echo -e "${YELLOW}    [!] Nenhum registro IPv4 (A) direto encontrado para ${DOMAIN}.${NC}"
fi

# ------------------------------------------------------------------------------
# Etapa 4: Transparência de Certificados (CT Logs via crt.sh)
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] 4/5 Buscando subdomínios em Logs de Transparência de Certificados (crt.sh)...${NC}"
SUBDOMAINS_FILE="${OUTDIR}/subdomains_crtsh.txt"

if curl -s --max-time 30 "https://crt.sh/?q=%25.${DOMAIN}&output=json" | \
   jq -r '.[].name_value' 2>/dev/null | \
   sed 's/\*\.//g' | \
   sort -u > "$SUBDOMAINS_FILE"; then
    SUB_COUNT=$(wc -l < "$SUBDOMAINS_FILE" | tr -d ' ')
    echo -e "    Foram encontrados ${YELLOW}${SUB_COUNT}${NC} subdomínios/entradas únicas."
    echo -e "    Salvo em: ${SUBDOMAINS_FILE}"
else
    echo -e "${YELLOW}    [!] Tempo esgotado ou erro ao consultar crt.sh (o serviço pode estar sobrecarregado).${NC}"
fi

# ------------------------------------------------------------------------------
# Etapa 5: Histórico de URLs Indexadas (Wayback Machine / Internet Archive)
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] 5/5 Consultando histórico passivo de URLs no Archive.org (Wayback Machine)...${NC}"
WAYBACK_FILE="${OUTDIR}/wayback_urls.txt"

if curl -s --max-time 30 "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" | \
    head -n 500 > "$WAYBACK_FILE"; then
    URL_COUNT=$(wc -l < "$WAYBACK_FILE" | tr -d ' ')
    echo -e "    Coletadas ${YELLOW}${URL_COUNT}${NC} URLs históricas (limite configurado: 500)."
    echo -e "    Salvo em: ${WAYBACK_FILE}"
else
    echo -e "${YELLOW}    [!] Não foi possível obter dados do Wayback Machine.${NC}"
fi

# ------------------------------------------------------------------------------
# Resumo Final
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}=================================================================${NC}"
echo -e "${GREEN}[✓] Reconhecimento passivo concluído com sucesso!${NC}"
echo -e "Arquivos gerados em ${YELLOW}${OUTDIR}/${NC}:"
ls -lh "$OUTDIR"
echo -e "${BLUE}=================================================================${NC}"
