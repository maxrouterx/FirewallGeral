#!/usr/bin/env bash
set -euo pipefail

## ----------------------------------------------------------------------------
# :> /tmp/firewall.sh && chmod +x /tmp/firewall.sh && nano /tmp/firewall.sh
# ----------------------------------------------------------------------------
# Script para configuração de firewall nftables com integração dinâmica
# dos blocos IPv4 e IPv6 obtidos via RDAP pelo ASN do IP público
# ----------------------------------------------------------------------------
## Variáveis de cores para destacar mensagens
MAG='\033[1;95m'; GRN='\033[0;92m'; YEL='\033[1;93m'; RED='\033[1;31m'; BLU='\033[0;94m'; NC='\033[0m'
## Diretórios e arquivos importantes
ROUTER_X_DIR="/router-x"
N_FILE="/etc/nftables.conf"
N_FILE_BK="/etc/.nftables.conf"
## Arrays para armazenar blocos CIDR IPv4 e IPv6
ipv4_cidr_blocks=()
ipv6_cidr_blocks=()
## -----------------------------------------# Função para verificar se o valor está no array (evitar duplicidade)
contains_element() {
        local seeking=$1
        shift
        local element
        for element in "$@"; do
                [[ "$element" == "$seeking" ]] && return 0
        done
        return 1
}
## --------------------------------------------# Função para verificar se um arquivo existe (e sair se não existir)
file_exists() {
        local file_local="$1"
        if [[ -f "$file_local" ]]; then
                return 0
        else
                echo -e "-- ${RED}[ ERRO ]:${NC} Arquivo (${BLU} $file_local ${NC}) NÃO encontrado.${YEL} [Encerrando o Script]...${NC}" && sleep 1
                exit 1
        fi
}
## ----------------------------------------------# Função para fazer Backup de um arquivo
mk_bkp() {
        local TSTMP
        TSTMP=$(date +%Y-%m-%d_%H-%M-%S)
        # Verifica se o arquivo existe e tenta fazer o backup
        file_exists "$1"
        if cp -f "$1" "$2.$TSTMP"; then
                echo -e "${GRN}--[ SUCESSO ]:${NC} Arquivo ${BLU}( $1 )${NC} Copiado para ${BLU}( $2.$TSTMP )${NC}"
        else
                echo -e "${RED}--[ ERRO ]:${NC} Falha ao Fazer Backup de: ${BLU}($1)${NC}.\n"
        fi
}
## -----------------------------------------# Função para configurar o resolv.conf com as entradas DNS
set_dns_config() {
        local RESOLV_CNF='/etc/resolv.conf'
        chattr -ia "$RESOLV_CNF" 2>/dev/null || true
        cat >"$RESOLV_CNF" <<EOF
## --------------------------------------------
#        MAX Configuração resolv.conf
## --------------------------------------------
nameserver 9.9.9.9
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2620:fe::9
nameserver 2620:119:35::35
## --------------------------------------------
EOF
        echo -e "-- DNS (${BLU}$RESOLV_CNF${NC}) configurado com ${GRN}[SUCESSO]${NC}"
}
update_check() {
        if ! apt update -qq &>/dev/null; then
                echo -e "-- ${RED}[ERRO]: (apt update )${NC} - ${YEL} Falha ao Atualizar Repositórios. Verifique sua Conexão.${NC}" && exit 1
        fi
        if ! apt dist-upgrade -yqq; then
                echo -e "-- ${RED}[ERRO]: ( apt dist-upgrade -yqq )${NC} - ${YEL} Falha na Atualização do Sistema.${NC}" && exit 1
        fi
}
## -----------------------------------------# Função para instalar pacotes
install_packages() {
        echo -e "\n-- UPDATE [${GRN} OK ${NC}] - ATUALIZANDO E INSTALANDO PACOTES NECESSÁRIOS...${YEL} [ AGUARDE PODE DEMORAR ]${NC}"
        # Bota Grafana pra NÃO atualizar e Verifica se o serviço nftables existe.
        apt-mark hold grafana &>/dev/null || true
        set_dns_config
        update_check

        if apt-get install -yq smartmontools curl ethtool parted man-db hdparm iotop htop wget ipcalc nmap \
                python3-pip sipcalc whois dnsutils pwgen dnstop iftop locate traceroute mtr-tiny fio \
                net-tools dstat nload lshw progress arping ncdu netdiscover tcpdump bmon lm-sensors \
                bash-completion ioping unzip lsb-release gdisk kpartx inxi apt-rdepends lldpd jq >/dev/null 2>&1; then
                echo -e "\n-- [${BLU} Instalação de Pacotes Adicionais ${NC}] Concluída com ${GRN}[ SUCESSO ]${NC}. \n"
        else
                echo -e "\n-- ${RED}[ERRO]${NC}: Instalação de Pacotes Adicionais Falhou. ${YEL}Verifique os LOGS para Detalhes${NC}... \n"
                exit 1
        fi
}
## -----------------------------------------# Verifica se o serviço nftables existe
check_setup_nftables() {
        echo -e "\n-- Verificando Diretório: (${BLU} $ROUTER_X_DIR ${NC}) ..."
        if [ ! -d "$ROUTER_X_DIR" ]; then
                mkdir -p "$ROUTER_X_DIR" && echo -e "-- O Diretório (${BLU}$ROUTER_X_DIR${NC}) Criado com ${GRN}[ SUCESSO ]${NC}.\n"
        else
                echo -e "-- Diretório (${BLU} $ROUTER_X_DIR ${NC}) já Existe. [ Prosseguindo ]...\n"
        fi
        # Verifica se o serviço nftables existe
        if systemctl list-unit-files --type=service | grep -q "nftables.service"; then
                ## --------------------------------------------# Verifica se o arquivo /etc/nftables.conf existe e faz backup
                echo -e "\n--${YEL} VERIFICANDO ARQUIVO${NC} [$N_FILE] ..." && sleep 1
                file_exists "$N_FILE"
                chattr -ai "$N_FILE" 2>/dev/null || true
                mk_bkp "$N_FILE" "$N_FILE_BK"
                cat >"$N_FILE" <<EOF
#!/sbin/nft -f
flush ruleset
table inet filter {
        chain input {
                type filter hook input priority 0;
        }
        chain forward {
                type filter hook forward priority 0;
        }
        chain output {
                type filter hook output priority 0;
        }
}
EOF
                # Verifica o status do serviço nftables
                systemctl restart nftables.service
                NFT_STTS=$(systemctl is-active nftables.service)
                if [ "$NFT_STTS" == "active" ]; then
                        echo -e "\n-- Status do NFTABLES: ${GRN}[ $NFT_STTS ]${NC}"
                else
                        echo -e "\n-- Status do NFTABLES: ${RED}[ $NFT_STTS ]${NC}" && sleep 3
                fi
        else
                echo -e "\n-- O serviço [nftables] ${YEL}NÃO${NC} está encontrado no Sistema. ${BLU}Instalando via [apt]${NC}..."
                update_check
                if apt-get install nftables -yqq; then
                        echo -e "-- ${GRN}Pacote [nftables] instalado com SUCESSO.${NC}"
                else
                        echo -e "-- ${RED}[ ERRO ]:${NC} ${YEL}Falha na instalação do [nftables]...${NC}" && exit 1
                fi
        fi
}
## --------------------------------------------# Função para validar se um IP é IPv4 ou IPv6
validar_ipv4() {
        local ip=$1
        # Regex para IPv4
        local ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
        # Verifica se o IP corresponde ao formato IPv4
        [[ $ip =~ $ipv4_regex ]] && return 0 || return 1
}
## ------------------------------------------------------------------------------------------
get_ip_block() {
        # Tentativa de obter o endereço IP público usando curl
        IP4_PUB=$(curl -s https://ipv4.icanhazip.com || wget -qO- http://ipecho.net/plain)
        IP4_PUB=$(echo "$IP4_PUB" | tr -d '\r\n')

        # Verifica se o IP público é um IPv4 válido
        if ! validar_ipv4 "$IP4_PUB"; then
                echo -e "\n- ${YEL} IPv4 público inválido. Informe o BLOCO IPv4 para ACESSO ao SERVIDOR:${NC}"
                read -rp "--> Ex: ( $IP4_PUB/22 ) : " ASN_BLOCK
        else
                echo -e "--${GRN} IP público detectado:${NC} $IP4_PUB"
                # Consulta RDAP para o IP
                RDAP_RESPONSE=$(curl -s "https://rdap.registro.br/ip/$IP4_PUB")
                ASN=$(echo "$RDAP_RESPONSE" | jq -r '.nicbr_autnum // empty')
                BLOCO_ACESS=$(echo "$RDAP_RESPONSE" | jq -r '.handle // empty')
                export ASN

                # Verifica se o ASN foi encontrado
                if [[ -z "$ASN" || "$ASN" == "null" ]]; then
                        echo -e "--${RED} ASN não encontrado para IP $IP4_PUB.${NC}"
                        ASN_BLOCK="IP_BLOCK_NOT_FOUND"
                else
                        # Obtendo os blocos de IP relacionados ao ASN e removendo as URLs
                        ASN_BLOCK=$(curl -s "https://rdap.registro.br/autnum/$ASN" | jq -r '.links[] | select(.rel == "related") | .href // empty' | sed 's|https://rdap.registro.br/ip/||g')
                        [[ -z "$ASN_BLOCK" ]] && ASN_BLOCK="IP_BLOCK_NOT_FOUND"
                fi
                # Tenta obter o endereço IP da máquina. Exibe os IPs da máquina
                if [[ -z "$BLOCO_ACESS" || "$BLOCO_ACESS" == "null" ]]; then
                        echo -e "--${YEL} Bloco IP NÃO localizado via RDAP. Informe Manualmente:${NC}"
                        while true; do
                                read -rp "--> Informe Bloco IPv4 CIDR (ex: 192.168.1.0/24): " BLOCO_ACESS
                                [[ "$BLOCO_ACESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] && break
                                echo -e "--${RED} Formato inválido. Tente Novamente.${NC}"
                        done
                fi
        fi
        echo -e "--${YEL} BLOCO IPv4 para ACESSO ao SERVIDOR:${NC} [ $BLOCO_ACESS ]"
        if ! contains_element "$BLOCO_ACESS" "${ipv4_cidr_blocks[@]}"; then
                ipv4_cidr_blocks+=("$BLOCO_ACESS")
        fi
}
## --------------------------------------------# Coleta blocos IPv6 via RDAP a partir do mesmo ASN
get_ipv6_blocks() {
        local ASN="$1"
        local links bloco
        if [[ -z "$ASN" || "$ASN" == "null" ]]; then
                echo -e "-- ${YEL}[AVISO]:${NC} ASN inválido ou não definido. Ignorando coleta IPv6."
                return
        fi
        echo -e "-- ${BLU}Consultando Blocos IPv6 para ASN: $ASN ...${NC}"
        mapfile -t links < <(curl -s "https://rdap.registro.br/autnum/$ASN" | jq -r '.links[]?.href')

        for link in "${links[@]}"; do
                if [[ "$link" =~ ^https://rdap\.registro\.br/ip/([0-9a-fA-F:]+::?)/([0-9]+)$ ]]; then
                        bloco="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
                        if ! contains_element "$bloco" "${ipv6_cidr_blocks[@]}"; then
                                ipv6_cidr_blocks+=("$bloco")
                        fi
                fi
        done
        if [[ "${#ipv6_cidr_blocks[@]}" -eq 0 ]]; then
                echo -e "-- ${YEL}[AVISO]:${NC} Nenhum bloco IPv6 foi detectado para o ASN $ASN."
        else
                echo -e "-- ${GRN}Blocos IPv6 adicionados: ${NC}"
                for bloco in "${ipv6_cidr_blocks[@]}"; do
                        echo -e "${MAG}    $bloco ${NC}"
                done
        fi
        # Gera a string separada por vírgula para blocos IPv6
        ipv6_blocks_string=$(IFS=, ; echo "${ipv6_cidr_blocks[*]}")
        # Loop para adicionar mais blocos CIDR IPv4, evitando duplicatas
        while true; do
                read -rp "$(echo -e "\n-- Informe Outro BLOCO IPv4 Para Acesso (${YEL} ENTER para SAIR ${NC}):")" novoBloco
                if [[ -z $novoBloco ]]; then
                        sleep 1
                        break
                fi
                if [[ ! $novoBloco =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
                        echo -e "-${RED} [ Erro ] - BLOCO CIDR IPv4 inválido.${NC}"
                        continue
                fi
                # Verifica se o bloco já foi adicionado ao array usando a função contains_element
                if contains_element "$novoBloco" "${ipv4_cidr_blocks[@]}"; then
                        echo -e "--${YEL} [ Aviso ] ${NC}- O Bloco ( $novoBloco ) já foi informado... [${GRN} OK ${NC}]"
                        continue
                fi
                ipv4_cidr_blocks+=("$novoBloco")
                echo -e "-- ${GRN}Novo Bloco IPv4 CIDR${NC}: $novoBloco"
        done
        # Transforma o array de blocos em uma string separada por vírgulas
        ipv4_blocks_string=$(IFS=, ; echo "${ipv4_cidr_blocks[*]}")
        echo -e "--${GRN} Blocos CIDR IPv4 Informados${NC}: $ipv4_blocks_string \n" && sleep 1
}
## --------------------------------------------# Verifica se o arquivo de configuração do SSH existe
config_ssh() {
        # Caminho para o arquivo de configuração do SSH
        SSH_CONFIG='/etc/ssh/sshd_config'
        if [[ -f "$SSH_CONFIG" ]]; then
                #SSH_PORT=$(grep -i "^Port" "$SSH_CONFIG" | awk '{print $2}')
                SSH_PORT=$(grep -i port /etc/ssh/sshd_config | awk '{ print $2 }' | grep -E "[[:digit:]]" | head -n1)
        else
                echo -e "\n-- Arquivo [ $SSH_CONFIG ] NÃO Existe -- ${RED} SAINDO... ${NC}" ; exit 1
        fi
        # Verifica se a porta é válida (entre 22 e 65535)
        if [[ "$SSH_PORT" -lt 22 || "$SSH_PORT" -gt 65535 ]]; then
                echo "--> A PORTA SSH extraída [ $SSH_PORT ] NÃO é válida."
                read -rp "$(echo -e "-- Por Favor, informe um Número de porta SSH Válido (${YEL}22-65535${NC}):")" SSH_PORT
                # Valida a nova porta fornecida pelo usuário
                while [[ ! "$SSH_PORT" =~ ^[0-9]+$ || "$SSH_PORT" -lt 22 || "$SSH_PORT" -gt 65535 ]]; do
                        read -rp "$(echo -e "--> Número de porta Inválido. Informe um Número de porta Válido (${YEL}22-65535${NC}):")" SSH_PORT
                done
        else
                echo -e "\n-- ${BLU}Porta SSH Configurada:${NC} [${YEL} $SSH_PORT ${NC}] -- ${RED}NÃO Precisa ser informada Abaixo: ${NC}"
        fi
}
## --------------------------------------------# Loop para solicitar as portas
portas_regex() {
        config_ssh
        while true; do
                read -rp "$(echo -e "Informe a(s) OUTRA(s) PORTA(s) para ACESSO (Formato: ${YEL}80/tcp${NC} ou ${YEL}53/udp${NC}) - (${YEL} ENTER para SAIR ${NC}):")" entrada
                [[ -z "$entrada" ]] && break

                if [[ ! "$entrada" =~ ^[0-9]{2,5}/(tcp|udp)$ ]]; then
                        echo -e "-- ${RED}[ ERRO ]:${NC} Formato inválido. Use ${YEL}<porta>/<tcp|udp>${NC} (ex: 443/tcp)"
                        continue
                fi

                porta="${entrada%%/*}"
                proto="${entrada##*/}"

                if ((porta < 10 || porta > 65534)); then
                        echo -e "-- ${RED}[ ERRO ]:${NC} Porta fora do intervalo permitido (10-65534)"
                        continue
                fi

                if [[ "$proto" == "tcp" ]]; then
                        if ! contains_element "$porta" "${tcp_ports[@]}"; then
                                tcp_ports+=("$porta")
                        else
                                echo -e "-- ${YEL}[AVISO]:${NC} Porta TCP $porta já adicionada."
                        fi
                elif [[ "$proto" == "udp" ]]; then
                        if ! contains_element "$porta" "${udp_ports[@]}"; then
                                udp_ports+=("$porta")
                        else
                                echo -e "-- ${YEL}[AVISO]:${NC} Porta UDP $porta já adicionada."
                        fi
                fi
        done
        # Transforma arrays em strings separadas por vírgulas
        tcp_ports_string=$(IFS=, ; echo "${tcp_ports[*]}")
        udp_ports_string=$(IFS=, ; echo "${udp_ports[*]}")
}
## --------------------------------------------# Gera o arquivo de regras do nftables
generate_ruleset_file() {
        local RULESET_PATH="$ROUTER_X_DIR/nft.ruleset"
        # Validando se SSH_PORT e portas estão definidas
        echo -e "-- ${GRN}Portas TCP:${NC} ${tcp_ports_string}"
        echo -e "-- ${GRN}Portas UDP:${NC} ${udp_ports_string}"
        sleep 1
        if [[ -z "${SSH_PORT:-}" ]]; then
                echo -e "-- ${RED}[ ERRO ]:${NC} Variável SSH_PORT não definida. Saindo..." && exit 1
        fi
        if [[ ${#tcp_ports[@]} -eq 0 && ${#udp_ports[@]} -eq 0 ]]; then
                echo -e "-- ${YEL}[AVISO]:${NC} Nenhuma porta adicional informada. Prosseguindo apenas com SSH.\n"
        fi
        chattr -ai "$RULESET_PATH" &>/dev/null
        cat >"$RULESET_PATH" <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
        # Permite os IPs da sua rede.
        set consultoria-v4 {
                type ipv4_addr
                flags interval
                # IPs IPv4 consultoria
                elements = { IPS_CONSULT } # IPs IPv4 consultoria
        }
        set gerencia-v4 {
                type ipv4_addr
                flags interval
                # IPs IPv4 privados + IPv4 GERENCIA
                elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, $ipv4_blocks_string }
        }
        set cliente-v4 {
                type ipv4_addr
                flags interval
                # IPs IPv4 privados + IPv4 Cliente
                elements = { $ipv4_blocks_string, 100.64.0.0/10 }
        }
        set publico-v4 {
                type ipv4_addr
                flags interval
                # IPs IPv4 públicos
                elements = { 0.0.0.0/0 }
        }
        set gerencia-v6 {
                type ipv6_addr
                flags interval
                # IPs IPv6 privados, IPv6 link-local, IPv6 multicast
                elements = { fe80::/10, ff00::/8, fc00::/7, $ipv6_blocks_string }
        }
        set publico-v6 {
                type ipv6_addr
                flags interval
                elements = { ::/0 } # IPs IPv6 públicos
        }
        chain input {
                type filter hook input priority 0;
# ACESSOS
        # Permitir conexões locais
                iif lo accept
                ip saddr 127.0.0.1 ip daddr 127.0.0.1 counter accept
        # Descartar conexões inválidas
                ct state invalid counter drop
        # Permitir ICMP (ping) IPv4.
                ip saddr @consultoria-v4 ip protocol icmp limit rate 5/second accept
                ip saddr @gerencia-v4 ip protocol icmp limit rate 5/second accept
                ip saddr @cliente-v4 ip protocol icmp limit rate 5/second accept
                #ip protocol icmp icmp type { echo-reply, echo-request } limit rate 5/second counter accept
        # Permitir traceroute IPv4
                udp dport 33434-33524 ct state { new,related,established } counter accept
        # Regras para acesso SSH
                ip saddr @consultoria-v4 tcp dport ${SSH_PORT}counter accept
                ip saddr @gerencia-v4 tcp dport ${SSH_PORT} counter accept
        # Permitir Acesso Outras PORTAS IPv4.
                ip saddr @gerencia-v4 udp dport { 10050,10051,2049${udp_ports_string:+,$udp_ports_string} } counter accept
                ip saddr @gerencia-v4 tcp dport { 10050,10051${tcp_ports_string:+,$tcp_ports_string} } counter accept
                ip saddr @cliente-v4 tcp dport { ${tcp_ports_string} } counter accept
                ip saddr @consultoria-v4 tcp dport { ${tcp_ports_string} } counter accept
                ip saddr @publico-v4 tcp dport { ${tcp_ports_string} } counter accept
# ACESSOS IPv6
        # Permitir conexões localhost IPv6
                iifname "lo" accept
                ip6 saddr ::1 ip6 daddr ::1 counter accept
        # Conexões estabelecidas e relacionadas IPv6.
                ct state { related, established } counter accept
        # Permitir ICMPv6 (ping) IPv6
                ip6 nexthdr icmpv6 accept
        # Permitir traceroute IPv6
                ip6 nexthdr 58 ct state new,related,established counter accept
        # Permitir IPs IPv6 para portas
                ip6 saddr @publico-v6 tcp dport { ${tcp_ports_string} } counter accept
                ip6 saddr @gerencia-v6 tcp dport $SSH_PORT counter accept
        # Libera tráfego IPv6 link-local, IPv6 multicast, IPv6 privados
                ip6 saddr @gerencia-v6 counter accept
# HABILITAR LOGS CASO PRECISE;
        #       counter log prefix "INPUT_DROP: " level info
                counter drop
        }
        chain forward {
                type filter hook forward priority 0; policy drop;
        }
        chain output {
                type filter hook output priority 0; policy accept;
        }
}
EOF
}
## --------------------------------------------# Aplica a configuração final no /etc/nftables.conf
apply_nftables_config() {
        local RULESET_FILE="$ROUTER_X_DIR/nft.ruleset"
        local TSTMP
        TSTMP=$(date +%Y-%m-%d_%H-%M-%S)
        cp -f "$RULESET_FILE" "$ROUTER_X_DIR/.nft.ruleset.$TSTMP"
        if [ ! -f "$RULESET_FILE" ]; then
                echo -e "-- ${RED}[ERRO]:${NC} Arquivo (${BLU} $RULESET_FILE ${NC}) NÃO encontrado. ${YEL}[ Saindo ]${NC}..." && exit 1
        fi
        echo "include \"$RULESET_FILE\";" >"$N_FILE"

        if systemctl restart nftables; then
                echo -e "\n-- Configuração do ${YEL}NFTABLES${NC} atualizada com ${GRN}[ SUCESSO ]${NC} \n"
                chattr +ai "$N_FILE" "$RULESET_FILE" 2>/dev/null
                systemctl enable nftables.service --quiet
        else
                echo -e "\n${RED}--[ ERRO ]:${NC} ao Reiniciar o serviço do ${YEL}NFTABLES${NC}.  \n"
                journalctl -xe | grep -i "nftables" | tail -n 20 && sleep 3
                nft -c -f "$RULESET_FILE"
                exit 1
        fi
}
## --------------------------------------------# Execução principal
main() {
        install_packages
        get_ip_block
        get_ipv6_blocks "$ASN"
        check_setup_nftables
        portas_regex
        generate_ruleset_file
        apply_nftables_config
}
main
