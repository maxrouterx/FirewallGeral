# 🔥 Script de Firewall com nftables – Automação via ASN/RDAP

Este script Bash configura um firewall robusto usando `nftables`, com:
- Coleta automática de blocos IPv4/IPv6 via RDAP a partir do IP público.
- Identificação do ASN e obtenção dinâmica de blocos.
- Definição personalizada de portas TCP/UDP para acesso.
- Geração automática do ruleset com aplicação no `/etc/nftables.conf`.
- Suporte a IPv6, fallback manual e backup completo.

## 📦 Requisitos

- Debian 12+ (ou derivados)
- Acesso root
- Internet ativa para RDAP/jq/curl
- Pacotes: `jq`, `curl`, `nftables`, etc (instalados automaticamente)

## 🚀 Execução

```bash
chmod +x firewall.sh
sudo ./firewall.sh
