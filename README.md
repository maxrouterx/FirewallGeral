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


⚙️ Modo Interativo
Detecta IP público e ASN automaticamente

Coleta blocos IPv4/IPv6 via RDAP

Permite entrada manual adicional de blocos CIDR e portas

Gera regras robustas segmentadas por perfil: consultoria, gerência, cliente

🧪 Modo Dry Run / Debug (em breve)
--dry-run : executa sem aplicar regras no sistema

--debug : exibe informações detalhadas de cada etapa

🛡️ Segurança
Backups automáticos com timestamp

Proteções contra duplicatas, entradas inválidas e falhas de dependência

Integração com systemctl e chattr para maior resiliência

📁 Arquivos gerados
/router-x/nft.ruleset → ruleset ativo

/etc/nftables.conf → aponta para o ruleset

Backups: /router-x/.nft.ruleset.YYYY-MM-DD_HH-MM-SS
```

Feito por Max – Especialista em redes ISP 🇧🇷
Script modular, expansível, com foco em robustez, clareza e automação.



