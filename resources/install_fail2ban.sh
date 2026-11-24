#!/bin/bash
# Installe et configure fail2ban. Lancé en root par le plugin Audit Sécurité (correction « fail2ban »).
#   $1 : racine de Jeedom (ex. /var/www/html)
#   $2 : adresses jamais bannies, séparées par des espaces (liste blanche de Jeedom)

set -u
JEEDOM_ROOT="${1:-/var/www/html}"
IGNORE_IP="${2:-127.0.0.1/8 ::1}"
JAIL=/etc/fail2ban/jail.d/auditsecurity.local

echo "== $(date '+%F %T') Installation de fail2ban =="
export DEBIAN_FRONTEND=noninteractive

if ! command -v fail2ban-client >/dev/null 2>&1; then
  apt-get update -q || echo "apt-get update a échoué, installation avec les listes actuelles"
  if ! apt-get install -y -q fail2ban; then
    echo "ERREUR : l'installation de fail2ban a échoué"
    exit 1
  fi
fi

# Debian 12+ n'a plus /var/log/auth.log par défaut : SSH se lit alors dans le journal systemd
SSH_BACKEND=auto
if [ ! -f /var/log/auth.log ] && command -v journalctl >/dev/null 2>&1; then
  apt-get install -y -q python3-systemd || true
  SSH_BACKEND=systemd
fi

# Action de bannissement selon l'outil de filtrage disponible
BANACTION=iptables-multiport
if ! command -v iptables >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
  BANACTION=nftables-multiport
fi

{
  echo "# Généré par le plugin Jeedom Audit Sécurité"
  echo "[DEFAULT]"
  echo "ignoreip = ${IGNORE_IP}"
  echo "bantime = 1h"
  echo "findtime = 10m"
  echo "maxretry = 5"
  echo "banaction = ${BANACTION}"
  echo "banaction_allports = ${BANACTION/multiport/allports}"
  echo
  if command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; then
    echo "[sshd]"
    echo "enabled = true"
    echo "backend = ${SSH_BACKEND}"
    echo
  fi
  # Règles Apache livrées avec Jeedom, uniquement si le log d'erreurs existe (sinon fail2ban refuse de démarrer)
  if ls "${JEEDOM_ROOT}"/log/http*.error >/dev/null 2>&1; then
    for jail in apache-botsearch apache-overflows apache-noscript; do
      echo "[${jail}]"
      echo "enabled = true"
      echo "backend = auto"
      echo "port = http,https"
      echo "logpath = ${JEEDOM_ROOT}/log/http*.error"
      [ "${jail}" = "apache-noscript" ] && echo "maxretry = 3"
      echo
    done
  fi
} > "${JAIL}"
chmod 644 "${JAIL}"
echo "Configuration écrite dans ${JAIL} :"
cat "${JAIL}"

if ! fail2ban-client -t >/dev/null 2>&1; then
  echo "ERREUR : configuration fail2ban invalide, fichier ${JAIL} retiré :"
  fail2ban-client -t 2>&1 | tail -n 5
  rm -f "${JAIL}"
fi

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban
sleep 3
if systemctl is-active --quiet fail2ban; then
  echo "fail2ban est actif"
  fail2ban-client status
else
  echo "ERREUR : fail2ban n'a pas démarré"
  journalctl -u fail2ban -n 20 --no-pager 2>/dev/null
  exit 1
fi
echo "== $(date '+%F %T') Terminé =="
