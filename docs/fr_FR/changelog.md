---
layout: default
lang: fr_FR
---

# Changelog Audit Sécurité

# 23/11/2026 - 0.2.0

- Nouvelle catégorie « Exposition Internet » : ports ouverts sur la box Internet par UPnP, exposition vue par Shodan, listes noires d'adresses IP, certificat HTTPS de l'accès externe
- Tests via des services externes (Shodan, listes noires) activables dans la configuration, désactivés par défaut
- Nouveaux contrôles : services dangereux à l'écoute, redémarrage en attente, dossiers sensibles lisibles par tous (avec correction automatique), fichiers SUID/SGID
- fail2ban n'est compté dans la note que si Jeedom est exposé sur Internet
- Nouvelle interface : jauge de la note, verdict, priorités, notes par catégorie filtrables, cartes dépliables
- Correction : l'interface restait sur « Audit en cours » après un audit

# 23/11/2026 - 0.1.0

- Première version (bêta)
- 38 contrôles répartis en 8 catégories : comptes, accès, API, Jeedom et plugins, serveur web, système, réseau, sauvegardes
- Note sur 100 et lettre de A à F, pondérées par la gravité ; une faille critique plafonne la lettre à D
- Corrections en un clic pour 16 contrôles, avec confirmation et retour arrière si la configuration système est invalide
- Contrôles ignorables (risque accepté), retirés de la note
- Audit automatique quotidien ou hebdomadaire, message Jeedom quand un nouveau problème apparaît
- Équipement avec les commandes Note, Lettre, Problèmes graves, Non conformes, À améliorer, Dernier audit, Résumé et Lancer l'audit
- Widget avec la lettre, la note et les compteurs
- Interface en français, anglais, allemand, espagnol et italien
