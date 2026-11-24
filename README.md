# Audit Sécurité - plugin Jeedom

Audit Sécurité contrôle la sécurité d'une installation Jeedom et lui donne une note sur 100, avec une lettre de A à F. Pour chaque point, il explique le risque et la marche à suivre, et beaucoup de points se corrigent en un clic.

## Fonctionnalités

- 46 contrôles : comptes et mots de passe par défaut, double authentification, force brute, liste blanche, API, HTTPS, fichiers sensibles téléchargeables, en-têtes Apache, versions de PHP et Debian, mots de passe système, SSH, NTP, mises à jour, droits des fichiers, pare-feu, fail2ban, base de données, MQTT, sauvegardes, espace disque, exposition sur Internet (UPnP, Shodan, listes noires, certificat HTTPS), droits des fichiers
- Note pondérée par la gravité ; une faille critique plafonne la lettre à D
- Corrections automatiques avec confirmation, test de la configuration et retour arrière en cas d'erreur
- Contrôles ignorables (risque accepté)
- Audit automatique quotidien ou hebdomadaire, message Jeedom quand un nouveau problème apparaît
- Équipement avec commandes (note, lettre, problèmes graves...) pour les scénarios, et widget
- Interface en français, anglais, allemand, espagnol et italien

## Installation

Depuis le Market Jeedom : *Plugins > Gestion des plugins > Market*, rechercher **Audit Sécurité**, installer puis activer le plugin.

Prérequis : Jeedom 4.4 ou supérieur.

## Documentation

- [Français](docs/fr_FR/index.md) · [English](docs/en_US/index.md) · [Deutsch](docs/de_DE/index.md) · [Español](docs/es_ES/index.md) · [Italiano](docs/it_IT/index.md)
- [Changelog](docs/fr_FR/changelog.md)

## Branches

- `stable` : version publiée sur le Market
- `beta` : version de test
