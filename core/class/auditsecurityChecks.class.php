<?php
/* This file is part of Jeedom.
 *
 * Jeedom is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Jeedom is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Jeedom. If not, see <http://www.gnu.org/licenses/>.
 */

require_once __DIR__ . '/auditsecurityTools.class.php';

/**
 * Catalogue des contrôles de sécurité.
 *
 * Chaque contrôle <id> est décrit dans definitions() et implémenté par check_<id>(), qui retourne
 * un résultat {status, detail, items} :
 *   - pass : conforme (tous les points) ;
 *   - warn : à améliorer (la moitié des points) ;
 *   - fail : non conforme (aucun point) ;
 *   - info : information, hors note ;
 *   - skip : non vérifiable sur cette installation, hors note.
 *
 * Une correction automatique éventuelle est implémentée par fix_<id>() : elle retourne un message
 * de succès ou lève une exception.
 */
class auditsecurityChecks {

  /** Ports et chemins utilisés par plusieurs contrôles */
  const MYSQL_PORT = 3306;
  const MQTT_PORT = 1883;

  /** Fin de support (sécurité, LTS comprise) des versions de Debian */
  private static $debianEol = array(
    '8' => '2020-06-30',
    '9' => '2022-06-30',
    '10' => '2024-06-30',
    '11' => '2026-08-31',
    '12' => '2028-06-30',
    '13' => '2030-06-30',
  );

  /** Fin de support sécurité des versions de PHP */
  private static $phpEol = array(
    '7.3' => '2021-12-06',
    '7.4' => '2022-11-28',
    '8.0' => '2023-11-26',
    '8.1' => '2025-12-31',
    '8.2' => '2026-12-31',
    '8.3' => '2027-12-31',
    '8.4' => '2028-12-31',
    '8.5' => '2029-12-31',
  );

  /** Mots de passe trop courants testés sur les comptes Jeedom et système */
  private static $commonPasswords = array('admin', 'jeedom', 'Mjeedom96', 'password', 'motdepasse', '123456', '12345678', 'azerty', 'qwerty', '0000', '1234', 'raspberry', 'root');

  /** Comptes techniques créés par le core Jeedom */
  private static $technicalUsers = array('internal_report', 'jeedom_support');

  /* ************************************************************************************ */
  /*                                   Catalogue                                          */
  /* ************************************************************************************ */

  public static function categories() {
    return array(
      'accounts' => array('name' => __('Comptes utilisateurs', __FILE__), 'icon' => 'fas fa-users'),
      'access' => array('name' => __('Accès et connexions', __FILE__), 'icon' => 'fas fa-door-closed'),
      'exposure' => array('name' => __('Exposition Internet', __FILE__), 'icon' => 'fas fa-globe-europe'),
      'api' => array('name' => __('API', __FILE__), 'icon' => 'fas fa-key'),
      'jeedom' => array('name' => __('Jeedom et plugins', __FILE__), 'icon' => 'fas fa-puzzle-piece'),
      'web' => array('name' => __('Serveur web', __FILE__), 'icon' => 'fas fa-globe'),
      'system' => array('name' => __('Système', __FILE__), 'icon' => 'fas fa-server'),
      'network' => array('name' => __('Réseau et services', __FILE__), 'icon' => 'fas fa-network-wired'),
      'resilience' => array('name' => __('Sauvegardes et résilience', __FILE__), 'icon' => 'fas fa-life-ring'),
    );
  }

  public static function definitions() {
    $linkUsers = array('type' => 'link', 'label' => __('Gérer les utilisateurs', __FILE__), 'url' => 'index.php?v=d&p=user');
    $linkUpdate = array('type' => 'link', 'label' => __('Centre de mises à jour', __FILE__), 'url' => 'index.php?v=d&p=update');
    $linkSecurity = array('type' => 'link', 'label' => __('Configuration > Sécurité', __FILE__), 'url' => 'index.php?v=d&p=administration#securitytab');
    $linkApi = array('type' => 'link', 'label' => __('Configuration > API', __FILE__), 'url' => 'index.php?v=d&p=administration#apitab');
    $linkNetwork = array('type' => 'link', 'label' => __('Configuration > Réseaux', __FILE__), 'url' => 'index.php?v=d&p=administration#networktab');
    $linkBackup = array('type' => 'link', 'label' => __('Sauvegardes', __FILE__), 'url' => 'index.php?v=d&p=backup');
    $linkLogs = array('type' => 'link', 'label' => __('Configuration > Logs', __FILE__), 'url' => 'index.php?v=d&p=administration#logtab');
    $linkPluginConfig = array('type' => 'link', 'label' => __('Configuration du plugin', __FILE__), 'url' => 'index.php?v=d&p=plugin&id=auditsecurity');
    $fixApache = array(
      'type' => 'auto',
      'label' => __('Restaurer la configuration Apache de Jeedom', __FILE__),
      'confirm' => __('Le fichier /etc/apache2/conf-available/security.conf va être remplacé par celui fourni par Jeedom (l\'actuel est sauvegardé en security.conf.auditsecurity.bak), le module headers activé et Apache rechargé. Si la configuration est invalide, l\'ancienne est remise en place. Cette configuration interdit d\'afficher Jeedom dans une page d\'un autre site (iframe) et limite les contenus externes : un tableau de bord qui intègre Jeedom, ou un plugin qui affiche un site externe, peut ne plus fonctionner.', __FILE__),
    );

    return array(
      /* ----------------------------- Comptes ----------------------------- */
      'default_admin' => array(
        'category' => 'accounts',
        'severity' => 'critical',
        'title' => __('Compte admin avec le mot de passe par défaut', __FILE__),
        'description' => __('Le couple admin / admin est le premier essayé par les robots qui scannent Internet. S\'il fonctionne, l\'attaquant a la main sur toute la maison.', __FILE__),
        'recommendation' => __('Changez le mot de passe du compte admin, ou créez un administrateur nominatif et désactivez le compte admin.', __FILE__),
        'fix' => $linkUsers,
      ),
      'weak_passwords' => array(
        'category' => 'accounts',
        'severity' => 'high',
        'title' => __('Mots de passe trop courants', __FILE__),
        'description' => __('Le plugin essaie, sans se connecter, une liste de mots de passe parmi les plus utilisés (jeedom, 123456, azerty, identifiant = mot de passe...) sur chaque compte actif.', __FILE__),
        'recommendation' => __('Utilisez des mots de passe longs et uniques (une phrase de passe ou un gestionnaire de mots de passe).', __FILE__),
        'fix' => $linkUsers,
      ),
      'support_access' => array(
        'category' => 'accounts',
        'severity' => 'medium',
        'title' => __('Accès support Jeedom ouvert', __FILE__),
        'description' => __('L\'accès support crée le compte jeedom_support, qui permet au support Jeedom de se connecter à votre box. Il ne doit rester ouvert que le temps d\'une intervention.', __FILE__),
        'recommendation' => __('Fermez l\'accès support une fois l\'intervention terminée.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Fermer l\'accès support', __FILE__), 'confirm' => __('Le compte jeedom_support va être désactivé.', __FILE__)),
      ),
      'twofa' => array(
        'category' => 'accounts',
        'severity' => 'high',
        'title' => __('Double authentification des administrateurs', __FILE__),
        'description' => __('Jeedom demande le code de double authentification (2FA) lors des connexions depuis l\'extérieur. Sans 2FA, un mot de passe volé ou deviné suffit pour prendre le contrôle depuis Internet.', __FILE__),
        'recommendation' => __('Activez la double authentification sur chaque compte administrateur (Profil > Sécurité), au moins si Jeedom est accessible depuis Internet.', __FILE__),
        'fix' => array('type' => 'link', 'label' => __('Mon profil', __FILE__), 'url' => 'index.php?v=d&p=profils'),
      ),
      'admin_count' => array(
        'category' => 'accounts',
        'severity' => 'low',
        'title' => __('Nombre d\'administrateurs', __FILE__),
        'description' => __('Chaque compte administrateur est une porte d\'entrée complète. Moins il y en a, plus la surface d\'attaque est réduite.', __FILE__),
        'recommendation' => __('Gardez trois administrateurs au plus ; donnez le profil Utilisateur ou Utilisateur limité aux autres comptes.', __FILE__),
        'fix' => $linkUsers,
      ),
      'inactive_users' => array(
        'category' => 'accounts',
        'severity' => 'low',
        'title' => __('Comptes inutilisés', __FILE__),
        'description' => __('Un compte actif qui ne sert plus (ancien occupant, compte de test...) reste une porte d\'entrée que personne ne surveille. Seules les connexions par l\'interface web sont enregistrées : un compte utilisé uniquement par l\'application mobile ou l\'API peut apparaître ici à tort.', __FILE__),
        'recommendation' => __('Désactivez ou supprimez les comptes sans connexion depuis plus de 6 mois.', __FILE__),
        'fix' => $linkUsers,
      ),

      /* ------------------------------ Accès ------------------------------ */
      'bruteforce' => array(
        'category' => 'access',
        'severity' => 'high',
        'title' => __('Protection contre les attaques par force brute', __FILE__),
        'description' => __('Jeedom peut bannir une adresse IP après plusieurs échecs de connexion. Sans cette protection, un robot peut essayer des milliers de mots de passe.', __FILE__),
        'recommendation' => __('Gardez un nombre d\'échecs autorisés bas (6 par défaut) et une durée de bannissement non nulle.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Appliquer les valeurs recommandées', __FILE__), 'confirm' => __('6 échecs autorisés sur 5 minutes, bannissement de 10 minutes (valeurs par défaut de Jeedom).', __FILE__)),
      ),
      'whiteips' => array(
        'category' => 'access',
        'severity' => 'high',
        'title' => __('Liste blanche d\'adresses IP', __FILE__),
        'description' => __('Les adresses de la liste blanche ne sont jamais bannies et peuvent utiliser l\'API en mode « IP blanche ». Une entrée trop large (*.*.*.*) désactive ces protections pour tout Internet.', __FILE__),
        'recommendation' => __('Limitez la liste blanche aux plages de votre réseau local (ex. 192.168.1.*).', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Limiter aux plages privées', __FILE__), 'confirm' => __('Les entrées qui couvrent tout Internet seront retirées et les entrées trop larges réduites à leur partie privée (ex. 172.*.*.* devient 172.16.0.0/12). Les adresses publiques précises ne sont pas modifiées.', __FILE__)),
      ),
      'session_lifetime' => array(
        'category' => 'access',
        'severity' => 'low',
        'title' => __('Durée des sessions', __FILE__),
        'description' => __('Une session très longue reste utilisable longtemps sur un appareil perdu ou partagé.', __FILE__),
        'recommendation' => __('Gardez une durée de session raisonnable (24 h par défaut). Les appareils de confiance peuvent être enregistrés pour éviter de retaper le mot de passe.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Ramener à 24 heures', __FILE__), 'confirm' => __('Les sessions expireront après 24 heures.', __FILE__)),
      ),
      'external_https' => array(
        'category' => 'access',
        'severity' => 'high',
        'title' => __('Accès externe chiffré (HTTPS)', __FILE__),
        'description' => __('En HTTP, le mot de passe et tous les échanges circulent en clair sur Internet et peuvent être interceptés (Wi-Fi public, opérateur...).', __FILE__),
        'recommendation' => __('Utilisez le DNS Jeedom (HTTPS inclus) ou un reverse proxy avec un certificat (Let\'s Encrypt), et déclarez l\'accès externe en https://.', __FILE__),
        'fix' => $linkNetwork,
      ),

      /* ------------------------ Exposition Internet ------------------------ */
      'upnp_mappings' => array(
        'category' => 'exposure',
        'severity' => 'high',
        'title' => __('Ports ouverts sur la box Internet par UPnP', __FILE__),
        'description' => __('Avec UPnP, n\'importe quel appareil ou programme du réseau local peut ouvrir un port de votre box Internet sans vous le demander. Le plugin interroge la box pour lister ces ouvertures, en particulier celles qui pointent vers Jeedom. Les redirections créées à la main dans la box ne sont pas visibles par ce contrôle.', __FILE__),
        'recommendation' => __('Supprimez les redirections vers Jeedom (utilisez le DNS Jeedom ou un VPN), puis désactivez UPnP dans la box Internet si aucun appareil n\'en a besoin.', __FILE__),
        'fix' => null,
      ),
      'shodan_exposure' => array(
        'category' => 'exposure',
        'severity' => 'high',
        'title' => __('Exposition vue depuis Internet (Shodan)', __FILE__),
        'description' => __('Shodan scanne Internet en permanence. Sa base InternetDB indique, pour votre adresse IP publique, les ports vus ouverts et les failles connues des services détectés. C\'est ce que voit n\'importe quel attaquant. InternetDB ne date pas ses observations : elles peuvent avoir plusieurs semaines, voire plusieurs mois. Les failles sont déduites de la version annoncée par chaque service, sans être vérifiées. Ces informations concernent toute la connexion (box Internet et autres appareils compris).', __FILE__),
        'recommendation' => __('Vérifiez d\'abord depuis l\'extérieur que ces ports sont toujours ouverts, par exemple depuis un téléphone en 4G/5G (Wi-Fi coupé) ou avec un service de test de ports en ligne. S\'ils le sont, fermez dans la box Internet les redirections de ports inutiles et mettez à jour les services signalés comme vulnérables. S\'ils sont fermés, l\'alerte disparaîtra quand Shodan aura de nouveau scanné l\'adresse.', __FILE__),
        'fix' => $linkPluginConfig,
      ),
      'dnsbl' => array(
        'category' => 'exposure',
        'severity' => 'medium',
        'title' => __('Adresse IP sur des listes noires', __FILE__),
        'description' => __('Les listes noires (Spamhaus, Barracuda, SpamCop) recensent les adresses qui envoient du spam ou font partie d\'un réseau de machines piratées. Y figurer peut signaler un appareil compromis chez vous. Les plages d\'adresses grand public (liste PBL de Spamhaus) ne sont pas comptées comme un problème.', __FILE__),
        'recommendation' => __('Recherchez l\'appareil compromis (ordinateur, caméra, objet connecté), nettoyez-le, puis demandez le retrait de l\'adresse sur le site de la liste noire.', __FILE__),
        'fix' => $linkPluginConfig,
      ),
      'tls_certificate' => array(
        'category' => 'exposure',
        'severity' => 'high',
        'title' => __('Certificat HTTPS de l\'accès externe', __FILE__),
        'description' => __('Un certificat expiré, auto-signé ou émis pour un autre nom fait afficher une alerte au navigateur et habitue à l\'ignorer, ce qui ouvre la porte aux interceptions.', __FILE__),
        'recommendation' => __('Utilisez un certificat reconnu (Let\'s Encrypt) et vérifiez que son renouvellement automatique fonctionne.', __FILE__),
        'fix' => $linkNetwork,
      ),

      /* ------------------------------- API ------------------------------- */
      'api_modes' => array(
        'category' => 'api',
        'severity' => 'medium',
        'title' => __('API ouvertes depuis Internet', __FILE__),
        'description' => __('En mode « Activé », une API répond depuis n\'importe quelle adresse, y compris Internet quand Jeedom y est exposé. Le mode « IP blanche » la réserve aux adresses de confiance (votre réseau local).', __FILE__),
        'recommendation' => __('Passez les API en mode « IP blanche » (ou « Désactivé » si vous ne les utilisez pas).', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Passer en mode IP blanche', __FILE__), 'confirm' => __('Les API listées n\'accepteront plus que les adresses de la liste blanche. Les services qui les appellent depuis Internet (webhooks, IFTTT, applications hors du réseau local...) ne fonctionneront plus.', __FILE__)),
      ),
      'api_key_strength' => array(
        'category' => 'api',
        'severity' => 'medium',
        'title' => __('Robustesse des clés API', __FILE__),
        'description' => __('Une clé API courte peut être devinée. Jeedom génère des clés de 64 caractères ; une clé plus courte a été saisie à la main.', __FILE__),
        'recommendation' => __('Régénérez les clés API trop courtes.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Régénérer les clés trop courtes', __FILE__), 'confirm' => __('De nouvelles clés vont être générées. Tous les services qui utilisent les anciennes clés devront être reconfigurés.', __FILE__)),
      ),

      /* ----------------------------- Jeedom ------------------------------ */
      'core_update' => array(
        'category' => 'jeedom',
        'severity' => 'medium',
        'title' => __('Version de Jeedom', __FILE__),
        'description' => __('Les mises à jour du core corrigent régulièrement des failles de sécurité.', __FILE__),
        'recommendation' => __('Faites une sauvegarde puis mettez Jeedom à jour.', __FILE__),
        'fix' => $linkUpdate,
      ),
      'plugins_update' => array(
        'category' => 'jeedom',
        'severity' => 'low',
        'title' => __('Plugins à mettre à jour', __FILE__),
        'description' => __('Un plugin obsolète peut contenir une faille corrigée depuis.', __FILE__),
        'recommendation' => __('Mettez à jour les plugins depuis le centre de mises à jour.', __FILE__),
        'fix' => $linkUpdate,
      ),
      'plugins_sources' => array(
        'category' => 'jeedom',
        'severity' => 'info',
        'title' => __('Plugins installés hors Market', __FILE__),
        'description' => __('Un plugin installé depuis GitHub, une URL ou un fichier n\'a pas été vérifié par le Market Jeedom et s\'exécute avec tous les droits de Jeedom.', __FILE__),
        'recommendation' => __('N\'installez hors Market que des plugins dont vous connaissez l\'auteur.', __FILE__),
        'fix' => $linkUpdate,
      ),
      'debug_logs' => array(
        'category' => 'jeedom',
        'severity' => 'medium',
        'title' => __('Logs en mode Debug', __FILE__),
        'description' => __('En Debug, les logs peuvent contenir des mots de passe, clés API ou jetons, et grossissent jusqu\'à saturer le disque.', __FILE__),
        'recommendation' => __('N\'activez le niveau Debug que le temps d\'un diagnostic.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Remettre les niveaux par défaut', __FILE__), 'confirm' => __('Les logs listés repasseront au niveau par défaut de Jeedom (Erreur pour le niveau global).', __FILE__)),
      ),

      /* ---------------------------- Serveur web --------------------------- */
      'http_sensitive_files' => array(
        'category' => 'web',
        'severity' => 'critical',
        'title' => __('Fichiers sensibles accessibles depuis le navigateur', __FILE__),
        'description' => __('Les dossiers log, backup et core/config ne doivent jamais être téléchargeables : les sauvegardes contiennent la base de données complète (mots de passe, clés API). Le plugin dépose un fichier témoin et vérifie qu\'Apache refuse de le servir.', __FILE__),
        'recommendation' => __('Vérifiez qu\'Apache prend en compte les fichiers .htaccess de Jeedom (AllowOverride All sur /var/www/html).', __FILE__),
        'fix' => $fixApache,
      ),
      'http_headers' => array(
        'category' => 'web',
        'severity' => 'low',
        'title' => __('En-têtes de sécurité HTTP', __FILE__),
        'description' => __('Les en-têtes X-Frame-Options et X-Content-Type-Options protègent contre l\'intégration de Jeedom dans une page piégée (clickjacking) et certaines injections.', __FILE__),
        'recommendation' => __('Utilisez la configuration Apache de sécurité fournie par Jeedom. Ce contrôle interroge Apache en local : si un reverse proxy ajoute ces en-têtes devant Jeedom, vous pouvez l\'ignorer.', __FILE__),
        'fix' => $fixApache,
      ),
      'server_tokens' => array(
        'category' => 'web',
        'severity' => 'low',
        'title' => __('Versions exposées par le serveur web', __FILE__),
        'description' => __('Les en-têtes Server et X-Powered-By donnent les versions exactes d\'Apache et PHP, ce qui aide un attaquant à cibler les failles connues.', __FILE__),
        'recommendation' => __('Masquez les versions (ServerTokens Prod, suppression de X-Powered-By). Ce contrôle interroge Apache en local : si un reverse proxy masque ces en-têtes devant Jeedom, vous pouvez l\'ignorer.', __FILE__),
        'fix' => $fixApache,
      ),
      'php_eol' => array(
        'category' => 'web',
        'severity' => 'high',
        'title' => __('Version de PHP', __FILE__),
        'description' => __('Une version de PHP en fin de support ne reçoit plus de correctifs de sécurité. Le PHP fourni par Debian reste corrigé par Debian tant que la version de Debian est supportée, même après la fin de support officielle de PHP.', __FILE__),
        'recommendation' => __('Mettez à jour le système d\'exploitation pour obtenir une version de PHP supportée.', __FILE__),
        'fix' => null,
      ),

      /* ------------------------------ Système ----------------------------- */
      'os_eol' => array(
        'category' => 'system',
        'severity' => 'high',
        'title' => __('Version du système d\'exploitation', __FILE__),
        'description' => __('Une version de Debian en fin de support ne reçoit plus de correctifs de sécurité (noyau, OpenSSL, Apache, SSH...).', __FILE__),
        'recommendation' => __('Migrez vers une version de Debian supportée (en suivant la documentation Jeedom, après une sauvegarde).', __FILE__),
        'fix' => null,
      ),
      'system_passwords' => array(
        'category' => 'system',
        'severity' => 'critical',
        'title' => __('Mots de passe système par défaut', __FILE__),
        'description' => __('Les images Jeedom et Raspberry Pi sont livrées avec des mots de passe connus de tous (Mjeedom96, raspberry...). Le plugin les compare, sans se connecter, aux comptes root, jeedom, pi et aux comptes utilisateurs du système.', __FILE__),
        'recommendation' => __('Connectez-vous en SSH et changez le mot de passe de chaque compte listé avec la commande passwd.', __FILE__),
        'fix' => null,
      ),
      'ssh_root' => array(
        'category' => 'system',
        'severity' => 'high',
        'title' => __('Connexion SSH en root par mot de passe', __FILE__),
        'description' => __('Autoriser root à se connecter en SSH avec un mot de passe expose directement le compte le plus puissant aux attaques par force brute.', __FILE__),
        'recommendation' => __('Interdisez la connexion root par mot de passe (PermitRootLogin prohibit-password) et utilisez un compte normal avec sudo, ou une clé SSH.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Interdire root par mot de passe', __FILE__), 'confirm' => __('root ne pourra plus se connecter en SSH avec un mot de passe (les clés SSH restent acceptées). Vérifiez AVANT d\'avoir un autre compte capable de se connecter en SSH et d\'utiliser sudo, sinon vous perdrez l\'accès SSH root. Les sessions ouvertes ne sont pas coupées.', __FILE__)),
      ),
      'ssh_password_auth' => array(
        'category' => 'system',
        'severity' => 'low',
        'title' => __('Authentification SSH par mot de passe', __FILE__),
        'description' => __('Les clés SSH sont bien plus robustes que les mots de passe face aux attaques par force brute.', __FILE__),
        'recommendation' => __('Si vous utilisez SSH régulièrement, passez aux clés SSH puis désactivez PasswordAuthentication.', __FILE__),
        'fix' => null,
      ),
      'ntp' => array(
        'category' => 'system',
        'severity' => 'low',
        'title' => __('Synchronisation de l\'heure', __FILE__),
        'description' => __('Une horloge décalée fait échouer la double authentification et la vérification des certificats HTTPS, et fausse les journaux.', __FILE__),
        'recommendation' => __('Activez la synchronisation NTP.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Activer la synchronisation NTP', __FILE__), 'confirm' => __('La commande timedatectl set-ntp true va être exécutée.', __FILE__)),
      ),
      'apt_security_updates' => array(
        'category' => 'system',
        'severity' => 'medium',
        'title' => __('Mises à jour de sécurité du système', __FILE__),
        'description' => __('Les paquets Debian reçoivent des correctifs de sécurité qu\'il faut installer.', __FILE__),
        'recommendation' => __('Faites une sauvegarde puis lancez la mise à jour du système (sudo apt update && sudo apt upgrade), ou celle proposée par Jeedom.', __FILE__),
        'fix' => $linkUpdate,
      ),
      'reboot_required' => array(
        'category' => 'system',
        'severity' => 'low',
        'title' => __('Redémarrage en attente', __FILE__),
        'description' => __('Certaines mises à jour (noyau, bibliothèques système) ne s\'appliquent qu\'après un redémarrage : en attendant, l\'ancienne version vulnérable reste en mémoire.', __FILE__),
        'recommendation' => __('Redémarrez la box à un moment opportun (Réglages > Système > Redémarrer).', __FILE__),
        'fix' => null,
      ),
      'config_perms' => array(
        'category' => 'system',
        'severity' => 'medium',
        'title' => __('Droits du fichier de configuration', __FILE__),
        'description' => __('Le fichier core/config/common.config.php contient le mot de passe de la base de données. Il ne doit pas être lisible par tous les comptes du système.', __FILE__),
        'recommendation' => __('Restreignez ses droits en lecture au serveur web (640).', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Restreindre les droits (640)', __FILE__), 'confirm' => __('Le fichier ne sera plus lisible que par le serveur web.', __FILE__)),
      ),
      'sensitive_dirs_perms' => array(
        'category' => 'system',
        'severity' => 'medium',
        'title' => __('Dossiers sensibles lisibles par tous', __FILE__),
        'description' => __('Les dossiers backup (sauvegardes contenant toute la base de données), log (mots de passe et jetons en mode Debug) et core/config ne doivent être accessibles qu\'au serveur web, pas aux autres comptes du système.', __FILE__),
        'recommendation' => __('Retirez l\'accès « autres » à ces dossiers (chmod o-rwx). Le serveur web y garde accès.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Retirer l\'accès aux autres comptes', __FILE__), 'confirm' => __('L\'accès « autres » va être retiré aux dossiers listés (chmod o-rwx). Les fichiers qu\'ils contiennent, y compris les prochaines sauvegardes, ne seront plus accessibles aux autres comptes du système.', __FILE__)),
      ),
      'suid_files' => array(
        'category' => 'system',
        'severity' => 'high',
        'title' => __('Fichiers SUID/SGID dans Jeedom', __FILE__),
        'description' => __('Un fichier SUID ou SGID s\'exécute avec les droits de son propriétaire, souvent root. Jeedom et ses plugins n\'en ont jamais besoin : leur présence est un signe classique de compromission ou d\'une erreur grave.', __FILE__),
        'recommendation' => __('Identifiez l\'origine des fichiers listés. En cas de doute, considérez la box comme compromise : restaurez une sauvegarde saine sur un système réinstallé et changez tous les mots de passe.', __FILE__),
        'fix' => null,
      ),
      'world_writable' => array(
        'category' => 'system',
        'severity' => 'medium',
        'title' => __('Fichiers modifiables par tous', __FILE__),
        'description' => __('Un fichier de Jeedom modifiable par n\'importe quel compte du système permet à un programme compromis d\'y injecter du code.', __FILE__),
        'recommendation' => __('Retirez le droit d\'écriture « autres » (chmod o-w).', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Retirer l\'écriture pour tous', __FILE__), 'confirm' => __('Le droit d\'écriture « autres » va être retiré sur tous les fichiers de Jeedom (chmod -R o-w).', __FILE__)),
      ),
      'sudo_www' => array(
        'category' => 'system',
        'severity' => 'info',
        'title' => __('Droits sudo du serveur web', __FILE__),
        'description' => __('Jeedom a besoin que le serveur web (www-data) puisse lancer des commandes en root. En conséquence, une faille dans Jeedom ou un plugin donne le contrôle total du système : d\'où l\'importance des autres points de cet audit.', __FILE__),
        'recommendation' => __('Rien à corriger : c\'est nécessaire au fonctionnement de Jeedom. Limitez l\'exposition de l\'interface et n\'installez que des plugins de confiance.', __FILE__),
        'fix' => null,
      ),

      /* ------------------------------ Réseau ------------------------------ */
      'firewall' => array(
        'category' => 'network',
        'severity' => 'medium',
        'title' => __('Pare-feu', __FILE__),
        'description' => __('Un pare-feu limite les services joignables depuis le réseau, par exemple en réservant SSH et la base de données au réseau local.', __FILE__),
        'recommendation' => __('Configurez un pare-feu (ufw ou nftables) qui n\'ouvre que les ports utiles. Attention à ne pas bloquer votre propre accès SSH.', __FILE__),
        'fix' => null,
      ),
      'fail2ban' => array(
        'category' => 'network',
        'severity' => 'medium',
        'title' => __('Fail2ban', __FILE__),
        'description' => __('Fail2ban bannit automatiquement les adresses qui multiplient les tentatives de connexion SSH ou les requêtes suspectes sur Apache.', __FILE__),
        'recommendation' => __('Installez et activez fail2ban, indispensable si un port de la box Internet est redirigé vers Jeedom. Sans exposition détectée, ce contrôle est une simple information.', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Installer et activer fail2ban', __FILE__), 'confirm' => __('fail2ban va être installé en tâche de fond (apt), avec la protection SSH et les règles Apache fournies par Jeedom. Votre réseau local n\'est jamais banni. Suivez l\'avancement dans le log auditsecurity, puis relancez l\'audit.', __FILE__)),
      ),
      'mysql_exposed' => array(
        'category' => 'network',
        'severity' => 'high',
        'title' => __('Base de données accessible depuis le réseau', __FILE__),
        'description' => __('La base de données de Jeedom n\'a besoin d\'être joignable que localement. Ouverte sur le réseau, elle est exposée aux attaques par force brute.', __FILE__),
        'recommendation' => __('Limitez MariaDB à la boucle locale (bind-address = 127.0.0.1) si aucun autre appareil ne s\'y connecte.', __FILE__),
        'fix' => null,
      ),
      'db_credentials' => array(
        'category' => 'network',
        'severity' => 'medium',
        'title' => __('Identifiants de la base de données', __FILE__),
        'description' => __('Jeedom doit utiliser un compte dédié avec un mot de passe long, pas le compte root de la base.', __FILE__),
        'recommendation' => __('Créez un utilisateur dédié à Jeedom avec un mot de passe aléatoire d\'au moins 12 caractères.', __FILE__),
        'fix' => null,
      ),
      'mosquitto' => array(
        'category' => 'network',
        'severity' => 'high',
        'title' => __('Broker MQTT sans authentification', __FILE__),
        'description' => __('Un broker MQTT ouvert sans mot de passe permet à n\'importe quel appareil du réseau de lire et de piloter vos équipements (Zigbee2MQTT, Tasmota, Shelly...). Le plugin tente une connexion anonyme sur l\'adresse réseau du broker, puis se déconnecte aussitôt sans rien lire ni publier.', __FILE__),
        'recommendation' => __('Désactivez allow_anonymous et définissez un password_file (le plugin MQTT Manager le fait automatiquement). Si l\'accès au port MQTT est déjà restreint par un pare-feu, vous pouvez ignorer ce contrôle (risque accepté avec mesure compensatoire).', __FILE__),
        'fix' => null,
      ),
      'dangerous_services' => array(
        'category' => 'network',
        'severity' => 'high',
        'title' => __('Services dangereux à l\'écoute', __FILE__),
        'description' => __('Certains services sont dangereux sur un réseau : Telnet et FTP transmettent les mots de passe en clair, l\'API Docker non chiffrée donne le contrôle root de la machine, VNC, Redis ou MongoDB sont souvent sans mot de passe.', __FILE__),
        'recommendation' => __('Arrêtez et désinstallez ces services, ou limitez-les à la boucle locale (127.0.0.1). Utilisez SSH à la place de Telnet et FTP.', __FILE__),
        'fix' => null,
      ),
      'exposed_ports' => array(
        'category' => 'network',
        'severity' => 'info',
        'title' => __('Services à l\'écoute sur le réseau', __FILE__),
        'description' => __('Liste des services joignables depuis le réseau local. Chacun est une porte d\'entrée potentielle : vérifiez qu\'ils sont tous utiles.', __FILE__),
        'recommendation' => __('Arrêtez les services inutiles et ne redirigez sur votre box Internet que les ports indispensables (idéalement aucun, avec le DNS Jeedom ou un VPN).', __FILE__),
        'fix' => null,
      ),

      /* ---------------------------- Résilience ---------------------------- */
      'backup_recent' => array(
        'category' => 'resilience',
        'severity' => 'high',
        'title' => __('Sauvegarde récente', __FILE__),
        'description' => __('Une sauvegarde récente permet de repartir rapidement après une panne, une erreur ou une compromission.', __FILE__),
        'recommendation' => __('Gardez la sauvegarde automatique de Jeedom active (quotidienne).', __FILE__),
        'fix' => array('type' => 'auto', 'label' => __('Lancer une sauvegarde', __FILE__), 'confirm' => __('Une sauvegarde complète va être lancée en tâche de fond.', __FILE__)),
      ),
      'backup_offsite' => array(
        'category' => 'resilience',
        'severity' => 'medium',
        'title' => __('Sauvegarde hors de la box', __FILE__),
        'description' => __('Une sauvegarde stockée uniquement sur la box disparaît avec elle (carte SD morte, rançongiciel, vol).', __FILE__),
        'recommendation' => __('Activez l\'envoi des sauvegardes vers le cloud Jeedom (Market) ou un partage réseau (Samba).', __FILE__),
        'fix' => $linkBackup,
      ),
      'disk_space' => array(
        'category' => 'resilience',
        'severity' => 'low',
        'title' => __('Espace disque', __FILE__),
        'description' => __('Un disque plein empêche les sauvegardes, les logs et peut corrompre la base de données.', __FILE__),
        'recommendation' => __('Libérez de l\'espace (anciennes sauvegardes, logs) ou passez sur un support plus grand.', __FILE__),
        'fix' => $linkLogs,
      ),
    );
  }

  /* ************************************************************************************ */
  /*                                   Exécution                                          */
  /* ************************************************************************************ */

  /** Lance un contrôle et retourne son résultat brut {status, detail, items}. */
  public static function run($_id) {
    $method = 'check_' . $_id;
    if (!method_exists(__CLASS__, $method)) {
      return self::skip(__('Contrôle inconnu', __FILE__));
    }
    try {
      $result = self::$method();
    } catch (Throwable $e) {
      log::add('auditsecurity', 'error', 'Contrôle ' . $_id . ' : ' . $e->getMessage());
      return self::skip(__('Erreur pendant le contrôle :', __FILE__) . ' ' . $e->getMessage());
    }
    return $result;
  }

  /** Vrai si le contrôle dispose d'une correction automatique. */
  public static function hasAutoFix($_id) {
    return method_exists(__CLASS__, 'fix_' . $_id);
  }

  /** Applique la correction automatique d'un contrôle. Retourne un message. */
  public static function fix($_id) {
    $method = 'fix_' . $_id;
    if (!method_exists(__CLASS__, $method)) {
      throw new Exception(__('Aucune correction automatique pour ce contrôle', __FILE__));
    }
    log::add('auditsecurity', 'info', 'Correction demandée : ' . $_id);
    $message = self::$method();
    log::add('auditsecurity', 'info', 'Correction ' . $_id . ' : ' . $message);
    return $message;
  }

  private static function result($_status, $_detail, $_items = array(), $_extra = array()) {
    return array_merge(array('status' => $_status, 'detail' => $_detail, 'items' => array_values($_items)), $_extra);
  }

  private static function pass($_detail, $_items = array()) {
    return self::result('pass', $_detail, $_items);
  }

  private static function warn($_detail, $_items = array()) {
    return self::result('warn', $_detail, $_items);
  }

  private static function fail($_detail, $_items = array()) {
    return self::result('fail', $_detail, $_items);
  }

  private static function info($_detail, $_items = array()) {
    return self::result('info', $_detail, $_items);
  }

  private static function skip($_detail) {
    return self::result('skip', $_detail);
  }

  /** Résultat sans correction automatique possible (ex. sudo absent), même si le contrôle en propose une. */
  private static function noFix($_result) {
    $_result['noFix'] = true;
    return $_result;
  }

  /* ************************************************************************************ */
  /*                                   Utilitaires                                        */
  /* ************************************************************************************ */

  /** Vrai si le mot de passe en clair correspond à celui du compte (sans se connecter, sans journaliser). */
  private static function passwordMatches($_user, $_password) {
    $stored = (string) $_user->getPassword();
    if ($stored === '') {
      return false;
    }
    $algo = password_get_info($stored)['algo'];
    if ($algo !== null && $algo !== 0) {
      return password_verify($_password, $stored);
    }
    return hash_equals($stored, hash('sha512', $_password)) || hash_equals($stored, sha1($_password));
  }

  /** Comptes Jeedom actifs, hors comptes techniques du core. */
  private static function activeUsers() {
    $users = array();
    foreach (user::all() as $user) {
      if ($user->getEnable() == 1 && !in_array($user->getLogin(), self::$technicalUsers)) {
        $users[] = $user;
      }
    }
    return $users;
  }

  /** Description de l'accès externe à Jeedom, ou '' s'il n'y en a pas. */
  private static function externalAccess() {
    $access = array();
    if (config::byKey('market::allowDNS') == 1) {
      $access[] = __('DNS Jeedom', __FILE__);
    }
    if (trim(config::byKey('externalAddr')) != '') {
      $access[] = config::byKey('externalProtocol') . config::byKey('externalAddr');
    }
    // Interface web de Jeedom redirigée par UPnP sur la box Internet
    $webPorts = array(80, 443, intval(config::byKey('internalPort', 'core', 80)));
    foreach (self::jeedomUpnpMappings() as $mapping) {
      if (in_array($mapping['internal'], $webPorts)) {
        $access[] = sprintf(__('port %d redirigé par UPnP', __FILE__), $mapping['external']);
      }
    }
    return implode(', ', array_unique($access));
  }

  /** Redirections UPnP de la box Internet qui pointent vers la box Jeedom. */
  private static function jeedomUpnpMappings() {
    $localIps = auditsecurityTools::localIps();
    $result = array();
    foreach (auditsecurityTools::upnpMappings() as $mapping) {
      if (in_array($mapping['client'], $localIps)) {
        $result[] = $mapping;
      }
    }
    return $result;
  }

  /** Vrai si l'utilisateur a autorisé les tests qui contactent des services externes. */
  private static function externalChecksAllowed() {
    return config::byKey('externalChecks', 'auditsecurity', 0) == 1;
  }

  /** Résultat brut de Shodan InternetDB pour l'IP publique (mis en cache pour l'audit), ou null. */
  private static function shodanData() {
    static $data = false;
    if ($data !== false) {
      return $data;
    }
    $data = null;
    if (!self::externalChecksAllowed()) {
      return null;
    }
    $public = auditsecurityTools::publicIp(true);
    if ($public === null || auditsecurityTools::isNonPublicIp($public['ip'])) {
      return null;
    }
    $res = auditsecurityTools::httpGetExternal('https://internetdb.shodan.io/' . $public['ip']);
    if ($res === null) {
      return null;
    }
    if ($res['code'] == 404) {
      $data = array('ip' => $public['ip'], 'ports' => array(), 'vulns' => array(), 'tags' => array(), 'hostnames' => array());
    } elseif ($res['code'] == 200) {
      $json = json_decode($res['body'], true);
      if (is_array($json)) {
        $data = array_merge(array('ports' => array(), 'vulns' => array(), 'tags' => array(), 'hostnames' => array()), $json, array('ip' => $public['ip']));
      }
    }
    return $data;
  }

  /** Horodatage du premier audit où Shodan a renvoyé ce même résultat (adresse, ports, failles). */
  private static function shodanSince($_data) {
    $ports = array_map('intval', $_data['ports']);
    $vulns = $_data['vulns'];
    sort($ports);
    sort($vulns);
    $signature = md5(json_encode(array($_data['ip'], $ports, $vulns)));
    $snapshot = config::byKey('shodanSnapshot', 'auditsecurity', array());
    if (!is_array($snapshot) || !isset($snapshot['signature'], $snapshot['since']) || $snapshot['signature'] !== $signature) {
      $snapshot = array('signature' => $signature, 'since' => time());
      config::save('shodanSnapshot', $snapshot, 'auditsecurity');
    }
    return (int) $snapshot['since'];
  }

  /** Raisons de penser que Jeedom est exposé sur Internet (liste vide si aucune). */
  private static function exposureReasons() {
    $reasons = array();
    // Accès déclarés dans Jeedom (les redirections UPnP sont détaillées juste après)
    if (config::byKey('market::allowDNS') == 1) {
      $reasons[] = __('DNS Jeedom', __FILE__);
    }
    if (trim(config::byKey('externalAddr')) != '') {
      $reasons[] = config::byKey('externalProtocol') . config::byKey('externalAddr');
    }
    foreach (self::jeedomUpnpMappings() as $mapping) {
      $reasons[] = sprintf(__('port %d redirigé par UPnP vers le port %d de Jeedom', __FILE__), $mapping['external'], $mapping['internal']);
    }
    $shodan = self::shodanData();
    if ($shodan !== null && count($shodan['ports']) > 0) {
      $reasons[] = sprintf(__('ports vus ouverts par Shodan : %s', __FILE__), implode(', ', $shodan['ports']));
    }
    return array_values(array_unique($reasons));
  }

  private static function profileName($_profile) {
    $names = array('admin' => __('Administrateur', __FILE__), 'user' => __('Utilisateur', __FILE__), 'restrict' => __('Utilisateur limité', __FILE__));
    return isset($names[$_profile]) ? $names[$_profile] : $_profile;
  }

  /** Configuration SSH effective (clés en minuscules), ou null si sshd est absent. */
  private static function sshConfig() {
    if (!auditsecurityTools::hasBinary('sshd')) {
      return null;
    }
    $config = array();
    $output = '';
    if (auditsecurityTools::canRoot()) {
      $res = auditsecurityTools::execRoot('sshd -T', 10);
      if ($res['code'] === 0) {
        $output = $res['output'];
      }
    }
    if ($output === '') {
      // Repli : lecture du fichier principal (le premier réglage rencontré l'emporte, comme pour sshd)
      $output = (string) auditsecurityTools::readFile('/etc/ssh/sshd_config');
    }
    foreach (explode("\n", $output) as $line) {
      $line = trim($line);
      if ($line === '' || $line[0] === '#') {
        continue;
      }
      if (stripos($line, 'match ') === 0) {
        break;
      }
      $parts = preg_split('/\s+/', $line, 2);
      $key = strtolower($parts[0]);
      if (!isset($config[$key])) {
        $config[$key] = isset($parts[1]) ? strtolower(trim($parts[1])) : '';
      }
    }
    return $config;
  }

  /** Vrai si le serveur SSH écoute (service ou activation par socket), ou si on ne peut pas le savoir. */
  private static function sshListening($_ssh) {
    $ports = auditsecurityTools::listeningPorts();
    if (count($ports) == 0) {
      return true;
    }
    $sshPort = isset($_ssh['port']) ? intval($_ssh['port']) : 22;
    foreach ($ports as $port) {
      if ($port['port'] == $sshPort) {
        return true;
      }
    }
    return false;
  }

  /** Signes que le port SSH est joignable depuis Internet (redirection UPnP, port vu par Shodan). */
  private static function sshExposure($_sshPort) {
    $reasons = array();
    foreach (self::jeedomUpnpMappings() as $mapping) {
      if ($mapping['internal'] == $_sshPort) {
        $reasons[] = sprintf(__('port %d redirigé par UPnP vers le port %d de Jeedom', __FILE__), $mapping['external'], $mapping['internal']);
      }
    }
    $shodan = self::shodanData();
    if ($shodan !== null && in_array($_sshPort, array_map('intval', $shodan['ports']))) {
      $reasons[] = sprintf(__('ports vus ouverts par Shodan : %s', __FILE__), $_sshPort);
    }
    return $reasons;
  }

  /** Version d'une fin de support : {status, detail} selon la date de fin de support. */
  private static function eolStatus($_label, $_eol) {
    if ($_eol === null) {
      return self::info(sprintf(__('%s : date de fin de support inconnue du plugin.', __FILE__), $_label));
    }
    $now = time();
    $end = strtotime($_eol);
    if ($end < $now) {
      return self::fail(sprintf(__('%s n\'est plus supporté depuis le %s.', __FILE__), $_label, date('d/m/Y', $end)));
    }
    if ($end - $now < 180 * 86400) {
      return self::warn(sprintf(__('%s ne sera plus supporté à partir du %s : prévoyez la migration.', __FILE__), $_label, date('d/m/Y', $end)));
    }
    return self::pass(sprintf(__('%s est supporté jusqu\'au %s.', __FILE__), $_label, date('d/m/Y', $end)));
  }

  /* ************************************************************************************ */
  /*                                   Contrôles                                          */
  /* ************************************************************************************ */

  /* ----------------------------- Comptes ----------------------------- */

  private static function check_default_admin() {
    if (config::byKey('ldap:enable') == '1') {
      return self::skip(__('Authentification LDAP active : les mots de passe sont gérés par l\'annuaire.', __FILE__));
    }
    $user = user::byLogin('admin');
    if (!is_object($user) || $user->getEnable() == 0) {
      return self::pass(__('Aucun compte « admin » actif.', __FILE__));
    }
    if (self::passwordMatches($user, 'admin')) {
      return self::fail(__('Le compte « admin » utilise le mot de passe « admin ».', __FILE__));
    }
    return self::pass(__('Le compte « admin » n\'utilise pas le mot de passe par défaut.', __FILE__));
  }

  private static function check_weak_passwords() {
    if (config::byKey('ldap:enable') == '1') {
      return self::skip(__('Authentification LDAP active : les mots de passe sont gérés par l\'annuaire.', __FILE__));
    }
    $weak = array();
    $users = self::activeUsers();
    foreach ($users as $user) {
      $login = $user->getLogin();
      $candidates = array_unique(array_merge(array($login, strtolower($login)), self::$commonPasswords));
      foreach ($candidates as $candidate) {
        // admin / admin est déjà signalé par le contrôle dédié
        if ($login === 'admin' && $candidate === 'admin') {
          continue;
        }
        if (self::passwordMatches($user, $candidate)) {
          $weak[] = $login . ' (' . self::profileName($user->getProfils()) . ')';
          break;
        }
      }
    }
    if (count($weak) > 0) {
      return self::fail(sprintf(__('%d compte(s) avec un mot de passe trop courant.', __FILE__), count($weak)), $weak);
    }
    return self::pass(sprintf(__('Aucun des %d compte(s) actif(s) n\'utilise un mot de passe de la liste testée.', __FILE__), count($users)));
  }

  private static function check_support_access() {
    $user = user::byLogin('jeedom_support');
    if (is_object($user) && $user->getEnable() == 1) {
      return self::warn(__('Le compte jeedom_support est actif.', __FILE__));
    }
    return self::pass(__('L\'accès support est fermé.', __FILE__));
  }

  private static function fix_support_access() {
    user::supportAccess(false);
    return __('Accès support fermé.', __FILE__);
  }

  private static function check_twofa() {
    $admins = array();
    $users = array();
    foreach (self::activeUsers() as $user) {
      if ($user->getOptions('twoFactorAuthentification', 0) == 1 && $user->getOptions('twoFactorAuthentificationSecret') != '') {
        continue;
      }
      if ($user->getProfils() == 'admin') {
        $admins[] = $user->getLogin() . ' (' . self::profileName('admin') . ')';
      } else {
        $users[] = $user->getLogin() . ' (' . self::profileName($user->getProfils()) . ')';
      }
    }
    $missing = array_merge($admins, $users);
    if (count($missing) == 0) {
      return self::pass(__('Tous les comptes actifs ont la double authentification.', __FILE__));
    }
    $external = self::externalAccess();
    if ($external == '') {
      return self::info(__('Aucun accès externe n\'est configuré : Jeedom ne demande la double authentification qu\'aux connexions depuis l\'extérieur. À activer si vous ouvrez l\'accès externe.', __FILE__), $missing);
    }
    if (count($admins) > 0) {
      return self::fail(sprintf(__('Jeedom est accessible depuis Internet (%s) et %d administrateur(s) n\'ont pas la double authentification.', __FILE__), $external, count($admins)), $missing);
    }
    return self::warn(sprintf(__('Jeedom est accessible depuis Internet (%s) et %d compte(s) non administrateur(s) n\'ont pas la double authentification.', __FILE__), $external, count($users)), $missing);
  }

  private static function check_admin_count() {
    $admins = array();
    foreach (self::activeUsers() as $user) {
      if ($user->getProfils() == 'admin') {
        $admins[] = $user->getLogin();
      }
    }
    if (count($admins) > 3) {
      return self::warn(sprintf(__('%d comptes administrateurs actifs.', __FILE__), count($admins)), $admins);
    }
    return self::pass(sprintf(__('%d compte(s) administrateur(s) actif(s).', __FILE__), count($admins)), $admins);
  }

  private static function check_inactive_users() {
    $limit = strtotime('-180 days');
    $inactive = array();
    foreach (self::activeUsers() as $user) {
      $last = $user->getOptions('lastConnection', '');
      if ($last == '') {
        $inactive[] = $user->getLogin() . ' (' . __('aucune connexion enregistrée par l\'interface', __FILE__) . ')';
      } elseif (strtotime($last) < $limit) {
        $inactive[] = $user->getLogin() . ' (' . sprintf(__('dernière connexion le %s', __FILE__), date('d/m/Y', strtotime($last))) . ')';
      }
    }
    if (count($inactive) > 0) {
      return self::warn(sprintf(__('%d compte(s) actif(s) sans connexion depuis plus de 6 mois.', __FILE__), count($inactive)), $inactive);
    }
    return self::pass(__('Tous les comptes actifs ont été utilisés ces 6 derniers mois.', __FILE__));
  }

  /* ------------------------------ Accès ------------------------------ */

  private static function check_bruteforce() {
    $max = intval(config::byKey('security::maxFailedLogin'));
    $window = intval(config::byKey('security::timeLoginFailed'));
    $ban = intval(config::byKey('security::bantime'));
    $detail = sprintf(__('%d échec(s) autorisé(s) sur %d s, bannissement de %s.', __FILE__), $max, $window, ($ban == -1) ? __('durée illimitée', __FILE__) : $ban . ' s');
    if ($max <= 0 || $ban == 0 || $window <= 0) {
      return self::fail(__('Protection désactivée :', __FILE__) . ' ' . $detail);
    }
    if ($max > 10 || ($ban > 0 && $ban < 300)) {
      return self::warn(__('Protection trop permissive :', __FILE__) . ' ' . $detail);
    }
    return self::pass($detail);
  }

  private static function fix_bruteforce() {
    config::save('security::maxFailedLogin', 6);
    config::save('security::timeLoginFailed', 300);
    if (intval(config::byKey('security::bantime')) != -1) {
      config::save('security::bantime', 600);
    }
    return __('Protection contre la force brute configurée.', __FILE__);
  }

  /** Vrai si une entrée de liste blanche couvre tout Internet. */
  private static function isWildcardIp($_entry) {
    $entry = trim($_entry);
    return ($entry === '*' || preg_match('/^\*(\.\*){1,3}$/', $entry) || preg_match('#^(0\.0\.0\.0|::)/0$#', $entry));
  }

  /** Plages IPv4 privées ou locales (jamais joignables depuis Internet) */
  private static $privateRanges = array('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16');

  /**
   * Plage couverte par une entrée de liste blanche, avec les mêmes règles que netMatch() du core
   * (192.168.1.* = /24, 172.*.*.* = /8, notation CIDR, IP seule).
   * @return array|null [début, fin] en entiers, ou null si l'entrée n'est pas analysable (IPv6, plage a-b...)
   */
  private static function ipRange($_entry) {
    $entry = str_replace(' ', '', $_entry);
    if ($entry === '' || strpos($entry, '-') !== false || strpos($entry, ':') !== false) {
      return null;
    }
    if (strpos($entry, '*') !== false) {
      $entry = preg_replace('#/.*$#', '', $entry);
      $stars = substr_count($entry, '*');
      if ($stars > 3) {
        return array(0, 0xFFFFFFFF);
      }
      $base = str_replace('*', '0', $entry);
      $prefix = 32 - 8 * $stars;
    } elseif (strpos($entry, '/') !== false) {
      list($base, $prefix) = explode('/', $entry, 2);
      $prefix = intval($prefix);
    } else {
      $base = $entry;
      $prefix = 32;
    }
    $dots = substr_count($base, '.');
    if ($dots < 3) {
      $base .= str_repeat('.0', 3 - $dots);
    }
    $long = ip2long($base);
    if ($long === false || $prefix < 0 || $prefix > 32) {
      return null;
    }
    $mask = ($prefix == 0) ? 0 : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);
    $start = $long & $mask;
    return array($start, $start | (~$mask & 0xFFFFFFFF));
  }

  /**
   * Analyse de la liste blanche : chaque entrée est classée
   *   - open : couvre tout Internet (à retirer) ;
   *   - narrow : déborde sur des adresses publiques mais contient des plages privées (à réduire, ex. 172.*.*.*) ;
   *   - public : adresse ou plage publique précise (à vérifier par l'utilisateur) ;
   *   - ok : uniquement des adresses privées ou locales.
   * @return array liste de {entry, type, replace (plages privées de remplacement)}
   */
  private static function analyzeWhiteIps() {
    $result = array();
    foreach (array_filter(array_map('trim', explode(';', config::byKey('security::whiteips')))) as $entry) {
      if (self::isWildcardIp($entry)) {
        $result[] = array('entry' => $entry, 'type' => 'open', 'replace' => array());
        continue;
      }
      $range = self::ipRange($entry);
      if ($range === null) {
        $result[] = array('entry' => $entry, 'type' => 'ok', 'replace' => array());
        continue;
      }
      $inside = array();
      $type = 'public';
      foreach (self::$privateRanges as $private) {
        $priv = self::ipRange($private);
        if ($range[0] >= $priv[0] && $range[1] <= $priv[1]) {
          $type = 'ok'; // entièrement privée
          break;
        }
        if ($priv[0] >= $range[0] && $priv[1] <= $range[1]) {
          $inside[] = $private; // plage privée contenue dans l'entrée
        }
      }
      if ($type != 'ok' && count($inside) > 0) {
        $type = 'narrow';
      }
      $result[] = array('entry' => $entry, 'type' => $type, 'replace' => ($type == 'narrow') ? $inside : array());
    }
    return $result;
  }

  private static function check_whiteips() {
    $analysis = self::analyzeWhiteIps();
    $open = array();
    $items = array();
    $fixable = false;
    foreach ($analysis as $row) {
      if ($row['type'] == 'open') {
        $open[] = $row['entry'];
        $fixable = true;
      } elseif ($row['type'] == 'narrow') {
        $items[] = sprintf(__('%s : couvre aussi des adresses publiques, remplaçable par %s', __FILE__), $row['entry'], implode(', ', $row['replace']));
        $fixable = true;
      } elseif ($row['type'] == 'public') {
        $items[] = sprintf(__('%s : adresse publique, vérifiez qu\'elle vous appartient', __FILE__), $row['entry']);
      }
    }
    if (count($open) > 0) {
      $result = self::fail(__('La liste blanche contient une entrée qui couvre tout Internet.', __FILE__), array_merge($open, $items));
    } elseif (count($items) > 0) {
      $result = self::warn(__('La liste blanche couvre des adresses publiques.', __FILE__), $items);
    } else {
      $entries = array_map(function ($row) { return $row['entry']; }, $analysis);
      return self::pass(count($entries) == 0 ? __('Liste blanche vide.', __FILE__) : __('La liste blanche ne contient que des plages locales.', __FILE__), $entries);
    }
    // Seules les entrées ouvertes ou trop larges se corrigent automatiquement
    return $fixable ? $result : self::noFix($result);
  }

  private static function fix_whiteips() {
    $kept = array();
    $changed = false;
    foreach (self::analyzeWhiteIps() as $row) {
      if ($row['type'] == 'open') {
        $changed = true;
      } elseif ($row['type'] == 'narrow') {
        $kept = array_merge($kept, $row['replace']);
        $changed = true;
      } else {
        $kept[] = $row['entry'];
      }
    }
    if (!$changed) {
      throw new Exception(__('Aucune entrée à corriger automatiquement : vérifiez les adresses publiques à la main (Configuration > Sécurité).', __FILE__));
    }
    if (!in_array('127.0.0.1', $kept)) {
      array_unshift($kept, '127.0.0.1');
    }
    $kept = array_values(array_unique($kept));
    config::save('security::whiteips', implode(';', $kept));
    return __('Liste blanche :', __FILE__) . ' ' . implode(';', $kept);
  }

  private static function check_session_lifetime() {
    $hours = floatval(config::byKey('session_lifetime'));
    if ($hours > 168) {
      return self::warn(sprintf(__('Les sessions durent %s heures (%s jours).', __FILE__), $hours, round($hours / 24, 1)));
    }
    return self::pass(sprintf(__('Les sessions durent %s heures.', __FILE__), $hours));
  }

  private static function fix_session_lifetime() {
    config::save('session_lifetime', 24);
    return __('Durée des sessions ramenée à 24 heures.', __FILE__);
  }

  private static function check_external_https() {
    $dns = (config::byKey('market::allowDNS') == 1);
    $addr = trim(config::byKey('externalAddr'));
    $protocol = config::byKey('externalProtocol');
    if (!$dns && $addr == '') {
      return self::pass(__('Aucun accès externe n\'est configuré.', __FILE__));
    }
    if ($addr != '' && $protocol != 'https://') {
      return self::fail(sprintf(__('L\'accès externe déclaré est en HTTP : %s', __FILE__), $protocol . $addr));
    }
    if ($dns) {
      return self::pass(__('Accès externe par le DNS Jeedom, chiffré en HTTPS.', __FILE__));
    }
    return self::pass(sprintf(__('Accès externe en HTTPS : %s', __FILE__), $protocol . $addr));
  }

  /* ------------------------------- API ------------------------------- */

  /** API du core vérifiées, avec leur clé de configuration */
  private static function coreApis() {
    return array(
      'core' => array('name' => __('API JSON RPC / HTTP', __FILE__), 'key' => 'api'),
      'apitts' => array('name' => __('API TTS', __FILE__), 'key' => 'apitts'),
      'apipro' => array('name' => __('API Pro', __FILE__), 'key' => 'apipro'),
    );
  }

  private static function check_api_modes() {
    $open = array();
    foreach (self::coreApis() as $id => $api) {
      if (config::byKey($api['key']) == '') {
        continue;
      }
      if (config::byKey('api::' . $id . '::mode', 'core', 'enable') == 'enable') {
        $open[] = $api['name'];
      }
    }
    if (count($open) == 0) {
      return self::pass(__('Les API du core sont restreintes ou désactivées.', __FILE__));
    }
    if (self::externalAccess() == '') {
      return self::pass(__('Des API sont ouvertes, mais Jeedom n\'est pas exposé sur Internet.', __FILE__), $open);
    }
    return self::warn(__('Ces API répondent depuis n\'importe quelle adresse, et Jeedom est accessible depuis Internet.', __FILE__), $open);
  }

  private static function fix_api_modes() {
    if (trim(config::byKey('security::whiteips')) == '') {
      throw new Exception(__('La liste blanche est vide : renseignez-la (Configuration > Sécurité) avant de passer les API en mode IP blanche.', __FILE__));
    }
    $changed = array();
    foreach (self::coreApis() as $id => $api) {
      if (config::byKey($api['key']) != '' && config::byKey('api::' . $id . '::mode', 'core', 'enable') == 'enable') {
        config::save('api::' . $id . '::mode', 'whiteip');
        $changed[] = $api['name'];
      }
    }
    return __('Passées en mode IP blanche :', __FILE__) . ' ' . implode(', ', $changed);
  }

  private static function check_api_key_strength() {
    $weak = array();
    foreach (self::coreApis() as $id => $api) {
      $key = (string) config::byKey($api['key']);
      if ($key !== '' && strlen($key) < 32) {
        $weak[] = $api['name'] . ' (' . strlen($key) . ' ' . __('caractères', __FILE__) . ')';
      }
    }
    if (count($weak) > 0) {
      return self::fail(__('Clés API trop courtes.', __FILE__), $weak);
    }
    return self::pass(__('Les clés API font au moins 32 caractères.', __FILE__));
  }

  private static function fix_api_key_strength() {
    $changed = array();
    foreach (self::coreApis() as $id => $api) {
      $key = (string) config::byKey($api['key']);
      if ($key !== '' && strlen($key) < 32) {
        config::save($api['key'], config::genKey());
        $changed[] = $api['name'];
      }
    }
    return __('Clés régénérées :', __FILE__) . ' ' . implode(', ', $changed);
  }

  /* ----------------------------- Jeedom ------------------------------ */

  private static function check_core_update() {
    $update = update::byTypeAndLogicalId('core', 'jeedom');
    $version = jeedom::version();
    if (is_object($update) && $update->getStatus() == 'update') {
      return self::warn(sprintf(__('Jeedom %s est installé, la version %s est disponible.', __FILE__), $version, $update->getRemoteVersion()));
    }
    return self::pass(sprintf(__('Jeedom %s est à jour (selon la dernière vérification des mises à jour).', __FILE__), $version));
  }

  private static function check_plugins_update() {
    $pending = array();
    foreach (update::byType('plugin') as $update) {
      if ($update->getStatus() == 'update' && $update->getConfiguration('doNotUpdate', 0) != 1) {
        $pending[] = $update->getName();
      }
    }
    if (count($pending) > 0) {
      return self::warn(sprintf(__('%d plugin(s) à mettre à jour.', __FILE__), count($pending)), $pending);
    }
    return self::pass(__('Tous les plugins sont à jour (selon la dernière vérification des mises à jour).', __FILE__));
  }

  private static function check_plugins_sources() {
    $others = array();
    foreach (update::byType('plugin') as $update) {
      $source = $update->getSource();
      if ($source != 'market' && $source != '') {
        $others[] = $update->getName() . ' (' . $source . ')';
      }
    }
    if (count($others) > 0) {
      return self::info(sprintf(__('%d plugin(s) installé(s) hors Market.', __FILE__), count($others)), $others);
    }
    return self::pass(__('Tous les plugins viennent du Market.', __FILE__));
  }

  /** Logs actuellement en niveau Debug : {id => nom}. */
  private static function debugLogs() {
    $debug = array();
    if (intval(config::byKey('log::level')) == 100) {
      $debug['__global__'] = __('Niveau global de Jeedom', __FILE__);
    }
    foreach (plugin::listPlugin(true) as $plugin) {
      $id = $plugin->getId();
      $level = config::byKey('log::level::' . $id);
      if (is_array($level) && isset($level['100']) && $level['100'] == 1 && (!isset($level['default']) || $level['default'] != 1)) {
        $debug[$id] = $plugin->getName();
      }
    }
    return $debug;
  }

  private static function check_debug_logs() {
    $debug = self::debugLogs();
    if (count($debug) > 0) {
      return self::warn(sprintf(__('%d log(s) en mode Debug.', __FILE__), count($debug)), array_values($debug));
    }
    return self::pass(__('Aucun log en mode Debug.', __FILE__));
  }

  private static function fix_debug_logs() {
    foreach (self::debugLogs() as $id => $name) {
      if ($id == '__global__') {
        config::save('log::level', 400);
        continue;
      }
      config::save('log::level::' . $id, array('100' => '0', '200' => '0', '300' => '0', '400' => '0', '1000' => '0', 'default' => '1'));
    }
    return __('Niveaux de log remis par défaut.', __FILE__);
  }

  /* ---------------------------- Serveur web --------------------------- */

  /** Dossier web de Jeedom : chemin servi par Apache pour un chemin disque, ou null s'il est hors de la racine. */
  private static function webPath($_path) {
    $root = auditsecurityTools::jeedomRoot();
    $real = realpath($_path);
    if ($real === false || strpos($real, $root . '/') !== 0) {
      return null;
    }
    return substr($real, strlen($root));
  }

  /** Page de connexion de Jeedom (réponse 200 sans session), mise en cache pour l'audit. */
  private static function homePage() {
    static $home = false;
    if ($home === false) {
      $home = auditsecurityTools::httpGet('/index.php?v=d');
    }
    return $home;
  }

  private static function check_http_sensitive_files() {
    if (self::homePage() === null) {
      return self::skip(sprintf(__('L\'interface locale (%s) ne répond pas.', __FILE__), auditsecurityTools::localUrl()));
    }
    $root = auditsecurityTools::jeedomRoot();
    $exposed = array();
    $tested = array();
    // Fichiers témoins déposés dans les dossiers qui doivent rester inaccessibles
    $dirs = array($root . '/log');
    $backupDir = config::byKey('backup::path');
    $dirs[] = (substr($backupDir, 0, 1) == '/') ? $backupDir : $root . '/' . $backupDir;
    foreach (array_unique($dirs) as $dir) {
      $webDir = self::webPath($dir);
      if ($webDir === null || !is_writable($dir)) {
        continue;
      }
      $token = 'auditsecurity-' . bin2hex(random_bytes(8));
      $file = $dir . '/' . $token . '.txt';
      if (@file_put_contents($file, $token) === false) {
        continue;
      }
      $res = auditsecurityTools::httpGet($webDir . '/' . $token . '.txt');
      @unlink($file);
      $tested[] = $webDir . '/';
      if ($res !== null && $res['code'] >= 200 && $res['code'] < 300 && strpos($res['body'], $token) !== false) {
        $exposed[] = $webDir . '/ ' . __('(fichiers téléchargeables)', __FILE__);
      }
    }
    // Fichiers existants qui ne doivent pas être servis
    $files = array('/core/config/default.config.ini' => 'session_lifetime');
    if (file_exists($root . '/.git/HEAD')) {
      $files['/.git/HEAD'] = 'ref:';
    }
    foreach ($files as $path => $marker) {
      $res = auditsecurityTools::httpGet($path);
      $tested[] = $path;
      if ($res !== null && $res['code'] >= 200 && $res['code'] < 300 && strpos($res['body'], $marker) !== false) {
        $exposed[] = $path;
      }
    }
    if (count($exposed) > 0) {
      return self::fail(__('Ces emplacements sont accessibles depuis le navigateur :', __FILE__), $exposed);
    }
    return self::pass(__('Apache refuse l\'accès aux emplacements testés.', __FILE__), $tested);
  }

  private static function check_http_headers() {
    $res = self::homePage();
    if ($res === null) {
      return self::skip(sprintf(__('L\'interface locale (%s) ne répond pas.', __FILE__), auditsecurityTools::localUrl()));
    }
    $missing = array();
    foreach (array('x-frame-options' => 'X-Frame-Options', 'x-content-type-options' => 'X-Content-Type-Options') as $key => $name) {
      if (!isset($res['headers'][$key])) {
        $missing[] = $name;
      }
    }
    if (count($missing) > 0) {
      return self::warn(__('En-têtes absents :', __FILE__) . ' ' . implode(', ', $missing), $missing);
    }
    return self::pass(__('Les en-têtes de sécurité sont présents.', __FILE__));
  }

  private static function check_server_tokens() {
    $res = self::homePage();
    if ($res === null) {
      return self::skip(sprintf(__('L\'interface locale (%s) ne répond pas.', __FILE__), auditsecurityTools::localUrl()));
    }
    $leaks = array();
    if (isset($res['headers']['server']) && preg_match('/\d/', $res['headers']['server'])) {
      $leaks[] = 'Server: ' . $res['headers']['server'];
    }
    if (isset($res['headers']['x-powered-by'])) {
      $leaks[] = 'X-Powered-By: ' . $res['headers']['x-powered-by'];
    }
    if (count($leaks) > 0) {
      return self::warn(__('Le serveur web annonce ses versions.', __FILE__), $leaks);
    }
    return self::pass(__('Aucune version n\'est annoncée.', __FILE__));
  }

  /** Correction commune aux contrôles Apache : reprend la configuration de sécurité livrée avec Jeedom. */
  private static function fixApacheSecurity() {
    $source = auditsecurityTools::jeedomRoot() . '/install/apache_security';
    $target = '/etc/apache2/conf-available/security.conf';
    if (!file_exists($source)) {
      throw new Exception(__('Fichier de référence introuvable :', __FILE__) . ' ' . $source);
    }
    if (!auditsecurityTools::canRoot() || !auditsecurityTools::hasBinary('apache2ctl')) {
      throw new Exception(__('Apache ou les droits root sont indisponibles sur cette installation.', __FILE__));
    }
    $content = str_replace('WEBSERVER_HOME', auditsecurityTools::jeedomRoot(), file_get_contents($source));
    $backup = $target . '.auditsecurity.bak';
    auditsecurityTools::execRoot('sh -c ' . escapeshellarg('[ -f ' . $target . ' ] && [ ! -f ' . $backup . ' ] && cp -p ' . $target . ' ' . $backup . '; true'), 10);
    auditsecurityTools::writeRootFile($target, $content);
    auditsecurityTools::execRoot('a2enmod -q headers', 20);
    auditsecurityTools::execRoot('a2enconf -q security', 20);
    $test = auditsecurityTools::execRoot('apache2ctl configtest 2>&1', 20);
    if ($test['code'] !== 0) {
      if (auditsecurityTools::readFile($backup, true) !== null) {
        auditsecurityTools::execRoot('cp -p ' . escapeshellarg($backup) . ' ' . escapeshellarg($target), 10);
      }
      throw new Exception(__('Configuration Apache invalide, ancienne configuration restaurée :', __FILE__) . ' ' . trim($test['output']));
    }
    // Rechargement différé pour ne pas couper la requête en cours (comme le fait le core)
    if (auditsecurityTools::hasBinary('at')) {
      auditsecurityTools::execRoot('sh -c ' . escapeshellarg('echo "systemctl reload apache2" | at now'), 10);
    } else {
      auditsecurityTools::execRoot('sh -c ' . escapeshellarg('(sleep 2; systemctl reload apache2) >/dev/null 2>&1 &'), 5);
    }
    return __('Configuration Apache de Jeedom restaurée, Apache va être rechargé. Relancez l\'audit dans quelques secondes.', __FILE__);
  }

  private static function fix_http_sensitive_files() {
    return self::fixApacheSecurity();
  }

  private static function fix_http_headers() {
    return self::fixApacheSecurity();
  }

  private static function fix_server_tokens() {
    return self::fixApacheSecurity();
  }

  /** Version d'un paquet Debian installé, ou '' s'il est absent (ou dpkg indisponible). */
  private static function packageVersion($_package) {
    if (!auditsecurityTools::hasBinary('dpkg-query')) {
      return '';
    }
    $res = auditsecurityTools::exec("dpkg-query -W -f='\${Version}' " . escapeshellarg($_package) . ' 2>/dev/null', 5);
    return ($res['code'] === 0) ? trim($res['output']) : '';
  }

  private static function check_php_eol() {
    $branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    $label = 'PHP ' . PHP_VERSION;
    // PHP des dépôts Debian : l'équipe sécurité de Debian le corrige pendant tout le support de la distribution,
    // bien après la fin de support officielle de PHP. Le dépôt sury.org (version en « +0~ ») suit au contraire PHP.
    $package = self::packageVersion('php' . $branch . '-common');
    $os = auditsecurityTools::osRelease();
    $major = isset($os['VERSION_ID']) ? explode('.', $os['VERSION_ID'])[0] : '';
    if ($package !== '' && strpos($package, '+0~') === false && stripos($package, 'sury') === false
      && isset($os['ID']) && in_array($os['ID'], array('debian', 'raspbian')) && isset(self::$debianEol[$major])) {
      return self::eolStatus(sprintf(__('%s (paquet Debian %s, corrigé par Debian)', __FILE__), $label, $package), self::$debianEol[$major]);
    }
    return self::eolStatus($label, isset(self::$phpEol[$branch]) ? self::$phpEol[$branch] : null);
  }

  /* ------------------------------ Système ----------------------------- */

  private static function check_os_eol() {
    $os = auditsecurityTools::osRelease();
    $name = isset($os['PRETTY_NAME']) ? $os['PRETTY_NAME'] : __('Système inconnu', __FILE__);
    if (!isset($os['ID']) || ($os['ID'] != 'debian' && $os['ID'] != 'raspbian')) {
      if (auditsecurityTools::isDocker()) {
        return self::info(sprintf(__('%s (conteneur Docker) : pensez à mettre à jour l\'image et le système hôte.', __FILE__), $name));
      }
      return self::info(sprintf(__('%s : seules les versions de Debian sont suivies par le plugin.', __FILE__), $name));
    }
    $major = isset($os['VERSION_ID']) ? explode('.', $os['VERSION_ID'])[0] : '';
    return self::eolStatus($name, isset(self::$debianEol[$major]) ? self::$debianEol[$major] : null);
  }

  private static function check_system_passwords() {
    if (!auditsecurityTools::canRoot()) {
      return self::skip(__('Droits root indisponibles : impossible de lire /etc/shadow.', __FILE__));
    }
    if (!auditsecurityTools::hasBinary('perl')) {
      return self::skip(__('perl est absent : impossible de comparer les mots de passe.', __FILE__));
    }
    $shadow = auditsecurityTools::readFile('/etc/shadow', true);
    if ($shadow === null) {
      return self::skip(__('Impossible de lire /etc/shadow.', __FILE__));
    }
    // Comptes testés : root, jeedom, pi et les comptes humains (UID >= 1000 avec un shell)
    $accounts = array('root' => true, 'jeedom' => true, 'pi' => true);
    foreach (explode("\n", (string) @file_get_contents('/etc/passwd')) as $line) {
      $cols = explode(':', $line);
      if (count($cols) >= 7 && intval($cols[2]) >= 1000 && intval($cols[2]) < 65534 && !preg_match('#(nologin|false)$#', $cols[6])) {
        $accounts[$cols[0]] = true;
      }
    }
    $input = '';
    $empty = array();
    foreach (explode("\n", $shadow) as $line) {
      $cols = explode(':', $line);
      if (count($cols) < 2 || !isset($accounts[$cols[0]])) {
        continue;
      }
      $hash = $cols[1];
      if ($hash === '') {
        $empty[] = $cols[0] . ' (' . __('aucun mot de passe', __FILE__) . ')';
        continue;
      }
      if ($hash[0] === '!' || $hash[0] === '*') {
        continue; // compte verrouillé
      }
      $candidates = array_unique(array_merge(array($cols[0]), self::$commonPasswords));
      $input .= $cols[0] . "\t" . $hash . "\t" . implode("\t", $candidates) . "\n";
    }
    $weak = $empty;
    if ($input !== '') {
      // perl utilise le crypt() du système, compatible avec tous les formats (yescrypt, sha512...)
      $script = 'while(<STDIN>){chomp;my($u,$h,@c)=split(/\t/);foreach my $p(@c){my $r=crypt($p,$h);if(defined $r && $r eq $h){print "$u\n";last;}}}';
      $res = auditsecurityTools::exec('perl -e ' . escapeshellarg($script), 60, $input);
      foreach (array_filter(explode("\n", trim($res['output']))) as $login) {
        $weak[] = $login . ' (' . __('mot de passe par défaut ou trop courant', __FILE__) . ')';
      }
    }
    if (count($weak) > 0) {
      return self::fail(sprintf(__('%d compte(s) système avec un mot de passe connu.', __FILE__), count($weak)), $weak);
    }
    return self::pass(sprintf(__('Aucun mot de passe connu sur les comptes testés : %s.', __FILE__), implode(', ', array_keys($accounts))));
  }

  private static function check_ssh_root() {
    $ssh = self::sshConfig();
    if ($ssh === null) {
      return self::pass(__('Serveur SSH non installé.', __FILE__));
    }
    if (!self::sshListening($ssh)) {
      return self::pass(__('Serveur SSH arrêté.', __FILE__));
    }
    $value = isset($ssh['permitrootlogin']) ? $ssh['permitrootlogin'] : 'prohibit-password';
    if ($value == 'yes') {
      $result = self::fail(__('PermitRootLogin yes : root peut se connecter en SSH avec un mot de passe.', __FILE__));
      return auditsecurityTools::canRoot() ? $result : self::noFix($result);
    }
    return self::pass('PermitRootLogin ' . $value);
  }

  private static function fix_ssh_root() {
    if (!auditsecurityTools::canRoot()) {
      throw new Exception(__('Droits root indisponibles.', __FILE__));
    }
    $main = (string) auditsecurityTools::readFile('/etc/ssh/sshd_config', true);
    // Le premier réglage rencontré l'emporte : le fichier inclus en tête de sshd_config est prioritaire
    if (preg_match('#^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf#mi', $main)) {
      auditsecurityTools::writeRootFile('/etc/ssh/sshd_config.d/00-auditsecurity.conf', "# Ajouté par le plugin Jeedom Audit Sécurité\nPermitRootLogin prohibit-password\n");
      $rollback = 'rm -f /etc/ssh/sshd_config.d/00-auditsecurity.conf';
    } else {
      auditsecurityTools::execRoot('cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.auditsecurity.bak', 10);
      auditsecurityTools::execRoot("sed -i -E 's/^[#[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config", 10);
      $rollback = 'cp -p /etc/ssh/sshd_config.auditsecurity.bak /etc/ssh/sshd_config';
    }
    $test = auditsecurityTools::execRoot('sshd -t 2>&1', 10);
    if ($test['code'] !== 0) {
      auditsecurityTools::execRoot($rollback, 10);
      throw new Exception(__('Configuration SSH invalide, modification annulée :', __FILE__) . ' ' . trim($test['output']));
    }
    $reload = auditsecurityTools::execRoot('sh -c ' . escapeshellarg('systemctl reload ssh 2>/dev/null || systemctl reload sshd'), 15);
    if ($reload['code'] !== 0) {
      throw new Exception(__('Configuration modifiée mais le service SSH n\'a pas pu être rechargé.', __FILE__));
    }
    return __('root ne peut plus se connecter en SSH par mot de passe.', __FILE__);
  }

  private static function check_ssh_password_auth() {
    $ssh = self::sshConfig();
    if ($ssh === null) {
      return self::pass(__('Serveur SSH non installé.', __FILE__));
    }
    if (!self::sshListening($ssh)) {
      return self::pass(__('Serveur SSH arrêté.', __FILE__));
    }
    $value = isset($ssh['passwordauthentication']) ? $ssh['passwordauthentication'] : 'yes';
    if ($value == 'yes') {
      $exposed = self::sshExposure(isset($ssh['port']) ? intval($ssh['port']) : 22);
      if (count($exposed) > 0) {
        return self::warn(__('Les connexions SSH par mot de passe sont autorisées et SSH semble accessible depuis Internet.', __FILE__), $exposed);
      }
      // Sur le seul réseau local, c'est l'usage courant : simple information
      return self::info(__('Les connexions SSH par mot de passe sont autorisées. SSH ne semble pas accessible depuis Internet : à durcir si vous l\'ouvrez.', __FILE__));
    }
    return self::pass(__('Connexions SSH par clé uniquement.', __FILE__));
  }

  private static function check_ntp() {
    if (!auditsecurityTools::hasBinary('timedatectl') || auditsecurityTools::isDocker()) {
      return self::skip(__('timedatectl indisponible (l\'heure est gérée par le système hôte).', __FILE__));
    }
    $res = auditsecurityTools::exec('timedatectl show -p NTPSynchronized -p NTP', 5);
    if ($res['code'] !== 0) {
      return self::skip(__('Impossible d\'interroger timedatectl.', __FILE__));
    }
    if (strpos($res['output'], 'NTPSynchronized=yes') !== false) {
      return self::pass(__('L\'horloge est synchronisée.', __FILE__));
    }
    if (strpos($res['output'], 'NTP=no') !== false) {
      $result = self::fail(__('La synchronisation NTP est désactivée.', __FILE__));
      return auditsecurityTools::canRoot() ? $result : self::noFix($result);
    }
    return self::warn(__('La synchronisation NTP est active mais l\'horloge n\'est pas encore synchronisée (serveur NTP injoignable ?).', __FILE__));
  }

  private static function fix_ntp() {
    $res = auditsecurityTools::execRoot('timedatectl set-ntp true 2>&1', 15);
    if ($res['code'] !== 0) {
      throw new Exception(trim($res['output']));
    }
    return __('Synchronisation NTP activée.', __FILE__);
  }

  private static function check_apt_security_updates() {
    if (!auditsecurityTools::hasBinary('apt-get')) {
      return self::skip(__('apt-get indisponible.', __FILE__));
    }
    // Simulation : ne modifie rien, se base sur les listes de paquets déjà téléchargées
    $res = auditsecurityTools::exec('LANG=C apt-get -s -o Debug::NoLocking=true upgrade', 60);
    if ($res['code'] !== 0) {
      return self::skip(__('Impossible de simuler la mise à jour des paquets.', __FILE__));
    }
    $security = array();
    $total = 0;
    foreach (explode("\n", $res['output']) as $line) {
      if (strpos($line, 'Inst ') !== 0) {
        continue;
      }
      $total++;
      if (stripos($line, 'security') !== false) {
        $parts = explode(' ', $line);
        $security[] = $parts[1];
      }
    }
    // Date des listes : le fichier Release le plus récent (apt lui donne la date de publication du dépôt)
    $lists = 0;
    foreach (glob('/var/lib/apt/lists/*Release') ?: array() as $file) {
      $lists = max($lists, (int) @filemtime($file));
    }
    if ($lists == 0) {
      $lists = (int) @filemtime('/var/lib/apt/lists');
    }
    $age = ($lists) ? ' ' . sprintf(__('(listes de paquets du %s)', __FILE__), date('d/m/Y', $lists)) : '';
    if (count($security) > 0) {
      return self::warn(sprintf(__('%d mise(s) à jour de sécurité en attente, %d au total.', __FILE__), count($security), $total) . $age, array_slice($security, 0, 50));
    }
    // Sans « apt update » récent, apt ne connaît pas les derniers correctifs : ne pas conclure que tout est à jour
    if ($lists > 0 && time() - $lists > 30 * 86400) {
      return self::info(sprintf(__('Les listes de paquets datent du %s : le système ne connaît pas les correctifs récents, ce résultat n\'est pas fiable. Lancez sudo apt update, puis relancez l\'audit.', __FILE__), date('d/m/Y', $lists)));
    }
    if ($total > 0) {
      return self::pass(sprintf(__('Aucune mise à jour de sécurité en attente (%d autre(s) mise(s) à jour).', __FILE__), $total) . $age);
    }
    return self::pass(__('Le système est à jour.', __FILE__) . $age);
  }

  private static function check_config_perms() {
    $file = auditsecurityTools::jeedomRoot() . '/core/config/common.config.php';
    if (!file_exists($file)) {
      return self::skip(__('Fichier de configuration introuvable.', __FILE__));
    }
    clearstatcache(true, $file);
    $perms = fileperms($file) & 0777;
    $detail = sprintf(__('Droits actuels : %s.', __FILE__), substr(sprintf('%o', $perms), -3));
    if ($perms & 0004) {
      $result = self::warn(__('Le fichier est lisible par tous les comptes du système.', __FILE__) . ' ' . $detail);
      return auditsecurityTools::canRoot() ? $result : self::noFix($result);
    }
    return self::pass($detail);
  }

  private static function fix_config_perms() {
    $file = auditsecurityTools::jeedomRoot() . '/core/config/common.config.php';
    $owner = system::get('www-uid') . ':' . system::get('www-gid');
    $res = auditsecurityTools::execRoot('sh -c ' . escapeshellarg('chown ' . $owner . ' ' . escapeshellarg($file) . ' && chmod 640 ' . escapeshellarg($file)), 10);
    if ($res['code'] !== 0) {
      throw new Exception(__('Impossible de modifier les droits du fichier.', __FILE__));
    }
    return __('Droits du fichier de configuration restreints (640).', __FILE__);
  }

  /** Dossiers sensibles de Jeedom : chemin => nom affiché. */
  private static function sensitiveDirs() {
    $root = auditsecurityTools::jeedomRoot();
    $backup = config::byKey('backup::path');
    $backup = (substr($backup, 0, 1) == '/') ? $backup : $root . '/' . $backup;
    $dirs = array();
    foreach (array($backup => 'backup', $root . '/log' => 'log', $root . '/core/config' => 'core/config') as $path => $name) {
      $real = realpath($path);
      if ($real !== false && is_dir($real)) {
        $dirs[$real] = $name;
      }
    }
    return $dirs;
  }

  /**
   * Vrai si le serveur web est propriétaire du dossier (ou de son groupe) : retirer l'accès « autres »
   * ne le prive alors de rien. Dans le doute (extension posix absente), on considère que oui.
   */
  private static function webServerOwns($_path) {
    if (!function_exists('posix_getpwuid') || !function_exists('posix_getgrgid')) {
      return true;
    }
    $owner = posix_getpwuid(fileowner($_path));
    $group = posix_getgrgid(filegroup($_path));
    $user = system::get('www-uid');
    $gid = system::get('www-gid');
    return (is_array($owner) && $owner['name'] == $user) || (is_array($group) && $group['name'] == $gid);
  }

  private static function check_sensitive_dirs_perms() {
    $open = array();
    $items = array();
    $fixable = false;
    foreach (self::sensitiveDirs() as $path => $name) {
      clearstatcache(true, $path);
      $perms = fileperms($path) & 0777;
      $label = $name . ' (' . substr(sprintf('%o', $perms), -3) . ')';
      // Accessible si les autres peuvent traverser (x) le dossier
      if ($perms & 0001) {
        if (self::webServerOwns($path)) {
          $fixable = true;
          $open[] = $label;
        } else {
          $open[] = $label . ' : ' . __('n\'appartient pas au serveur web, à corriger à la main', __FILE__);
        }
      } else {
        $items[] = $label;
      }
    }
    if (count($open) > 0) {
      $result = self::warn(__('Ces dossiers sont accessibles aux autres comptes du système :', __FILE__), $open);
      return (auditsecurityTools::canRoot() && $fixable) ? $result : self::noFix($result);
    }
    return self::pass(__('Les dossiers sensibles ne sont accessibles qu\'au serveur web.', __FILE__), $items);
  }

  private static function fix_sensitive_dirs_perms() {
    $done = array();
    foreach (self::sensitiveDirs() as $path => $name) {
      // Sans le serveur web comme propriétaire, retirer l'accès « autres » pourrait couper Jeedom
      if ((fileperms($path) & 0001) && self::webServerOwns($path)) {
        $res = auditsecurityTools::execRoot('chmod o-rwx ' . escapeshellarg($path), 10);
        if ($res['code'] !== 0) {
          throw new Exception(__('Impossible de modifier les droits.', __FILE__) . ' ' . $name);
        }
        $done[] = $name;
      }
    }
    return __('Accès « autres » retiré :', __FILE__) . ' ' . implode(', ', $done);
  }

  private static function check_suid_files() {
    $root = auditsecurityTools::jeedomRoot();
    $res = auditsecurityTools::exec('find ' . escapeshellarg($root) . ' -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -n 50', 60);
    $files = array_filter(explode("\n", trim($res['output'])));
    if (count($files) > 0) {
      $items = array();
      foreach ($files as $file) {
        $items[] = str_replace($root, '', $file);
      }
      return self::fail(sprintf(__('%d fichier(s) SUID/SGID trouvé(s) dans Jeedom.', __FILE__), count($files)), $items);
    }
    return self::pass(__('Aucun fichier SUID/SGID dans Jeedom.', __FILE__));
  }

  private static function check_world_writable() {
    $root = auditsecurityTools::jeedomRoot();
    $res = auditsecurityTools::exec('find ' . escapeshellarg($root) . ' -xdev -perm -0002 ! -type l -print 2>/dev/null | head -n 201', 60);
    $files = array_filter(explode("\n", trim($res['output'])));
    if (count($files) > 0) {
      $items = array();
      foreach (array_slice($files, 0, 20) as $file) {
        $items[] = str_replace($root, '', $file);
      }
      if (count($files) > 20) {
        $items[] = '...';
      }
      $result = self::warn(sprintf(__('%s fichier(s) ou dossier(s) modifiable(s) par tous.', __FILE__), (count($files) > 200) ? '200+' : count($files)), $items);
      return auditsecurityTools::canRoot() ? $result : self::noFix($result);
    }
    return self::pass(__('Aucun fichier de Jeedom n\'est modifiable par tous.', __FILE__));
  }

  private static function fix_world_writable() {
    $res = auditsecurityTools::execRoot('chmod -R o-w ' . escapeshellarg(auditsecurityTools::jeedomRoot()), 120);
    if ($res['code'] !== 0) {
      throw new Exception(__('Impossible de modifier les droits.', __FILE__));
    }
    return __('Droit d\'écriture « autres » retiré.', __FILE__);
  }

  private static function check_sudo_www() {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
      return self::info(__('Jeedom tourne directement en root.', __FILE__));
    }
    if (!auditsecurityTools::canRoot()) {
      return self::info(__('Le serveur web n\'a pas les droits sudo : certaines fonctions de Jeedom et de cet audit sont limitées.', __FILE__));
    }
    return self::info(__('Le serveur web peut lancer n\'importe quelle commande en root sans mot de passe (configuration standard de Jeedom).', __FILE__));
  }

  /* ------------------------------ Réseau ------------------------------ */

  private static function check_firewall() {
    if (auditsecurityTools::isDocker()) {
      return self::skip(__('Conteneur Docker : le filtrage se fait sur le système hôte.', __FILE__));
    }
    if (!auditsecurityTools::canRoot()) {
      return self::skip(__('Droits root indisponibles : impossible de lire les règles du pare-feu.', __FILE__));
    }
    if (auditsecurityTools::hasBinary('ufw')) {
      $res = auditsecurityTools::execRoot('ufw status', 10);
      if (stripos($res['output'], 'Status: active') !== false) {
        return self::pass(__('Pare-feu ufw actif.', __FILE__));
      }
    }
    if (auditsecurityTools::hasBinary('nft')) {
      $res = auditsecurityTools::execRoot('nft list ruleset', 10);
      $blocks = self::nftInputBlocks($res['output']);
      if ($blocks > 0) {
        return self::pass(__('Règles nftables de filtrage en entrée présentes.', __FILE__));
      }
    }
    if (auditsecurityTools::hasBinary('iptables')) {
      $res = auditsecurityTools::execRoot('iptables -S INPUT', 10);
      if (preg_match('/^-P INPUT (DROP|REJECT)/m', $res['output']) || preg_match('/^-A INPUT .*-j (DROP|REJECT)/m', $res['output'])) {
        return self::pass(__('Règles iptables de filtrage en entrée présentes.', __FILE__));
      }
    }
    return self::warn(__('Aucun pare-feu actif détecté (ufw, nftables, iptables) : tous les services à l\'écoute sont joignables.', __FILE__));
  }

  /**
   * Nombre de règles nftables qui filtrent l'entrée de la box : politique « drop » ou règle drop/reject
   * dans une chaîne attachée au hook input. Les tables de fail2ban et les chaînes de transit (Docker, forward) ne comptent pas.
   */
  private static function nftInputBlocks($_ruleset) {
    $blocks = 0;
    $table = '';
    $inputChain = false;
    foreach (explode("\n", $_ruleset) as $line) {
      $line = trim($line);
      if (preg_match('/^table\s+\S+\s+(\S+)/', $line, $m)) {
        $table = $m[1];
        $inputChain = false;
      }
      if (preg_match('/^chain\s+/', $line)) {
        $inputChain = false;
      }
      if (stripos($table, 'f2b') !== false) {
        continue;
      }
      if (strpos($line, 'hook input') !== false) {
        $inputChain = true;
        if (preg_match('/policy\s+drop/', $line)) {
          $blocks++;
        }
        continue;
      }
      if ($inputChain && preg_match('/(^|\s)(drop|reject)(\s|$|;)/', $line)) {
        $blocks++;
      }
    }
    return $blocks;
  }

  private static function check_fail2ban() {
    if (auditsecurityTools::isDocker()) {
      return self::skip(__('Conteneur Docker : fail2ban s\'installe sur le système hôte.', __FILE__));
    }
    $state = auditsecurityTools::serviceState('fail2ban');
    if ($state == 'active') {
      return self::pass(__('fail2ban est actif.', __FILE__));
    }
    $detail = ($state == 'unknown') ? __('fail2ban n\'est pas installé.', __FILE__) : sprintf(__('fail2ban est installé mais pas démarré (%s).', __FILE__), $state);
    $reasons = self::exposureReasons();
    if (count($reasons) > 0) {
      $result = self::warn($detail . ' ' . __('Jeedom semble exposé sur Internet :', __FILE__), $reasons);
    } else {
      $result = self::info($detail . ' ' . __('Aucune exposition sur Internet détectée : utile seulement si vous redirigez des ports de votre box Internet vers Jeedom.', __FILE__));
    }
    return (auditsecurityTools::canRoot() && auditsecurityTools::hasBinary('apt-get')) ? $result : self::noFix($result);
  }

  private static function fix_fail2ban() {
    if (!auditsecurityTools::canRoot()) {
      throw new Exception(__('Droits root indisponibles.', __FILE__));
    }
    $script = realpath(__DIR__ . '/../../resources/install_fail2ban.sh');
    $ignore = array('127.0.0.1/8', '::1');
    foreach (array_filter(array_map('trim', explode(';', config::byKey('security::whiteips')))) as $entry) {
      if (!self::isWildcardIp($entry)) {
        $ignore[] = self::wildcardToCidr($entry);
      }
    }
    $cmd = auditsecurityTools::sudo() . 'bash ' . escapeshellarg($script) . ' ' . escapeshellarg(auditsecurityTools::jeedomRoot()) . ' ' . escapeshellarg(implode(' ', array_unique($ignore)));
    exec('nohup ' . $cmd . ' >> ' . escapeshellarg(log::getPathToLog('auditsecurity')) . ' 2>&1 &');
    return __('Installation de fail2ban lancée en tâche de fond. Relancez l\'audit dans une minute.', __FILE__);
  }

  /** Convertit une entrée de liste blanche Jeedom (192.168.1.*) en notation CIDR pour fail2ban. */
  private static function wildcardToCidr($_entry) {
    if (strpos($_entry, '*') === false) {
      return $_entry;
    }
    $parts = explode('.', $_entry);
    $fixed = 0;
    foreach ($parts as $part) {
      if ($part === '*') {
        break;
      }
      $fixed++;
    }
    $parts = array_pad(array_slice($parts, 0, $fixed), 4, '0');
    return implode('.', $parts) . '/' . ($fixed * 8);
  }

  private static function check_mysql_exposed() {
    global $CONFIG;
    $host = isset($CONFIG['db']['host']) ? $CONFIG['db']['host'] : 'localhost';
    if (!in_array($host, array('localhost', '127.0.0.1', '::1'))) {
      return self::info(sprintf(__('La base de données est sur un autre serveur (%s) : vérifiez sa sécurité séparément.', __FILE__), $host));
    }
    if (count(auditsecurityTools::listeningPorts()) == 0) {
      return self::skip(__('Impossible de lister les ports à l\'écoute.', __FILE__));
    }
    if (auditsecurityTools::isPortPublic(self::MYSQL_PORT)) {
      return self::fail(sprintf(__('La base de données écoute sur le réseau (port %d).', __FILE__), self::MYSQL_PORT));
    }
    return self::pass(__('La base de données n\'écoute qu\'en local.', __FILE__));
  }

  private static function check_db_credentials() {
    global $CONFIG;
    $issues = array();
    $user = isset($CONFIG['db']['username']) ? $CONFIG['db']['username'] : '';
    $password = isset($CONFIG['db']['password']) ? (string) $CONFIG['db']['password'] : '';
    if ($user == 'root') {
      $issues[] = __('Jeedom utilise le compte root de la base de données', __FILE__);
    }
    if ($password === '') {
      $issues[] = __('Aucun mot de passe', __FILE__);
    } elseif (strlen($password) < 12) {
      $issues[] = sprintf(__('Mot de passe de %d caractères', __FILE__), strlen($password));
    } elseif (in_array($password, self::$commonPasswords) || $password == $user) {
      $issues[] = __('Mot de passe trop courant', __FILE__);
    }
    if (count($issues) > 0) {
      return self::fail(__('Identifiants de base de données faibles.', __FILE__), $issues);
    }
    return self::pass(sprintf(__('Compte dédié (%s) avec un mot de passe de %d caractères.', __FILE__), $user, strlen($password)));
  }

  /**
   * Lecture de la configuration Mosquitto locale : {exists, anonymous, passwordFile, listeners, lines}.
   * « lines » liste les directives utiles avec leur fichier et leur ligne, pour savoir d'où vient un réglage.
   * Les dossiers déclarés par include_dir sont lus comme le fait Mosquitto.
   */
  private static function mosquittoConfig() {
    $files = array('/etc/mosquitto/mosquitto.conf');
    $dirs = array('/etc/mosquitto/conf.d');
    $config = array('exists' => false, 'anonymous' => null, 'passwordFile' => false, 'listeners' => array(), 'lines' => array());
    $read = array();
    for ($i = 0; $i < count($files); $i++) {
      $file = $files[$i];
      if (isset($read[$file])) {
        continue;
      }
      $read[$file] = true;
      $content = auditsecurityTools::readFile($file);
      if ($content === null) {
        continue;
      }
      $config['exists'] = true;
      foreach (explode("\n", $content) as $number => $line) {
        $line = trim($line);
        $useful = false;
        if (preg_match('/^allow_anonymous\s+(true|false)/i', $line, $m)) {
          $config['anonymous'] = (strtolower($m[1]) == 'true');
          $useful = true;
        }
        if (preg_match('/^(password_file|auth_plugin|plugin)\s+\S+/i', $line)) {
          $config['passwordFile'] = true;
          $useful = true;
        }
        if (preg_match('/^listener\s+(\d+)/i', $line, $m)) {
          $config['listeners'][] = (int) $m[1];
          $useful = true;
        }
        if (preg_match('/^include_dir\s+(\S+)/i', $line, $m)) {
          $dirs[] = rtrim($m[1], '/');
          $useful = true;
        }
        if ($useful) {
          $config['lines'][] = $file . ':' . ($number + 1) . ' : ' . $line;
        }
      }
      // Les fichiers des dossiers inclus sont lus après le fichier principal
      if ($i == 0) {
        foreach (array_unique($dirs) as $dir) {
          foreach (glob($dir . '/*.conf') ?: array() as $included) {
            $files[] = $included;
          }
        }
      }
    }
    $config['files'] = array_keys(array_filter($read));
    return $config;
  }

  /** Version de Mosquitto installée (ex. « 2.0.11 »), ou null. */
  private static function mosquittoVersion() {
    foreach (array('/usr/sbin/mosquitto -h 2>&1', 'mosquitto -h 2>&1') as $cmd) {
      $res = auditsecurityTools::exec($cmd, 5);
      if (preg_match('/mosquitto version (\d+\.\d+(?:\.\d+)?)/i', $res['output'], $m)) {
        return $m[1];
      }
    }
    if (auditsecurityTools::hasBinary('dpkg-query')) {
      $res = auditsecurityTools::exec("dpkg-query -W -f='\${Version}' mosquitto 2>/dev/null", 5);
      if (preg_match('/^(?:\d+:)?(\d+\.\d+(?:\.\d+)?)/', trim($res['output']), $m)) {
        return $m[1];
      }
    }
    return null;
  }

  /** Plugins Jeedom actifs liés à MQTT (MQTT Manager, jMQTT, Zigbee2MQTT...). */
  private static function mqttPlugins() {
    $names = array();
    try {
      foreach (plugin::listPlugin(true) as $plugin) {
        if (preg_match('/mqtt|z2m/i', $plugin->getId() . ' ' . $plugin->getName())) {
          $names[] = $plugin->getName() . ' (' . $plugin->getId() . ')';
        }
      }
    } catch (Throwable $e) {
    }
    return $names;
  }

  /** Éléments de diagnostic : d'où viennent le broker et sa configuration. */
  private static function mosquittoDiagnostic($_config, $_ports, $_tests, $_version, $_service) {
    $items = array();
    if ($_version !== null) {
      $items[] = __('Version de Mosquitto :', __FILE__) . ' ' . $_version;
    }
    if ($_service != 'unknown') {
      $items[] = __('Service mosquitto :', __FILE__) . ' ' . $_service;
    }
    foreach (auditsecurityTools::listeningPorts() as $listen) {
      if (in_array($listen['port'], $_ports)) {
        $items[] = sprintf(__('Port %d en écoute sur %s', __FILE__), $listen['port'], $listen['address']) . ($listen['process'] != '' ? ' ' . __('par', __FILE__) . ' ' . $listen['process'] : '');
      }
    }
    foreach ($_tests as $test) {
      $items[] = $test;
    }
    $plugins = self::mqttPlugins();
    if (count($plugins) > 0) {
      $items[] = __('Plugins MQTT actifs :', __FILE__) . ' ' . implode(', ', $plugins);
    }
    if ($_config['exists']) {
      $items[] = __('Fichiers lus :', __FILE__) . ' ' . implode(', ', $_config['files']);
      foreach ($_config['lines'] as $line) {
        $items[] = $line;
      }
      if (count($_config['lines']) == 0) {
        $items[] = __('Aucune directive listener, allow_anonymous ni password_file dans ces fichiers.', __FILE__);
      }
    }
    return $items;
  }

  /**
   * Points d'écoute MQTT joignables depuis le réseau : liste de {host, port} à tester.
   * Une écoute sur toutes les interfaces (0.0.0.0, ::) est testée sur l'adresse locale de la box.
   */
  private static function mqttEndpoints($_ports) {
    $localIps = auditsecurityTools::localIps();
    $endpoints = array();
    foreach (auditsecurityTools::listeningPorts() as $listen) {
      if (!$listen['public'] || !in_array($listen['port'], $_ports)) {
        continue;
      }
      $host = in_array($listen['address'], array('0.0.0.0', '::', '*', '')) ? (isset($localIps[0]) ? $localIps[0] : '') : $listen['address'];
      if ($host != '') {
        $endpoints[$host . ':' . $listen['port']] = array('host' => $host, 'port' => $listen['port']);
      }
    }
    return array_values($endpoints);
  }

  private static function check_mosquitto() {
    $config = self::mosquittoConfig();
    $ports = array_unique(array_merge(array(self::MQTT_PORT), $config['listeners']));
    $endpoints = self::mqttEndpoints($ports);
    if (count($endpoints) == 0) {
      if (count(auditsecurityTools::listeningPorts()) > 0) {
        return self::pass($config['exists'] ? __('Le broker MQTT n\'écoute qu\'en local.', __FILE__) : __('Aucun broker MQTT local détecté.', __FILE__));
      }
      // Ports non listables : test direct du port MQTT standard sur l'adresse de la box
      foreach (auditsecurityTools::localIps() as $ip) {
        $endpoints[] = array('host' => $ip, 'port' => self::MQTT_PORT);
      }
    }

    // Test réel : connexion anonyme sur chaque point d'écoute réseau
    $accepted = array();
    $refused = array();
    $errors = array();
    foreach ($endpoints as $endpoint) {
      $test = auditsecurityTools::mqttAnonymousTest($endpoint['host'], $endpoint['port']);
      $label = $endpoint['host'] . ':' . $endpoint['port'];
      if ($test['result'] == 'accepted') {
        $accepted[] = $label . ' : ' . __('connexion anonyme acceptée', __FILE__);
      } elseif ($test['result'] == 'refused') {
        $refused[] = $label . ' : ' . sprintf(__('connexion anonyme refusée (code %d)', __FILE__), $test['code']);
      } else {
        $errors[] = $label . ' : ' . __('pas de réponse MQTT (port fermé, TLS ou broker injoignable)', __FILE__);
      }
    }
    if (count($accepted) > 0) {
      return self::fail(__('Test réel : le broker MQTT accepte une connexion sans mot de passe depuis le réseau.', __FILE__), array_merge($accepted, $refused));
    }
    if (count($refused) > 0) {
      return self::pass(__('Test réel : le broker MQTT refuse les connexions sans mot de passe.', __FILE__), $refused);
    }

    // Test impossible (broker TLS, injoignable...) : repli sur la lecture de la configuration
    if (!$config['exists']) {
      if (count(auditsecurityTools::listeningPorts()) == 0) {
        return self::pass(__('Aucun broker MQTT local détecté.', __FILE__));
      }
      return self::info(sprintf(__('Un service écoute sur le port MQTT %d mais n\'a pas pu être testé et sa configuration n\'est pas lisible (broker dans un conteneur ?). Vérifiez qu\'il exige un mot de passe.', __FILE__), self::MQTT_PORT), self::mosquittoDiagnostic($config, $ports, $errors, null, 'unknown'));
    }
    $version = self::mosquittoVersion();
    $service = auditsecurityTools::serviceState('mosquitto');
    $items = self::mosquittoDiagnostic($config, $ports, $errors, $version, $service);
    if ($service == 'inactive' || $service == 'failed') {
      return self::pass(__('Mosquitto est installé mais son service est arrêté : aucun broker à protéger pour le moment.', __FILE__), $items);
    }
    if ($config['anonymous'] === true) {
      return self::warn(__('Le test de connexion n\'a pas abouti et la configuration contient allow_anonymous true : vérifiez à quel listener ce réglage s\'applique.', __FILE__), $items);
    }
    if (!$config['passwordFile']) {
      // Depuis Mosquitto 2.0, allow_anonymous vaut false par défaut : sans réglage explicite, les connexions anonymes sont refusées
      if ($version !== null && version_compare($version, '2.0', '>=')) {
        return self::pass(sprintf(__('Mosquitto %s refuse par défaut les connexions anonymes (allow_anonymous n\'est pas activé).', __FILE__), $version), $items);
      }
      if ($version !== null) {
        return self::warn(sprintf(__('Mosquitto %s accepte par défaut les connexions anonymes et aucun password_file n\'est déclaré.', __FILE__), $version), $items);
      }
      return self::warn(__('Aucun password_file déclaré : selon la version de Mosquitto, les connexions anonymes peuvent être acceptées.', __FILE__), $items);
    }
    return self::pass(__('Le broker MQTT exige une authentification (d\'après sa configuration).', __FILE__), $items);
  }

  private static function check_exposed_ports() {
    $ports = auditsecurityTools::listeningPorts();
    if (count($ports) == 0) {
      return self::skip(__('Impossible de lister les ports à l\'écoute.', __FILE__));
    }
    $items = array();
    foreach ($ports as $port) {
      if (!$port['public']) {
        continue;
      }
      $key = $port['port'] . ($port['process'] != '' ? ' (' . $port['process'] . ')' : '');
      $items[$key] = sprintf(__('Port %d', __FILE__), $port['port']) . ($port['process'] != '' ? ' : ' . $port['process'] : '');
    }
    ksort($items, SORT_NUMERIC);
    return self::info(sprintf(__('%d service(s) à l\'écoute sur le réseau.', __FILE__), count($items)), array_values($items));
  }

  /* ------------------------ Exposition Internet ------------------------ */

  /** Ports considérés comme sensibles quand ils sont ouverts sur Internet vers Jeedom */
  private static $sensitivePorts = array(21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 80 => 'HTTP', 1883 => 'MQTT', 2375 => 'Docker', 3306 => 'MariaDB', 5900 => 'VNC', 8080 => 'HTTP');

  private static function check_upnp_mappings() {
    if (auditsecurityTools::isDocker()) {
      return self::skip(__('Conteneur Docker : la découverte UPnP ne traverse généralement pas le réseau Docker.', __FILE__));
    }
    $gateway = auditsecurityTools::upnpGateway();
    if ($gateway === null) {
      return self::pass(__('Aucune box Internet n\'a répondu en UPnP (UPnP désactivé ou non pris en charge) : aucun port n\'a pu être ouvert automatiquement. Les redirections créées à la main ne sont pas vérifiées.', __FILE__));
    }
    $box = ($gateway['name'] != '') ? $gateway['name'] : __('la box Internet', __FILE__);
    $localIps = auditsecurityTools::localIps();
    $toJeedom = array();
    $others = array();
    $sensitive = false;
    foreach (auditsecurityTools::upnpMappings() as $mapping) {
      $label = sprintf(__('Port %d (%s) vers %s:%d', __FILE__), $mapping['external'], $mapping['protocol'], $mapping['client'], $mapping['internal']) . ($mapping['description'] != '' ? ' - ' . $mapping['description'] : '');
      if (in_array($mapping['client'], $localIps)) {
        $toJeedom[] = $label . ' [' . __('Jeedom', __FILE__) . ']';
        if (isset(self::$sensitivePorts[$mapping['internal']])) {
          $sensitive = true;
        }
      } else {
        $others[] = $label;
      }
    }
    if ($sensitive) {
      return self::fail(sprintf(__('UPnP actif sur %s : des ports sensibles sont ouverts sur Internet vers Jeedom.', __FILE__), $box), array_merge($toJeedom, $others));
    }
    if (count($toJeedom) > 0) {
      return self::warn(sprintf(__('UPnP actif sur %s : des ports sont ouverts sur Internet vers Jeedom.', __FILE__), $box), array_merge($toJeedom, $others));
    }
    if (count($others) > 0) {
      return self::pass(sprintf(__('UPnP actif sur %s : %d redirection(s), aucune vers Jeedom. Vérifiez que les appareils concernés en ont besoin.', __FILE__), $box, count($others)), $others);
    }
    return self::pass(sprintf(__('UPnP actif sur %s, aucune redirection de port ouverte.', __FILE__), $box));
  }

  private static function check_shodan_exposure() {
    if (!self::externalChecksAllowed()) {
      return self::skip(__('Désactivé : autorisez les « Tests via des services externes » dans la configuration du plugin.', __FILE__));
    }
    $public = auditsecurityTools::publicIp(true);
    if ($public === null) {
      return self::skip(__('Impossible de déterminer l\'adresse IP publique.', __FILE__));
    }
    if (auditsecurityTools::isNonPublicIp($public['ip'])) {
      return self::pass(sprintf(__('La box Internet n\'a pas d\'adresse IPv4 publique propre (%s, partagée par l\'opérateur) : elle n\'est pas joignable directement depuis Internet en IPv4.', __FILE__), $public['ip']));
    }
    $data = self::shodanData();
    if ($data === null) {
      return self::skip(__('Shodan InternetDB ne répond pas.', __FILE__));
    }
    $items = array();
    foreach ($data['ports'] as $port) {
      $items[] = sprintf(__('Port %d', __FILE__), $port) . (isset(self::$sensitivePorts[$port]) ? ' (' . self::$sensitivePorts[$port] . ')' : '');
    }
    foreach ($data['vulns'] as $vuln) {
      $items[] = $vuln;
    }
    foreach ($data['hostnames'] as $hostname) {
      $items[] = __('Nom associé :', __FILE__) . ' ' . $hostname;
    }
    // Seuls ces marqueurs signalent une compromission ; les autres informations restent à vérifier
    $badTags = array_intersect($data['tags'], array('compromised', 'malware', 'c2', 'botnet'));
    $eolTags = array_intersect($data['tags'], array('eol-product', 'eol-os'));
    // InternetDB ne date pas ses observations : on indique depuis quand le plugin voit ce même résultat
    $staleNote = ' ' . sprintf(__('Résultat identique depuis le %s (Shodan ne fournit pas la date de son scan) : vérifiez depuis l\'extérieur que ces ports sont toujours ouverts.', __FILE__), date('d/m/Y', self::shodanSince($data)));
    if (count($badTags) > 0) {
      return self::fail(sprintf(__('Shodan signale l\'adresse %s comme compromise.', __FILE__), $data['ip']) . ' ' . __('Étiquettes :', __FILE__) . ' ' . implode(', ', $badTags) . '.' . $staleNote, $items);
    }
    if (count($data['vulns']) > 0 || count($eolTags) > 0) {
      // Les failles de Shodan sont déduites des numéros de version annoncés : Debian corrige souvent sans changer ce numéro
      $detail = sprintf(__('Shodan voit l\'adresse %s avec %d faille(s) connue(s).', __FILE__), $data['ip'], count($data['vulns']));
      if (count($eolTags) > 0) {
        $detail .= ' ' . __('Étiquettes :', __FILE__) . ' ' . implode(', ', $eolTags) . '.';
      }
      $detail .= ' ' . __('Ces failles sont déduites des versions annoncées par les services, sans test : elles peuvent être déjà corrigées.', __FILE__);
      return self::warn($detail . $staleNote, $items);
    }
    if (count($data['ports']) > 0) {
      return self::warn(sprintf(__('Shodan voit %d port(s) ouvert(s) sur l\'adresse %s.', __FILE__), count($data['ports']), $data['ip']) . $staleNote, $items);
    }
    return self::pass(sprintf(__('Shodan ne voit aucun port ouvert sur l\'adresse %s.', __FILE__), $data['ip']), $items);
  }

  private static function check_dnsbl() {
    if (!self::externalChecksAllowed()) {
      return self::skip(__('Désactivé : autorisez les « Tests via des services externes » dans la configuration du plugin.', __FILE__));
    }
    $public = auditsecurityTools::publicIp(true);
    if ($public === null) {
      return self::skip(__('Impossible de déterminer l\'adresse IP publique.', __FILE__));
    }
    if (auditsecurityTools::isNonPublicIp($public['ip'])) {
      return self::skip(sprintf(__('Adresse partagée par l\'opérateur (%s) : les listes noires ne s\'appliquent pas.', __FILE__), $public['ip']));
    }
    $reversed = implode('.', array_reverse(explode('.', $public['ip'])));
    // Codes de réponse qui signalent un vrai problème (la PBL de Spamhaus, 127.0.0.10-11, est ignorée)
    $lists = array(
      'zen.spamhaus.org' => array('127.0.0.2' => 'Spamhaus SBL', '127.0.0.3' => 'Spamhaus CSS', '127.0.0.4' => 'Spamhaus XBL', '127.0.0.5' => 'Spamhaus XBL', '127.0.0.6' => 'Spamhaus XBL', '127.0.0.7' => 'Spamhaus XBL', '127.0.0.9' => 'Spamhaus DROP'),
      'b.barracudacentral.org' => array('127.0.0.2' => 'Barracuda'),
      'bl.spamcop.net' => array('127.0.0.2' => 'SpamCop'),
    );
    $listed = array();
    $checked = array();
    $refused = array();
    foreach ($lists as $zone => $codes) {
      $answers = @gethostbynamel($reversed . '.' . $zone);
      if ($answers === false) {
        $checked[] = $zone;
        continue;
      }
      foreach ($answers as $answer) {
        if (strpos($answer, '127.255.255.') === 0) {
          // Requête refusée par la liste (résolveur DNS public ou quota dépassé)
          $refused[] = $zone;
          continue 2;
        }
        if (isset($codes[$answer])) {
          $listed[$codes[$answer]] = $codes[$answer] . ' (' . $answer . ')';
        }
      }
      $checked[] = $zone;
    }
    if (count($listed) > 0) {
      return self::fail(sprintf(__('L\'adresse %s figure sur des listes noires.', __FILE__), $public['ip']), array_values($listed));
    }
    if (count($checked) == 0) {
      return self::skip(__('Les listes noires ont refusé la requête (résolveur DNS public ?).', __FILE__));
    }
    $items = $checked;
    foreach ($refused as $zone) {
      $items[] = $zone . ' ' . __('(requête refusée)', __FILE__);
    }
    return self::pass(sprintf(__('L\'adresse %s ne figure sur aucune liste noire testée.', __FILE__), $public['ip']), $items);
  }

  private static function check_tls_certificate() {
    $addr = trim(config::byKey('externalAddr'));
    if ($addr == '' || config::byKey('externalProtocol') != 'https://') {
      if (config::byKey('market::allowDNS') == 1) {
        return self::pass(__('Accès externe par le DNS Jeedom : le certificat est géré par Jeedom.', __FILE__));
      }
      return self::pass(__('Aucun accès externe en HTTPS n\'est déclaré.', __FILE__));
    }
    $host = preg_replace('#[/:].*$#', '', $addr);
    $port = intval(config::byKey('externalPort', 'core', 443));
    if ($port <= 0) {
      $port = 443;
    }
    // 1. Connexion sans vérification : récupère le certificat présenté (échec = adresse injoignable)
    $first = self::tlsConnect($host, $port, false);
    if ($first['cert'] === null) {
      return self::skip(sprintf(__('%s:%d n\'est pas joignable depuis la box (routeur sans NAT loopback ?). Vérifiez le certificat depuis un navigateur hors de chez vous.', __FILE__), $host, $port));
    }
    $cert = $first['cert'];
    // 2. Connexion avec vérification : seul un refus lié au certificat compte, une coupure passagère est retentée
    $verified = false;
    for ($try = 0; $try < 2; $try++) {
      $check = self::tlsConnect($host, $port, true);
      if ($check['cert'] !== null) {
        $verified = true;
        break;
      }
      // Messages propres aux certificats (« Unable to connect to ssl://… » seul n'est qu'une coupure réseau)
      if (preg_match('/certificate|verify failed|SSL routines|handshake/i', $check['error'])) {
        break;
      }
      if ($try == 1) {
        return self::skip(sprintf(__('Connexion instable vers %s:%d : impossible de vérifier le certificat. Relancez l\'audit.', __FILE__), $host, $port));
      }
    }
    // Nom résolu en adresse locale (DNS du réseau local) : le certificat vu ici n'est pas forcément celui vu depuis Internet
    $resolved = gethostbyname($host);
    $localResolution = ($resolved !== $host && auditsecurityTools::isNonPublicIp($resolved));
    $issuer = isset($cert['issuer']['O']) ? $cert['issuer']['O'] : (isset($cert['issuer']['CN']) ? $cert['issuer']['CN'] : '?');
    $expires = (int) $cert['validTo_time_t'];
    $days = (int) floor(($expires - time()) / 86400);
    $items = array(__('Émetteur :', __FILE__) . ' ' . $issuer, __('Expiration :', __FILE__) . ' ' . date('d/m/Y', $expires));
    if (!$verified) {
      $detail = sprintf(__('Le certificat de %s n\'est pas reconnu (auto-signé, expiré ou émis pour un autre nom).', __FILE__), $host);
      if ($localResolution) {
        // Probablement le serveur local et non le reverse proxy vu depuis Internet : à confirmer de l'extérieur
        return self::warn($detail . ' ' . sprintf(__('Depuis la box, ce nom pointe vers l\'adresse locale %s : vérifiez le certificat depuis un navigateur hors de chez vous.', __FILE__), $resolved), $items);
      }
      return self::fail($detail, $items);
    }
    if ($days < 15) {
      return self::warn(sprintf(__('Le certificat de %s expire dans %d jour(s) : vérifiez son renouvellement.', __FILE__), $host, $days), $items);
    }
    return self::pass(sprintf(__('Certificat valide pour %s, encore %d jours.', __FILE__), $host, $days), $items);
  }

  /**
   * Connexion TLS : {cert: certificat analysé ou null, error: message d'erreur}.
   * Avec $_verify, la chaîne de certificats et le nom sont contrôlés par OpenSSL.
   */
  private static function tlsConnect($_host, $_port, $_verify) {
    $context = stream_context_create(array('ssl' => array('capture_peer_cert' => true, 'verify_peer' => $_verify, 'verify_peer_name' => $_verify, 'peer_name' => $_host, 'SNI_enabled' => true)));
    // Un refus de certificat produit plusieurs avertissements (la cause, puis « Unable to connect ») : on les garde tous
    $messages = array();
    set_error_handler(function ($_no, $_message) use (&$messages) {
      $messages[] = $_message;
      return true;
    });
    $client = stream_socket_client('ssl://' . $_host . ':' . $_port, $errno, $errstr, 6, STREAM_CLIENT_CONNECT, $context);
    restore_error_handler();
    if ($client === false) {
      return array('cert' => null, 'error' => trim($errstr . ' ' . implode(' ', $messages)));
    }
    $params = stream_context_get_params($client);
    fclose($client);
    $cert = isset($params['options']['ssl']['peer_certificate']) ? openssl_x509_parse($params['options']['ssl']['peer_certificate']) : false;
    return array('cert' => ($cert === false) ? null : $cert, 'error' => '');
  }

  /* ---------------------------- Réseau (suite) ---------------------------- */

  private static function check_dangerous_services() {
    $ports = auditsecurityTools::listeningPorts();
    if (count($ports) == 0) {
      return self::skip(__('Impossible de lister les ports à l\'écoute.', __FILE__));
    }
    // Port => {nom, grave (fail) ou non (warn)}
    $dangerous = array(
      23 => array('Telnet', true), 2375 => array('Docker API', true),
      21 => array('FTP', false), 5900 => array('VNC', false), 5901 => array('VNC', false), 6379 => array('Redis', false),
      27017 => array('MongoDB', false), 111 => array('rpcbind', false), 69 => array('TFTP', false),
    );
    $found = array();
    $severe = false;
    foreach ($ports as $port) {
      if ($port['public'] && isset($dangerous[$port['port']])) {
        $found[$port['port']] = sprintf(__('Port %d', __FILE__), $port['port']) . ' : ' . $dangerous[$port['port']][0] . ($port['process'] != '' ? ' (' . $port['process'] . ')' : '');
        $severe = $severe || $dangerous[$port['port']][1];
      }
    }
    if (count($found) == 0) {
      return self::pass(__('Aucun service dangereux à l\'écoute sur le réseau.', __FILE__));
    }
    ksort($found);
    $detail = sprintf(__('%d service(s) dangereux à l\'écoute sur le réseau.', __FILE__), count($found));
    return $severe ? self::fail($detail, array_values($found)) : self::warn($detail, array_values($found));
  }

  /* ---------------------------- Système (suite) ---------------------------- */

  private static function check_reboot_required() {
    if (auditsecurityTools::isDocker()) {
      return self::skip(__('Conteneur Docker : les redémarrages concernent le système hôte.', __FILE__));
    }
    $items = array();
    if (file_exists('/var/run/reboot-required')) {
      $packages = array_filter(array_map('trim', explode("\n", (string) @file_get_contents('/var/run/reboot-required.pkgs'))));
      $items = array_slice(array_unique($packages), 0, 20);
      if (count($items) == 0) {
        $items[] = '/var/run/reboot-required';
      }
    }
    // Debian ne crée pas toujours reboot-required : on compare le noyau en cours aux noyaux installés de la même variante
    $kernel = self::newerKernel();
    if ($kernel !== null) {
      $items[] = $kernel;
    }
    if (count($items) == 0) {
      return self::pass(__('Aucun redémarrage en attente.', __FILE__));
    }
    return self::warn(__('Des mises à jour attendent un redémarrage pour être appliquées.', __FILE__), $items);
  }

  /** Description du noyau plus récent installé que celui en cours, ou null. */
  private static function newerKernel() {
    $running = php_uname('r');
    $pattern = '/^(\d+(?:\.\d+)+(?:-\d+)?)(.*)$/';
    if (!preg_match($pattern, $running, $current)) {
      return null;
    }
    $sameFlavor = 0;
    $newest = null;
    foreach (glob('/lib/modules/*', GLOB_ONLYDIR) ?: array() as $dir) {
      $version = basename($dir);
      // Même variante uniquement (ex. -amd64, +rpt-rpi-v8) : un Raspberry Pi installe plusieurs variantes en parallèle
      if (!preg_match($pattern, $version, $other) || $other[2] !== $current[2]) {
        continue;
      }
      $sameFlavor++;
      if (version_compare(str_replace('-', '.', $other[1]), str_replace('-', '.', $current[1]), '>') && ($newest === null || version_compare(str_replace('-', '.', $other[1]), str_replace('-', '.', $newest), '>'))) {
        $newest = $version;
      }
    }
    if ($newest !== null) {
      return sprintf(__('Noyau %s installé, noyau %s en cours d\'exécution', __FILE__), $newest, $running);
    }
    if ($sameFlavor > 0 && !is_dir('/lib/modules/' . $running)) {
      return sprintf(__('Les modules du noyau en cours (%s) ont été supprimés par une mise à jour', __FILE__), $running);
    }
    return null;
  }

  /* ---------------------------- Résilience ---------------------------- */

  private static function check_backup_recent() {
    $latest = 0;
    foreach (array_keys(jeedom::listBackup()) as $file) {
      $latest = max($latest, (int) @filemtime($file));
    }
    if ($latest == 0) {
      return self::fail(__('Aucune sauvegarde trouvée sur la box.', __FILE__));
    }
    $days = floor((time() - $latest) / 86400);
    $detail = sprintf(__('Dernière sauvegarde le %s (il y a %d jour(s)).', __FILE__), date('d/m/Y H:i', $latest), $days);
    if ($days > 30) {
      return self::fail($detail);
    }
    if ($days > 7) {
      return self::warn($detail);
    }
    return self::pass($detail);
  }

  private static function fix_backup_recent() {
    jeedom::backup(true);
    return __('Sauvegarde lancée en tâche de fond (suivez-la dans le log backup).', __FILE__);
  }

  private static function check_backup_offsite() {
    $targets = array();
    foreach (update::listRepo() as $key => $repo) {
      if (!isset($repo['scope']['backup']) || $repo['scope']['backup'] === false) {
        continue;
      }
      if (config::byKey($key . '::enable') == 1 && config::byKey($key . '::cloudUpload') == 1) {
        $targets[] = $repo['name'];
      }
    }
    $path = config::byKey('backup::path');
    if (count($targets) > 0) {
      return self::pass(__('Les sauvegardes sont envoyées vers :', __FILE__) . ' ' . implode(', ', $targets), $targets);
    }
    if (substr($path, 0, 1) == '/' && strpos(realpath($path) ?: $path, auditsecurityTools::jeedomRoot()) !== 0) {
      return self::info(sprintf(__('Aucun envoi distant, mais les sauvegardes sont stockées dans %s : vérifiez qu\'il s\'agit d\'un support externe.', __FILE__), $path));
    }
    return self::warn(__('Les sauvegardes ne sont stockées que sur la box.', __FILE__));
  }

  private static function check_disk_space() {
    $root = auditsecurityTools::jeedomRoot();
    $free = @disk_free_space($root);
    $total = @disk_total_space($root);
    if (!$free || !$total) {
      return self::skip(__('Impossible de lire l\'espace disque.', __FILE__));
    }
    $percent = round($free / $total * 100);
    $freeGb = $free / 1073741824;
    $detail = sprintf(__('%d %% libre (%s sur %s).', __FILE__), $percent, sizeFormat($free), sizeFormat($total));
    if ($freeGb < 0.5 || ($percent < 5 && $freeGb < 2)) {
      return self::fail($detail);
    }
    if ($percent < 15 && $freeGb < 10) {
      return self::warn($detail);
    }
    return self::pass($detail);
  }
}
