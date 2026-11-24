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

/**
 * Outils communs aux contrôles : commandes système, requêtes HTTP locales, lecture de fichiers.
 * Toutes les commandes sont lancées avec un délai maximal pour ne jamais bloquer l'audit.
 */
class auditsecurityTools {

  private static $cache = array();

  /** Racine de l'installation Jeedom (ex. /var/www/html). */
  public static function jeedomRoot() {
    return realpath(__DIR__ . '/../../../..');
  }

  /** Préfixe sudo de Jeedom ('sudo ' ou '' si sudo n'est pas disponible). */
  public static function sudo() {
    if (!isset(self::$cache['sudo'])) {
      self::$cache['sudo'] = system::getCmdSudo();
    }
    return self::$cache['sudo'];
  }

  /** Vrai si les commandes root sont possibles (root ou sudo sans mot de passe). */
  public static function canRoot() {
    if (!isset(self::$cache['canRoot'])) {
      if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        self::$cache['canRoot'] = true;
      } else {
        $res = self::exec('sudo -n true', 5);
        self::$cache['canRoot'] = ($res['code'] === 0);
      }
    }
    return self::$cache['canRoot'];
  }

  /** Vrai si un exécutable est présent dans le PATH (ou les sbin, souvent absents du PATH de www-data). */
  public static function hasBinary($_name) {
    $key = 'bin::' . $_name;
    if (!isset(self::$cache[$key])) {
      $res = self::exec('command -v ' . escapeshellarg($_name) . ' || ls /usr/sbin/' . escapeshellarg($_name) . ' /sbin/' . escapeshellarg($_name) . ' 2>/dev/null', 5);
      self::$cache[$key] = (trim($res['output']) !== '');
    }
    return self::$cache[$key];
  }

  /** Vrai si Jeedom tourne dans Docker (pas de systemd, pas de SSH ni de pare-feu à gérer). */
  public static function isDocker() {
    if (!isset(self::$cache['docker'])) {
      self::$cache['docker'] = (jeedom::getHardwareName() == 'docker' || file_exists('/.dockerenv'));
    }
    return self::$cache['docker'];
  }

  /**
   * Lance une commande shell avec délai maximal.
   * @return array {code: int, output: string}
   */
  public static function exec($_cmd, $_timeout = 15, $_stdin = null) {
    $cmd = 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; ';
    if (!isset(self::$cache['timeout'])) {
      self::$cache['timeout'] = (trim((string) shell_exec($cmd . 'command -v timeout 2>/dev/null')) !== '');
    }
    if (self::$cache['timeout'] && is_numeric($_timeout) && $_timeout > 0) {
      $cmd .= 'timeout ' . intval($_timeout) . ' sh -c ' . escapeshellarg($_cmd);
    } else {
      $cmd .= $_cmd;
    }
    $descriptors = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
    $process = proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($process)) {
      return array('code' => -1, 'output' => '');
    }
    if ($_stdin !== null) {
      fwrite($pipes[0], $_stdin);
    }
    fclose($pipes[0]);
    $start = microtime(true);
    $output = stream_get_contents($pipes[1]);
    $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($process);
    self::debug('exec [' . $code . ', ' . round((microtime(true) - $start) * 1000) . ' ms] ' . $_cmd . ' => '
      . (self::isSensitive($_cmd) ? '(sortie masquée : données sensibles)' : self::excerpt($output . ($errors != '' ? ' | stderr: ' . $errors : ''))));
    return array('code' => $code, 'output' => (string) $output);
  }

  /* ---------------------------- Mode debug ---------------------------- */

  /** Trace en niveau Debug (le core ne l'écrit que si le log du plugin est en Debug). */
  public static function debug($_message) {
    if (!isset(self::$cache['debug'])) {
      self::$cache['debug'] = (intval(log::getLogLevel('auditsecurity')) == 100);
    }
    if (self::$cache['debug']) {
      log::add('auditsecurity', 'debug', $_message);
    }
  }

  /** Vrai si la sortie de la commande peut contenir des secrets (empreintes de mots de passe, mot de passe de la base). */
  private static function isSensitive($_cmd) {
    return (bool) preg_match('#shadow|common\.config|passwd|password|\.key\b|secret#i', $_cmd);
  }

  /** Extrait d'une sortie, sur une ligne et limité en longueur, pour le log. */
  private static function excerpt($_text, $_max = 600) {
    $text = self::utf8((string) $_text);
    $text = trim((string) preg_replace('/\s*\n\s*/u', ' ⏎ ', $text));
    if (function_exists('mb_strlen') && mb_strlen($text, 'UTF-8') > $_max) {
      return mb_substr($text, 0, $_max, 'UTF-8') . '… (' . strlen($text) . ' octets)';
    }
    return $text;
  }

  /**
   * Texte en UTF-8 valide : les octets invalides (sortie de commande non UTF-8, chaîne coupée) sont remplacés.
   * Indispensable avant toute expression régulière en mode /u, qui renverrait null sinon.
   */
  public static function utf8($_text) {
    $text = (string) $_text;
    if (function_exists('mb_scrub')) {
      return mb_scrub($text, 'UTF-8');
    }
    if (function_exists('iconv')) {
      $clean = @iconv('UTF-8', 'UTF-8//IGNORE', $text);
      return ($clean === false) ? $text : $clean;
    }
    return $text;
  }

  /** Lance une commande en root (via sudo si besoin). */
  public static function execRoot($_cmd, $_timeout = 15, $_stdin = null) {
    return self::exec(self::sudo() . $_cmd, $_timeout, $_stdin);
  }

  /** Lit un fichier, en root si la lecture directe échoue. Retourne null si illisible. */
  public static function readFile($_path, $_asRoot = false) {
    if (!$_asRoot && is_readable($_path)) {
      $content = @file_get_contents($_path);
      return ($content === false) ? null : $content;
    }
    if (!self::canRoot()) {
      return null;
    }
    $res = self::execRoot('cat ' . escapeshellarg($_path), 5);
    return ($res['code'] === 0) ? $res['output'] : null;
  }

  /** Écrit un fichier système en root (via un fichier temporaire puis install). */
  public static function writeRootFile($_path, $_content, $_mode = '0644') {
    $tmp = tempnam(jeedom::getTmpFolder('auditsecurity'), 'as_');
    file_put_contents($tmp, $_content);
    $res = self::execRoot('install -m ' . escapeshellarg($_mode) . ' -o root -g root ' . escapeshellarg($tmp) . ' ' . escapeshellarg($_path), 10);
    @unlink($tmp);
    if ($res['code'] !== 0) {
      throw new Exception(__('Impossible d\'écrire le fichier', __FILE__) . ' ' . $_path);
    }
  }

  /** URL locale de l'interface Jeedom (ex. http://127.0.0.1:80). */
  public static function localUrl() {
    if (!isset(self::$cache['localUrl'])) {
      self::$cache['localUrl'] = rtrim(network::getNetworkAccess('internal', 'proto:127.0.0.1:port:comp'), '/');
    }
    return self::$cache['localUrl'];
  }

  /**
   * Requête HTTP GET sur l'interface locale.
   * @return array|null {code: int, headers: array (clés en minuscules), body: string} ou null si injoignable
   */
  public static function httpGet($_path, $_maxBody = 65536) {
    if (!function_exists('curl_init')) {
      return null;
    }
    $headers = array();
    $ch = curl_init(self::localUrl() . '/' . ltrim($_path, '/'));
    curl_setopt_array($ch, array(
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_TIMEOUT => 8,
      CURLOPT_CONNECTTIMEOUT => 4,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_SSL_VERIFYHOST => 0,
      CURLOPT_RANGE => '0-' . ($_maxBody - 1),
      CURLOPT_HEADERFUNCTION => function ($_ch, $_line) use (&$headers) {
        $parts = explode(':', $_line, 2);
        if (count($parts) == 2) {
          $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
        }
        return strlen($_line);
      },
    ));
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    if (PHP_VERSION_ID < 80000) {
      curl_close($ch); // sans effet depuis PHP 8, déprécié en 8.5
    }
    self::debug('GET ' . self::localUrl() . '/' . ltrim($_path, '/') . ' => ' . (($body === false || $code === 0) ? 'échec ' . $error : $code . ' (' . strlen((string) $body) . ' octets)'));
    if ($body === false || $code === 0) {
      return null;
    }
    return array('code' => $code, 'headers' => $headers, 'body' => (string) $body);
  }

  /**
   * Ports TCP en écoute.
   * @return array liste de {address, port, process, public (bool : écoute hors boucle locale)}
   */
  public static function listeningPorts() {
    if (isset(self::$cache['ports'])) {
      return self::$cache['ports'];
    }
    $ports = array();
    $res = self::canRoot() ? self::execRoot('ss -H -ltnp', 10) : self::exec('ss -H -ltn', 10);
    if ($res['code'] !== 0 && trim($res['output']) === '') {
      $res = self::exec('ss -H -ltn', 10);
    }
    foreach (explode("\n", $res['output']) as $line) {
      $cols = preg_split('/\s+/', trim($line));
      if (count($cols) < 4) {
        continue;
      }
      $local = $cols[3];
      $pos = strrpos($local, ':');
      if ($pos === false) {
        continue;
      }
      $address = trim(substr($local, 0, $pos), '[]');
      $address = preg_replace('/%.*$/', '', $address);
      $port = (int) substr($local, $pos + 1);
      $process = '';
      if (preg_match('/users:\(\("([^"]+)"/', $line, $m)) {
        $process = $m[1];
      }
      $loopback = (strpos($address, '127.') === 0 || $address === '::1' || $address === 'localhost');
      $ports[$address . ':' . $port] = array('address' => $address, 'port' => $port, 'process' => $process, 'public' => !$loopback);
    }
    self::$cache['ports'] = array_values($ports);
    return self::$cache['ports'];
  }

  /** Ports publics (hors boucle locale) pour un numéro de port donné. */
  public static function isPortPublic($_port) {
    foreach (self::listeningPorts() as $port) {
      if ($port['port'] == $_port && $port['public']) {
        return true;
      }
    }
    return false;
  }

  /** Informations de /etc/os-release. */
  public static function osRelease() {
    if (!isset(self::$cache['os'])) {
      $os = array();
      $content = @file_get_contents('/etc/os-release');
      foreach (explode("\n", (string) $content) as $line) {
        if (preg_match('/^([A-Z_]+)=(.*)$/', trim($line), $m)) {
          $os[$m[1]] = trim($m[2], '"\'');
        }
      }
      self::$cache['os'] = $os;
    }
    return self::$cache['os'];
  }

  /** État d'un service systemd : 'active', 'inactive', 'failed', 'unknown' (absent ou systemd indisponible). */
  public static function serviceState($_service) {
    if (!self::hasBinary('systemctl')) {
      return 'unknown';
    }
    $res = self::exec('systemctl is-active ' . escapeshellarg($_service), 5);
    $state = trim($res['output']);
    if ($state === 'active' || $state === 'failed') {
      return $state;
    }
    $res = self::exec('systemctl list-unit-files ' . escapeshellarg($_service . '.service') . ' --no-legend', 5);
    return (trim($res['output']) === '') ? 'unknown' : 'inactive';
  }

  /* ---------------------------- Réseau local et Internet ---------------------------- */

  /** Adresses IPv4 de la box Jeedom sur le réseau local. */
  public static function localIps() {
    if (!isset(self::$cache['localIps'])) {
      $ips = array();
      $res = self::exec('hostname -I', 5);
      foreach (preg_split('/\s+/', trim($res['output'])) as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && strpos($ip, '127.') !== 0) {
          $ips[] = $ip;
        }
      }
      $internal = network::getNetworkAccess('internal', 'ip', '', false);
      if (filter_var($internal, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ips[] = $internal;
      }
      self::$cache['localIps'] = array_values(array_unique($ips));
    }
    return self::$cache['localIps'];
  }

  /** Vrai si l'adresse IPv4 n'est pas routable sur Internet (privée, CGNAT, boucle locale...). */
  public static function isNonPublicIp($_ip) {
    if (!filter_var($_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      return true;
    }
    // 100.64.0.0/10 : NAT de l'opérateur (CGNAT), non filtré par FILTER_FLAG_NO_PRIV_RANGE
    $long = ip2long($_ip);
    if (($long & 0xFFC00000) === (ip2long('100.64.0.0') & 0xFFC00000)) {
      return true;
    }
    return !filter_var($_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
  }

  /** Requête HTTP GET vers un service externe. Retourne {code, body} ou null. */
  public static function httpGetExternal($_url, $_timeout = 8) {
    if (!function_exists('curl_init')) {
      return null;
    }
    $ch = curl_init($_url);
    curl_setopt_array($ch, array(
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_MAXREDIRS => 2,
      CURLOPT_TIMEOUT => $_timeout,
      CURLOPT_CONNECTTIMEOUT => 5,
      CURLOPT_USERAGENT => 'Jeedom-AuditSecurity',
    ));
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    if (PHP_VERSION_ID < 80000) {
      curl_close($ch);
    }
    self::debug('GET ' . $_url . ' => ' . (($body === false || $code === 0) ? 'échec ' . $error : $code . ' : ' . self::excerpt($body, 300)));
    return ($body === false || $code === 0) ? null : array('code' => $code, 'body' => (string) $body);
  }

  /**
   * Routeur Internet compatible UPnP (IGD), découvert par SSDP sur le réseau local.
   * @return array|null {location, controlUrl, serviceType, name} ou null si aucun routeur ne répond
   */
  public static function upnpGateway() {
    if (array_key_exists('upnp', self::$cache)) {
      return self::$cache['upnp'];
    }
    self::$cache['upnp'] = null;
    $socket = @stream_socket_server('udp://0.0.0.0:0', $errno, $errstr, STREAM_SERVER_BIND);
    if ($socket === false) {
      return null;
    }
    $targets = array('urn:schemas-upnp-org:device:InternetGatewayDevice:1', 'urn:schemas-upnp-org:device:InternetGatewayDevice:2', 'urn:schemas-upnp-org:service:WANIPConnection:1');
    foreach ($targets as $target) {
      $message = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: " . $target . "\r\n\r\n";
      @stream_socket_sendto($socket, $message, 0, '239.255.255.250:1900');
    }
    $locations = array();
    $end = microtime(true) + 3;
    while (($left = $end - microtime(true)) > 0) {
      $read = array($socket);
      $write = $except = null;
      if (!@stream_select($read, $write, $except, 0, (int) ($left * 1000000))) {
        break;
      }
      $response = @stream_socket_recvfrom($socket, 2048);
      if ($response && preg_match('/^LOCATION:\s*(\S+)/mi', $response, $m)) {
        $locations[$m[1]] = true;
      }
    }
    fclose($socket);
    self::debug('UPnP : ' . count($locations) . ' réponse(s) SSDP' . (count($locations) > 0 ? ' : ' . implode(', ', array_keys($locations)) : ''));
    foreach (array_keys($locations) as $location) {
      $res = self::httpGetExternal($location, 5);
      if ($res === null || $res['code'] != 200) {
        continue;
      }
      $xml = @simplexml_load_string($res['body']);
      if ($xml === false) {
        continue;
      }
      $base = isset($xml->URLBase) && trim((string) $xml->URLBase) != '' ? trim((string) $xml->URLBase) : $location;
      $name = isset($xml->device->friendlyName) ? (string) $xml->device->friendlyName : '';
      // Recherche du service de connexion WAN dans l'arbre des périphériques
      foreach ($xml->xpath('//*[local-name()="service"]') as $service) {
        $type = (string) $service->serviceType;
        if (preg_match('/WAN(IP|PPP)Connection/', $type)) {
          self::$cache['upnp'] = array(
            'location' => $location,
            'controlUrl' => self::resolveUrl($base, (string) $service->controlURL),
            'serviceType' => $type,
            'name' => $name,
          );
          return self::$cache['upnp'];
        }
      }
    }
    return null;
  }

  private static function resolveUrl($_base, $_path) {
    if (preg_match('#^https?://#i', $_path)) {
      return $_path;
    }
    $parts = parse_url($_base);
    $root = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
    return $root . '/' . ltrim($_path, '/');
  }

  /**
   * Appel SOAP d'une action UPnP du routeur.
   * @return array|null valeurs de la réponse (NewXxx => valeur) ou null en cas d'erreur
   */
  public static function upnpCall($_gateway, $_action, $_args = array()) {
    $args = '';
    foreach ($_args as $key => $value) {
      $args .= '<' . $key . '>' . htmlspecialchars((string) $value, ENT_XML1) . '</' . $key . '>';
    }
    $body = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
      . '<u:' . $_action . ' xmlns:u="' . $_gateway['serviceType'] . '">' . $args . '</u:' . $_action . '></s:Body></s:Envelope>';
    $ch = curl_init($_gateway['controlUrl']);
    curl_setopt_array($ch, array(
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $body,
      CURLOPT_TIMEOUT => 5,
      CURLOPT_CONNECTTIMEOUT => 3,
      CURLOPT_HTTPHEADER => array('Content-Type: text/xml; charset="utf-8"', 'SOAPAction: "' . $_gateway['serviceType'] . '#' . $_action . '"'),
    ));
    $response = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if (PHP_VERSION_ID < 80000) {
      curl_close($ch);
    }
    if ($response === false || $code != 200) {
      self::debug('UPnP ' . $_action . ' => HTTP ' . $code);
      return null;
    }
    $values = array();
    preg_match_all('#<(New\w+)>(.*?)</\1>#s', $response, $matches, PREG_SET_ORDER);
    foreach ($matches as $match) {
      $values[$match[1]] = html_entity_decode($match[2], ENT_QUOTES | ENT_XML1);
    }
    return $values;
  }

  /** Redirections de ports ouvertes sur le routeur par UPnP (liste de {external, internal, client, protocol, description}). */
  public static function upnpMappings() {
    if (isset(self::$cache['upnpMappings'])) {
      return self::$cache['upnpMappings'];
    }
    $mappings = array();
    $gateway = self::upnpGateway();
    if ($gateway !== null) {
      for ($i = 0; $i < 200; $i++) {
        $entry = self::upnpCall($gateway, 'GetGenericPortMappingEntry', array('NewPortMappingIndex' => $i));
        if ($entry === null || !isset($entry['NewExternalPort'])) {
          break;
        }
        if (isset($entry['NewEnabled']) && $entry['NewEnabled'] == '0') {
          continue;
        }
        $mappings[] = array(
          'external' => (int) $entry['NewExternalPort'],
          'internal' => isset($entry['NewInternalPort']) ? (int) $entry['NewInternalPort'] : 0,
          'client' => isset($entry['NewInternalClient']) ? $entry['NewInternalClient'] : '',
          'protocol' => isset($entry['NewProtocol']) ? $entry['NewProtocol'] : '',
          'description' => isset($entry['NewPortMappingDescription']) ? $entry['NewPortMappingDescription'] : '',
        );
      }
    }
    self::$cache['upnpMappings'] = $mappings;
    return $mappings;
  }

  /**
   * IP publique de la connexion Internet : d'abord demandée au routeur (UPnP), sinon à api.ipify.org
   * si les services externes sont autorisés.
   * @return array {ip, source} ou null
   */
  public static function publicIp($_allowExternal) {
    $gateway = self::upnpGateway();
    if ($gateway !== null) {
      $res = self::upnpCall($gateway, 'GetExternalIPAddress');
      if (isset($res['NewExternalIPAddress']) && filter_var($res['NewExternalIPAddress'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return array('ip' => $res['NewExternalIPAddress'], 'source' => 'upnp');
      }
    }
    if ($_allowExternal) {
      $res = self::httpGetExternal('https://api.ipify.org', 6);
      if ($res !== null && $res['code'] == 200 && filter_var(trim($res['body']), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return array('ip' => trim($res['body']), 'source' => 'ipify');
      }
    }
    return null;
  }

  /**
   * Tente une connexion MQTT 3.1.1 anonyme (sans identifiant) puis se déconnecte aussitôt.
   * Rien n'est publié ni lu : seule la réponse CONNACK du broker est examinée.
   * @return array {result: 'accepted'|'refused'|'error', code: code de retour CONNACK ou null}
   */
  public static function mqttAnonymousTest($_host, $_port) {
    $address = (strpos($_host, ':') !== false) ? '[' . $_host . ']' : $_host;
    $socket = @stream_socket_client('tcp://' . $address . ':' . intval($_port), $errno, $errstr, 3);
    if ($socket === false) {
      self::debug('MQTT ' . $_host . ':' . $_port . ' => connexion impossible (' . $errstr . ')');
      return array('result' => 'error', 'code' => null);
    }
    stream_set_timeout($socket, 3);
    $clientId = 'auditsecurity-' . bin2hex(random_bytes(3));
    // En-tête variable : nom du protocole, niveau 4 (3.1.1), drapeaux = session propre sans identifiant, keepalive 10 s
    $body = "\x00\x04MQTT\x04\x02\x00\x0A" . pack('n', strlen($clientId)) . $clientId;
    @fwrite($socket, "\x10" . chr(strlen($body)) . $body);
    $response = @fread($socket, 4);
    if (strlen((string) $response) == 4 && ord($response[0]) == 0x20) {
      $code = ord($response[3]);
      if ($code == 0) {
        @fwrite($socket, "\xE0\x00"); // DISCONNECT propre
      }
      fclose($socket);
      self::debug('MQTT ' . $_host . ':' . $_port . ' => CONNACK code ' . $code);
      // 0 : acceptée ; 4 : identifiants invalides ; 5 : non autorisé
      return array('result' => ($code == 0) ? 'accepted' : (($code == 4 || $code == 5) ? 'refused' : 'error'), 'code' => $code);
    }
    fclose($socket);
    self::debug('MQTT ' . $_host . ':' . $_port . ' => pas de CONNACK (' . strlen((string) $response) . ' octets reçus)');
    return array('result' => 'error', 'code' => null);
  }

  /** Vide le cache (utile entre deux audits lancés dans le même processus). */
  public static function resetCache() {
    self::$cache = array();
  }
}
