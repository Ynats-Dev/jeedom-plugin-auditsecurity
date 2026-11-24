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

require_once __DIR__ . '/../../../../core/php/core.inc.php';
require_once __DIR__ . '/auditsecurityTools.class.php';
require_once __DIR__ . '/auditsecurityChecks.class.php';

/**
 * Audit de sécurité de l'installation Jeedom.
 *
 * Le dernier rapport est stocké dans la configuration du plugin (clé « report ») sous forme brute :
 * {date, duration, results: {<id>: {status, detail, items, noFix}}}. La note est recalculée à chaque
 * lecture, ce qui permet d'ignorer un contrôle (clé « ignored ») sans relancer l'audit.
 * Un contrôle peut être ignoré pour une durée limitée ({<id>: {since, until, by}}, until null = sans limite)
 * et porter un commentaire (clé « comments » : {<id>: {text, date, by}}).
 *
 * Un équipement unique (logicalId « audit ») porte les commandes utilisables dans les scénarios :
 * note, lettre, nombre de problèmes, date du dernier audit et action « Lancer l'audit ».
 */
class auditsecurity extends eqLogic {

  const LOGICAL_ID = 'audit';

  /** Poids de chaque sévérité dans la note */
  const WEIGHTS = array('critical' => 20, 'high' => 10, 'medium' => 5, 'low' => 2, 'info' => 0);

  /** Seuils des lettres (note minimale) */
  const GRADES = array('A' => 90, 'B' => 80, 'C' => 65, 'D' => 50, 'E' => 35, 'F' => 0);

  public static $_widgetPossibility = array('custom' => true);

  /* ************************************************************************************ */
  /*                                   Cron                                               */
  /* ************************************************************************************ */

  public static function cronDaily() {
    // Contrôles dont la période d'ignorance est terminée : ils reviennent dans la note
    if (self::purgeExpiredIgnored() > 0) {
      self::updateCommands(self::getReport());
    }
    $frequency = config::byKey('autoAudit', __CLASS__, 'daily');
    if ($frequency == 'daily' || ($frequency == 'weekly' && date('N') == 1)) {
      try {
        self::runAudit('cron');
      } catch (Throwable $e) {
        log::add(__CLASS__, 'error', __('Audit automatique en échec :', __FILE__) . ' ' . $e->getMessage());
      }
    }
  }

  /* ************************************************************************************ */
  /*                                   Audit                                              */
  /* ************************************************************************************ */

  /** Lance tous les contrôles, enregistre le rapport et met à jour les commandes. */
  public static function runAudit($_source = 'manual') {
    if (cache::byKey('auditsecurity::running')->getValue(0) == 1) {
      throw new Exception(__('Un audit est déjà en cours, patientez quelques secondes.', __FILE__));
    }
    cache::set('auditsecurity::running', 1, 300);
    try {
      $start = microtime(true);
      auditsecurityTools::resetCache();
      log::add(__CLASS__, 'info', 'Début de l\'audit (' . $_source . ')');
      self::purgeExpiredIgnored();
      $previous = self::getReport();
      $results = array();
      if (self::isDebug()) {
        log::add(__CLASS__, 'debug', 'Environnement : ' . self::environmentSummary());
      }
      foreach (array_keys(auditsecurityChecks::definitions()) as $id) {
        $results[$id] = self::runCheck($id);
      }
      $raw = array(
        'date' => date('Y-m-d H:i:s'),
        'duration' => round(microtime(true) - $start, 1),
        'results' => $results,
      );
      config::save('report', json_encode($raw, JSON_UNESCAPED_UNICODE), __CLASS__);
      $report = self::getReport();
      // Le verrou n'est levé que dans le finally : le rapport renvoyé ne doit pas se dire « en cours »
      $report['running'] = false;
      log::add(__CLASS__, 'info', 'Audit terminé en ' . $raw['duration'] . ' s : ' . $report['score'] . ' % (' . $report['grade'] . ')');
      self::notifyChanges($previous, $report);
      self::updateCommands($report);
      return $report;
    } finally {
      cache::set('auditsecurity::running', 0);
    }
  }

  /** Exécute un contrôle en mesurant sa durée (visible dans le diagnostic et le log debug). */
  private static function runCheck($_id) {
    $start = microtime(true);
    log::add(__CLASS__, 'debug', '[' . $_id . '] début');
    $result = auditsecurityChecks::run($_id);
    $result['ms'] = (int) round((microtime(true) - $start) * 1000);
    log::add(__CLASS__, 'debug', '[' . $_id . '] ' . $result['status'] . ' en ' . $result['ms'] . ' ms : ' . $result['detail']
      . (count($result['items']) > 0 ? ' | ' . implode(' ; ', array_slice($result['items'], 0, 20)) : ''));
    return $result;
  }

  /* ************************************************************************************ */
  /*                                   Mode debug et diagnostic                           */
  /* ************************************************************************************ */

  /** Vrai si le log du plugin est en niveau Debug (réglage « Logs et surveillance » de la configuration). */
  public static function isDebug() {
    return intval(log::getLogLevel(__CLASS__)) == 100;
  }

  /** Version du plugin, lue dans plugin_info/info.json. */
  private static function pluginVersion() {
    $info = json_decode((string) @file_get_contents(__DIR__ . '/../../plugin_info/info.json'), true);
    return isset($info['pluginVersion']) ? $info['pluginVersion'] : '?';
  }

  /** Résumé de l'environnement d'exécution (une ligne). */
  private static function environmentSummary() {
    $os = auditsecurityTools::osRelease();
    return 'plugin ' . self::pluginVersion() . ', Jeedom ' . jeedom::version() . ' (' . jeedom::getHardwareName() . ')'
      . ', ' . (isset($os['PRETTY_NAME']) ? $os['PRETTY_NAME'] : php_uname('s')) . ', noyau ' . php_uname('r') . ' ' . php_uname('m')
      . ', PHP ' . PHP_VERSION . ' (' . PHP_SAPI . ')'
      . ', root ' . (auditsecurityTools::canRoot() ? 'oui' : 'non') . ', Docker ' . (auditsecurityTools::isDocker() ? 'oui' : 'non');
  }

  /**
   * Rapport de diagnostic à joindre à une demande d'aide : environnement, options, résultat brut de chaque
   * contrôle et fin du log du plugin. Les données personnelles sont masquées (IP publiques, domaine externe,
   * comptes, adresses e-mail).
   */
  public static function getDiagnostic() {
    $start = microtime(true);
    $steps = array();
    // Chaque étape est écrite dans le log (mode debug) et renvoyée à la page pour la barre de progression
    $step = function ($_label) use ($start, &$steps) {
      $ms = (int) round((microtime(true) - $start) * 1000);
      $steps[] = array('label' => $_label, 'ms' => $ms);
      log::add('auditsecurity', 'debug', 'Diagnostic : ' . $_label . ' (' . $ms . ' ms)');
    };
    $step('début');
    auditsecurityTools::resetCache();
    $raw = self::getRawReport();
    $report = self::getReport();
    $step('rapport chargé (' . ($raw === null ? 'aucun audit' : count($report['checks']) . ' contrôles') . ')');
    $lines = array();
    $lines[] = '=== Audit Sécurité - rapport de diagnostic ===';
    $lines[] = 'Généré le ' . date('Y-m-d H:i:s');
    $lines[] = 'Environnement : ' . self::environmentSummary();
    $lines[] = 'Options : audit automatique ' . config::byKey('autoAudit', __CLASS__, 'daily')
      . ', notifications ' . config::byKey('notifyNew', __CLASS__, 1)
      . ', services externes ' . config::byKey('externalChecks', __CLASS__, 0)
      . ', debug ' . (self::isDebug() ? 'oui' : 'non');
    $lines[] = 'Accès externe déclaré : ' . (trim(config::byKey('externalAddr')) != '' ? 'oui (' . config::byKey('externalProtocol') . ')' : 'non')
      . ', DNS Jeedom ' . (config::byKey('market::allowDNS') == 1 ? 'oui' : 'non');
    $step('environnement décrit');
    if ($raw === null) {
      $lines[] = 'Aucun audit enregistré.';
    } else {
      $lines[] = 'Dernier audit : ' . $raw['date'] . ' en ' . $raw['duration'] . ' s, note ' . $report['score'] . ' % (' . $report['grade'] . ')';
      $lines[] = '';
      $lines[] = '=== Contrôles ===';
      foreach ($report['checks'] as $check) {
        $result = isset($raw['results'][$check['id']]) ? $raw['results'][$check['id']] : array();
        $lines[] = sprintf('[%s] %s%s%s : %s', $check['id'], $check['status'], $check['ignored'] ? ' (ignoré)' : '',
          isset($result['ms']) ? ' ' . $result['ms'] . ' ms' : '', $check['detail']);
        foreach ($check['items'] as $item) {
          $lines[] = '    - ' . $item;
        }
      }
    }
    $lines[] = '';
    $lines[] = '=== Fin du log auditsecurity ===';
    $log = log::getPathToLog(__CLASS__);
    if (file_exists($log)) {
      $content = (string) @file_get_contents($log);
      $tail = array_slice(explode("\n", rtrim($content)), -300);
      $lines = array_merge($lines, $tail);
      $step('log lu (' . strlen($content) . ' octets, ' . count($tail) . ' lignes gardées)');
    } else {
      $lines[] = 'Log absent (passez le log du plugin en Debug puis relancez l\'audit pour obtenir un log détaillé).';
      $step('log absent');
    }
    $text = self::redact(implode("\n", $lines)) . "\n";
    $step('données personnelles masquées');
    $step('terminé, ' . strlen($text) . ' octets renvoyés');
    return array('text' => $text, 'steps' => $steps);
  }

  /** Masque les données personnelles d'un texte destiné à être partagé. */
  private static function redact($_text) {
    // UTF-8 valide d'abord : sinon les expressions en mode /u renvoient null et le texte serait perdu
    $text = auditsecurityTools::utf8($_text);
    // Applique une expression ; en cas d'échec (erreur PCRE), garde le texte précédent et le signale dans le log
    $apply = function ($_text, $_pattern, $_replacement) {
      $result = is_callable($_replacement) ? preg_replace_callback($_pattern, $_replacement, $_text) : preg_replace($_pattern, $_replacement, $_text);
      if ($result === null) {
        log::add('auditsecurity', 'error', 'Diagnostic : masquage impossible (' . (function_exists('preg_last_error_msg') ? preg_last_error_msg() : preg_last_error()) . ')');
        return $_text;
      }
      return $result;
    };
    // Domaine de l'accès externe
    $external = preg_replace('#[/:].*$#', '', trim(config::byKey('externalAddr')));
    if ($external != '') {
      $text = str_ireplace($external, '[domaine-externe]', $text);
    }
    // Identifiants des comptes Jeedom (les comptes génériques restent visibles, ils aident au diagnostic)
    $number = 0;
    foreach (user::all() as $user) {
      $login = $user->getLogin();
      if (strlen($login) < 3 || in_array(strtolower($login), array('admin', 'root', 'jeedom', 'pi', 'jeedom_support', 'internal_report'))) {
        continue;
      }
      $number++;
      $text = $apply($text, '/(?<![\w.-])' . preg_quote($login, '/') . '(?![\w-])/u', '[compte-' . $number . ']');
    }
    // Adresses e-mail (quantificateurs possessifs : pas de retour arrière coûteux sur les longs mots)
    $text = $apply($text, '/[\w.+-]++@[\w-]++(?:\.[\w-]++)+/u', '[email]');
    // Adresses IPv4 publiques (les adresses locales restent utiles au diagnostic)
    $text = $apply($text, '/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', function ($_m) {
      return (filter_var($_m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !auditsecurityTools::isNonPublicIp($_m[1])) ? '[ip-publique]' : $_m[1];
    });
    return $text;
  }

  /** Relance un seul contrôle (après une correction) et met à jour le rapport. */
  public static function rerunCheck($_id) {
    $raw = self::getRawReport();
    if ($raw === null) {
      return self::runAudit('manual');
    }
    auditsecurityTools::resetCache();
    $raw['results'][$_id] = self::runCheck($_id);
    config::save('report', json_encode($raw, JSON_UNESCAPED_UNICODE), __CLASS__);
    $report = self::getReport();
    self::updateCommands($report);
    return $report;
  }

  /** Applique la correction automatique d'un contrôle puis le revérifie. */
  public static function applyFix($_id) {
    $definitions = auditsecurityChecks::definitions();
    if (!isset($definitions[$_id]) || !is_array($definitions[$_id]['fix']) || $definitions[$_id]['fix']['type'] != 'auto') {
      throw new Exception(__('Aucune correction automatique pour ce contrôle', __FILE__) . ' : ' . $_id);
    }
    $message = auditsecurityChecks::fix($_id);
    return array('message' => $message, 'report' => self::rerunCheck($_id));
  }

  /** Durées proposées pour ignorer un contrôle, en jours (0 = sans limite). */
  const IGNORE_DAYS = array(7, 30, 90, 365, 0);

  /** Longueur maximale d'un commentaire */
  const COMMENT_MAX = 1000;

  /**
   * Ignore (risque accepté) ou réintègre un contrôle dans la note.
   * $_days : durée en jours (0 = sans limite). $_comment : raison facultative, enregistrée comme commentaire
   * (null = commentaire inchangé).
   */
  public static function setIgnored($_id, $_ignored, $_days = 0, $_comment = null, $_by = '') {
    self::assertCheck($_id);
    $ignored = self::readIgnored();
    if ($_ignored) {
      $days = (int) $_days;
      if (!in_array($days, self::IGNORE_DAYS, true)) {
        throw new Exception(__('Durée invalide', __FILE__) . ' : ' . $_days);
      }
      $ignored[$_id] = array(
        'since' => date('Y-m-d H:i:s'),
        'until' => ($days > 0) ? date('Y-m-d H:i:s', strtotime('+' . $days . ' days')) : null,
        'by' => (string) $_by,
      );
      if ($_comment !== null) {
        self::saveComment($_id, $_comment, $_by);
      }
    } else {
      unset($ignored[$_id]);
    }
    config::save('ignored', json_encode($ignored), __CLASS__);
    $report = self::getReport();
    self::updateCommands($report);
    return $report;
  }

  /** Enregistre (ou supprime si vide) le commentaire d'un contrôle (nom distinct de eqLogic::setComment, méthode d'instance du core). */
  public static function setCheckComment($_id, $_text, $_by = '') {
    self::assertCheck($_id);
    self::saveComment($_id, $_text, $_by);
    return self::getReport();
  }

  private static function saveComment($_id, $_text, $_by) {
    $text = trim(str_replace("\r\n", "\n", (string) $_text));
    if (function_exists('mb_substr')) {
      $text = mb_substr($text, 0, self::COMMENT_MAX);
    } else {
      $text = substr($text, 0, self::COMMENT_MAX);
    }
    $comments = self::configArray('comments');
    if ($text === '') {
      unset($comments[$_id]);
    } else {
      $comments[$_id] = array('text' => $text, 'date' => date('Y-m-d H:i:s'), 'by' => (string) $_by);
    }
    config::save('comments', json_encode($comments, JSON_UNESCAPED_UNICODE), __CLASS__);
  }

  private static function assertCheck($_id) {
    if (!array_key_exists($_id, auditsecurityChecks::definitions())) {
      throw new Exception(__('Contrôle inconnu', __FILE__) . ' : ' . $_id);
    }
  }

  /** Contrôles ignorés, tous (y compris expirés), au format {since, until, by}. */
  private static function readIgnored() {
    $ignored = array();
    foreach (self::configArray('ignored') as $id => $entry) {
      // Anciennes versions : seule la date du jour où le contrôle a été ignoré, sans limite
      if (!is_array($entry)) {
        $entry = array('since' => (string) $entry, 'until' => null, 'by' => '');
      }
      $ignored[$id] = array_merge(array('since' => '', 'until' => null, 'by' => ''), $entry);
    }
    return $ignored;
  }

  private static function isExpired($_entry) {
    return !empty($_entry['until']) && strtotime($_entry['until']) <= time();
  }

  /** Contrôles ignorés dont la période n'est pas terminée. */
  private static function getIgnored() {
    return array_filter(self::readIgnored(), function ($_entry) {
      return !self::isExpired($_entry);
    });
  }

  /** Retire les périodes d'ignorance terminées et le signale. Retourne le nombre de contrôles réintégrés. */
  public static function purgeExpiredIgnored() {
    $ignored = self::readIgnored();
    $definitions = auditsecurityChecks::definitions();
    $titles = array();
    foreach ($ignored as $id => $entry) {
      if (self::isExpired($entry)) {
        unset($ignored[$id]);
        if (isset($definitions[$id])) {
          $titles[] = $definitions[$id]['title'];
        }
      }
    }
    if (count($titles) > 0) {
      config::save('ignored', json_encode($ignored), __CLASS__);
      message::add(__CLASS__, sprintf(__('Audit de sécurité : fin de la période d\'ignorance, contrôle(s) de nouveau pris en compte dans la note : %s', __FILE__), implode(', ', $titles)), '', 'auditsecurity::ignoreExpired');
    }
    return count($titles);
  }

  /**
   * Lit une valeur de configuration du plugin stockée en JSON.
   * config::byKey() décode déjà le JSON en tableau : on n'appelle json_decode() que sur une chaîne.
   */
  private static function configArray($_key) {
    $value = config::byKey($_key, __CLASS__, '');
    if (is_string($value) && $value !== '') {
      $value = json_decode($value, true);
    }
    return is_array($value) ? $value : array();
  }

  private static function getRawReport() {
    $raw = self::configArray('report');
    return isset($raw['results']) ? $raw : null;
  }

  /**
   * Rapport complet pour l'affichage : contrôles (définition + résultat), note, lettre, compteurs.
   * Retourne un rapport vide (date null) si aucun audit n'a encore été lancé.
   */
  public static function getReport() {
    $raw = self::getRawReport();
    $ignored = self::getIgnored();
    $comments = self::configArray('comments');
    $categories = auditsecurityChecks::categories();
    $checks = array();
    $counts = array('pass' => 0, 'warn' => 0, 'fail' => 0, 'info' => 0, 'skip' => 0, 'ignored' => 0);
    $earned = 0;
    $possible = 0;
    $serious = 0;
    $criticalFail = false;
    $catScores = array();

    foreach (auditsecurityChecks::definitions() as $id => $def) {
      $result = ($raw !== null && isset($raw['results'][$id])) ? $raw['results'][$id] : null;
      $status = ($result === null) ? 'pending' : $result['status'];
      $isIgnored = isset($ignored[$id]);
      $fix = $def['fix'];
      if (is_array($fix) && $fix['type'] == 'auto' && (!auditsecurityChecks::hasAutoFix($id) || !empty($result['noFix']))) {
        $fix = null;
      }
      $checks[] = array(
        'id' => $id,
        'category' => $def['category'],
        'severity' => $def['severity'],
        'title' => $def['title'],
        'description' => $def['description'],
        'recommendation' => $def['recommendation'],
        'fix' => $fix,
        'status' => $status,
        'detail' => ($result === null) ? '' : $result['detail'],
        'items' => ($result === null) ? array() : $result['items'],
        'ignored' => $isIgnored,
        'ignoredSince' => $isIgnored ? $ignored[$id]['since'] : null,
        'ignoredUntil' => $isIgnored ? $ignored[$id]['until'] : null,
        'comment' => (isset($comments[$id]['text']) && $comments[$id]['text'] !== '') ? $comments[$id] : null,
      );
      if ($result === null) {
        continue;
      }
      if ($isIgnored) {
        $counts['ignored']++;
        continue;
      }
      $counts[$status]++;
      $weight = self::WEIGHTS[$def['severity']];
      if ($weight == 0 || !in_array($status, array('pass', 'warn', 'fail'))) {
        continue;
      }
      $gain = ($status == 'pass') ? $weight : (($status == 'warn') ? $weight / 2 : 0);
      $possible += $weight;
      $earned += $gain;
      if (!isset($catScores[$def['category']])) {
        $catScores[$def['category']] = array('earned' => 0, 'possible' => 0);
      }
      $catScores[$def['category']]['possible'] += $weight;
      $catScores[$def['category']]['earned'] += $gain;
      if ($status == 'fail' && in_array($def['severity'], array('critical', 'high'))) {
        $serious++;
      }
      if ($status == 'fail' && $def['severity'] == 'critical') {
        $criticalFail = true;
      }
    }

    $score = ($possible > 0) ? (int) round(100 * $earned / $possible) : 100;
    $grade = self::gradeFor($score);
    // Une faille critique plafonne la lettre à D
    if ($criticalFail && in_array($grade, array('A', 'B', 'C'))) {
      $grade = 'D';
    }
    foreach ($categories as $id => &$category) {
      $category['score'] = isset($catScores[$id]) ? (int) round(100 * $catScores[$id]['earned'] / $catScores[$id]['possible']) : null;
    }
    unset($category);

    return array(
      'date' => ($raw === null) ? null : $raw['date'],
      'duration' => ($raw === null) ? null : $raw['duration'],
      'score' => ($raw === null) ? null : $score,
      'grade' => ($raw === null) ? null : $grade,
      'criticalCap' => $criticalFail,
      'serious' => $serious,
      'counts' => $counts,
      'categories' => $categories,
      'checks' => $checks,
      'running' => (cache::byKey('auditsecurity::running')->getValue(0) == 1),
    );
  }

  public static function gradeFor($_score) {
    foreach (self::GRADES as $grade => $min) {
      if ($_score >= $min) {
        return $grade;
      }
    }
    return 'F';
  }

  /** Verdict en clair associé à une lettre. */
  public static function verdict($_grade) {
    $verdicts = array(
      'A' => __('Excellent', __FILE__),
      'B' => __('Très bon niveau', __FILE__),
      'C' => __('Correct, à renforcer', __FILE__),
      'D' => __('Insuffisant', __FILE__),
      'E' => __('Faible', __FILE__),
      'F' => __('Critique', __FILE__),
    );
    return isset($verdicts[$_grade]) ? $verdicts[$_grade] : __('Pas encore évalué', __FILE__);
  }

  /** Date courte et lisible : « Aujourd'hui à 00:45 », « Hier à 18:10 » ou « 21/11/2026 18:10 ». */
  private static function relativeDate($_date) {
    $time = strtotime($_date);
    if (date('Y-m-d', $time) == date('Y-m-d')) {
      return sprintf(__('Aujourd\'hui à %s', __FILE__), date('H:i', $time));
    }
    if (date('Y-m-d', $time) == date('Y-m-d', strtotime('-1 day'))) {
      return sprintf(__('Hier à %s', __FILE__), date('H:i', $time));
    }
    return date('d/m/Y H:i', $time);
  }

  public static function gradeColor($_grade) {
    // Mêmes couleurs que la page du plugin (desktop/js/auditsecurity.js)
    $colors = array('A' => '#22a861', 'B' => '#7cb342', 'C' => '#e0a800', 'D' => '#f08c2a', 'E' => '#e5532d', 'F' => '#d32f2f');
    return isset($colors[$_grade]) ? $colors[$_grade] : '#8a8a8a';
  }

  /** Message Jeedom quand des problèmes apparaissent par rapport à l'audit précédent. */
  private static function notifyChanges($_previous, $_report) {
    if (config::byKey('notifyNew', __CLASS__, 1) != 1 || $_previous['date'] === null) {
      return;
    }
    $before = array();
    foreach ($_previous['checks'] as $check) {
      $before[$check['id']] = $check['status'];
    }
    $new = array();
    foreach ($_report['checks'] as $check) {
      if ($check['ignored'] || !in_array($check['status'], array('fail', 'warn'))) {
        continue;
      }
      $old = isset($before[$check['id']]) ? $before[$check['id']] : 'pending';
      if ($old == 'pass' || ($old == 'warn' && $check['status'] == 'fail')) {
        $new[] = $check['title'];
      }
    }
    if (count($new) > 0) {
      message::add(__CLASS__, sprintf(__('Audit de sécurité : note %d %% (%s). Nouveau(x) problème(s) : %s', __FILE__), $_report['score'], $_report['grade'], implode(', ', $new)), '', 'auditsecurity::new');
    }
  }

  /* ************************************************************************************ */
  /*                                   Équipement                                         */
  /* ************************************************************************************ */

  /** Retourne l'équipement de l'audit, en le créant s'il n'existe pas. */
  public static function getAuditEqLogic() {
    $eqLogic = self::byLogicalId(self::LOGICAL_ID, __CLASS__);
    if (!is_object($eqLogic)) {
      $eqLogic = new self();
      $eqLogic->setName(__('Audit sécurité', __FILE__));
      $eqLogic->setLogicalId(self::LOGICAL_ID);
      $eqLogic->setEqType_name(__CLASS__);
      $eqLogic->setIsEnable(1);
      $eqLogic->setIsVisible(1);
      $eqLogic->setCategory('security', 1);
      $eqLogic->save();
    }
    return $eqLogic;
  }

  /** Commandes de l'équipement : logicalId => {nom, type, sous-type, options} */
  private static function commandDefinitions() {
    return array(
      'score' => array('name' => __('Note', __FILE__), 'type' => 'info', 'subType' => 'numeric', 'unite' => '%', 'historized' => 1, 'min' => 0, 'max' => 100),
      'grade' => array('name' => __('Lettre', __FILE__), 'type' => 'info', 'subType' => 'string'),
      'serious' => array('name' => __('Problèmes graves', __FILE__), 'type' => 'info', 'subType' => 'numeric', 'historized' => 1),
      'failures' => array('name' => __('Non conformes', __FILE__), 'type' => 'info', 'subType' => 'numeric'),
      'warnings' => array('name' => __('À améliorer', __FILE__), 'type' => 'info', 'subType' => 'numeric'),
      'lastAudit' => array('name' => __('Dernier audit', __FILE__), 'type' => 'info', 'subType' => 'string'),
      'summary' => array('name' => __('Résumé', __FILE__), 'type' => 'info', 'subType' => 'string'),
      'refresh' => array('name' => __('Lancer l\'audit', __FILE__), 'type' => 'action', 'subType' => 'other'),
    );
  }

  public function postSave() {
    $order = 0;
    foreach (self::commandDefinitions() as $logicalId => $def) {
      $cmd = $this->getCmd(null, $logicalId);
      if (!is_object($cmd)) {
        $cmd = new auditsecurityCmd();
        $cmd->setLogicalId($logicalId);
        $cmd->setEqLogic_id($this->getId());
        $cmd->setName($def['name']);
        $cmd->setType($def['type']);
        $cmd->setSubType($def['subType']);
        $cmd->setOrder($order);
        $cmd->setIsVisible(1);
        if (isset($def['unite'])) {
          $cmd->setUnite($def['unite']);
        }
        if (isset($def['historized'])) {
          $cmd->setIsHistorized($def['historized']);
        }
        if (isset($def['min'])) {
          $cmd->setConfiguration('minValue', $def['min']);
          $cmd->setConfiguration('maxValue', $def['max']);
        }
        $cmd->save();
      } elseif (isset($def['unite']) && $cmd->getUnite() == '/100') {
        // Migration : la note était exprimée sur 100, elle l'est désormais en pourcentage
        $cmd->setUnite($def['unite']);
        $cmd->save();
      }
      $order++;
    }
  }

  /** Met à jour les commandes info de l'équipement à partir du rapport. */
  public static function updateCommands($_report) {
    if ($_report['date'] === null) {
      return;
    }
    $eqLogic = self::getAuditEqLogic();
    $summary = sprintf(__('%d %% (%s) : %d non conforme(s), %d à améliorer', __FILE__), $_report['score'], $_report['grade'], $_report['counts']['fail'], $_report['counts']['warn']);
    $values = array(
      'score' => $_report['score'],
      'grade' => $_report['grade'],
      'serious' => $_report['serious'],
      'failures' => $_report['counts']['fail'],
      'warnings' => $_report['counts']['warn'],
      'lastAudit' => $_report['date'],
      'summary' => $summary,
    );
    foreach ($values as $logicalId => $value) {
      $eqLogic->checkAndUpdateCmd($logicalId, $value);
    }
    $eqLogic->refreshWidget();
  }

  public function toHtml($_version = 'dashboard') {
    $replace = $this->preToHtml($_version);
    if (!is_array($replace)) {
      return $replace;
    }
    $version = jeedom::versionAlias($_version);
    $report = self::getReport();
    $refresh = $this->getCmd('action', 'refresh');
    $replace['#refresh_id#'] = is_object($refresh) ? $refresh->getId() : '';
    $replace['#grade#'] = ($report['grade'] === null) ? '?' : $report['grade'];
    $replace['#grade_color#'] = self::gradeColor($report['grade']);
    $replace['#score#'] = ($report['score'] === null) ? '-' : $report['score'];
    // Anneau de la jauge : circonférence 2πr avec r = 26
    $circumference = 2 * M_PI * 26;
    $replace['#ring_length#'] = round($circumference, 2);
    $replace['#ring_offset#'] = round($circumference * (1 - (($report['score'] === null) ? 0 : $report['score']) / 100), 2);
    $replace['#verdict#'] = self::verdict($report['grade']);
    foreach (array('fail', 'warn', 'pass') as $status) {
      $replace['#' . $status . '#'] = $report['counts'][$status];
      $replace['#' . $status . '_class#'] = ($report['counts'][$status] == 0) ? 'is-zero' : '';
    }
    $replace['#date#'] = ($report['date'] === null) ? __('Jamais lancé', __FILE__) : self::relativeDate($report['date']);
    $replace['#plugin_link#'] = 'index.php?v=d&m=auditsecurity&p=auditsecurity';
    // Le core ne traduit pas les templates d'équipement : traduction explicite des {{...}}
    $template = translate::exec(getTemplate('core', $version, 'auditsecurity', __CLASS__), 'plugins/auditsecurity/core/template/' . $version . '/auditsecurity.html');
    return $this->postToHtml($_version, template_replace($replace, $template));
  }
}

class auditsecurityCmd extends cmd {

  public static $_widgetPossibility = array('custom' => false);

  public function dontRemoveCmd() {
    return true;
  }

  public function execute($_options = array()) {
    if ($this->getLogicalId() == 'refresh') {
      auditsecurity::runAudit('cmd');
    }
  }
}
