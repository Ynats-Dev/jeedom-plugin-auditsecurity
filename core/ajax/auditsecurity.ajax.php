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

try {
  require_once dirname(__FILE__) . '/../../../../core/php/core.inc.php';
  include_file('core', 'authentification', 'php');

  if (!isConnect('admin')) {
    throw new Exception(__('401 - Accès non autorisé', __FILE__));
  }

  ajax::init();

  // Dernier rapport (sans relancer l'audit)
  if (init('action') == 'getReport') {
    ajax::success(auditsecurity::getReport());
  }

  // Lance un audit complet
  if (init('action') == 'runAudit') {
    @set_time_limit(300);
    ajax::success(auditsecurity::runAudit('manual'));
  }

  // Relance un seul contrôle
  if (init('action') == 'rerunCheck') {
    ajax::success(auditsecurity::rerunCheck(init('id')));
  }

  // Applique la correction automatique d'un contrôle
  if (init('action') == 'applyFix') {
    @set_time_limit(300);
    ajax::success(auditsecurity::applyFix(init('id')));
  }

  // Utilisateur connecté, conservé avec les commentaires et les contrôles ignorés
  $login = (isset($_SESSION['user']) && is_object($_SESSION['user'])) ? $_SESSION['user']->getLogin() : '';

  // Ignore (risque accepté, pour une durée en jours, 0 = sans limite) ou réintègre un contrôle
  if (init('action') == 'setIgnored') {
    $comment = isset($_POST['comment']) ? init('comment') : null;
    ajax::success(auditsecurity::setIgnored(init('id'), init('ignored') == 1, init('days', 0), $comment, $login));
  }

  // Commentaire d'un contrôle (texte vide = suppression)
  if (init('action') == 'setComment') {
    ajax::success(auditsecurity::setCheckComment(init('id'), init('text'), $login));
  }

  // Rapport de diagnostic (texte, données personnelles masquées) à joindre à une demande d'aide
  if (init('action') == 'getDiagnostic') {
    @set_time_limit(120);
    ajax::success(auditsecurity::getDiagnostic());
  }

  throw new Exception(__('Aucune méthode correspondante à', __FILE__) . ' : ' . init('action'));
} catch (Throwable $e) {
  // Throwable : une erreur PHP (TypeError...) doit aussi revenir en JSON, sinon le navigateur reçoit une réponse vide
  if (!($e instanceof Exception)) {
    log::add('auditsecurity', 'error', get_class($e) . ' : ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')');
  }
  ajax::error(displayException($e), $e->getCode());
}
