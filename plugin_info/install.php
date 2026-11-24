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

require_once dirname(__FILE__) . '/../../../core/php/core.inc.php';

// Fonction exécutée automatiquement après l'installation du plugin
function auditsecurity_install() {
  config::save('autoAudit', 'daily', 'auditsecurity');
  config::save('notifyNew', 1, 'auditsecurity');
  config::save('externalChecks', 0, 'auditsecurity');
  auditsecurity::getAuditEqLogic();
}

// Fonction exécutée automatiquement après la mise à jour du plugin
function auditsecurity_update() {
  // Recrée l'équipement s'il a été supprimé et les commandes ajoutées dans une nouvelle version
  auditsecurity::getAuditEqLogic()->save();
  // Ancienne case « Mode debug », remplacée par le niveau de log standard de Jeedom
  config::remove('debugMode', 'auditsecurity');
}

// Fonction exécutée automatiquement après la suppression du plugin
function auditsecurity_remove() {
  config::remove('report', 'auditsecurity');
  config::remove('ignored', 'auditsecurity');
  config::remove('comments', 'auditsecurity');
  config::remove('shodanSnapshot', 'auditsecurity');
}
