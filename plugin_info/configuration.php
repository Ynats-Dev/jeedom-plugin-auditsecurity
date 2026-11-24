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
include_file('core', 'authentification', 'php');
if (!isConnect('admin')) {
  include_file('desktop', '404', 'php');
  die();
}
?>
<form class="form-horizontal">
  <fieldset>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Audit automatique}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Relance l'audit en tâche de fond et met à jour la note de l'équipement. L'audit hebdomadaire a lieu le lundi.}}"></i></sup>
      </label>
      <div class="col-md-4">
        <select class="configKey form-control" data-l1key="autoAudit">
          <option value="daily">{{Tous les jours}}</option>
          <option value="weekly">{{Toutes les semaines}}</option>
          <option value="never">{{Jamais}}</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Prévenir des nouveaux problèmes}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Ajoute un message dans le centre de messages de Jeedom quand un contrôle conforme ne l'est plus.}}"></i></sup>
      </label>
      <div class="col-md-4">
        <input type="checkbox" class="configKey" data-l1key="notifyNew" checked>
      </div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Tests via des services externes}}
        <sup><i class="fas fa-question-circle tooltips" title="{{Désactivé par défaut. Une fois activé, l'adresse IP publique de votre connexion est envoyée à des services tiers pour vérifier ce qui est visible depuis Internet.}}"></i></sup>
      </label>
      <div class="col-md-6">
        <input type="checkbox" class="configKey" data-l1key="externalChecks">
        <div class="help-block">{{Services contactés : api.ipify.org (seulement si la box Internet ne donne pas l'adresse IP publique par UPnP), internetdb.shodan.io, et les listes noires zen.spamhaus.org, b.barracudacentral.org et bl.spamcop.net (requêtes DNS).}}</div>
      </div>
    </div>
    <div class="form-group">
      <label class="col-md-4 control-label">{{Signaler un problème}}
        <sup><i class="fas fa-question-circle tooltips" title="{{En niveau de log Debug, le plugin écrit dans le log auditsecurity le détail de chaque contrôle : durée, commandes système lancées, requêtes et résultats. Les données sensibles (mots de passe, empreintes) ne sont jamais écrites.}}"></i></sup>
      </label>
      <div class="col-md-6">
        <div class="help-block">{{Passez le niveau de log sur Debug (cadre Logs et surveillance ci-dessus), relancez l'audit, puis cliquez sur Diagnostic dans la page du plugin et joignez le fichier téléchargé à votre message sur le forum. Remettez ensuite le niveau de log par défaut.}}</div>
      </div>
    </div>
  </fieldset>
</form>
