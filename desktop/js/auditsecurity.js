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

/* Page du plugin Audit Sécurité : affichage du rapport, lancement de l'audit, corrections.
 * Écrit sans jQuery (compatible avec le mode « jqueryless » du core) et encapsulé pour supporter
 * le rechargement de la page par le core. */
(function () {
  var AJAX_URL = 'plugins/auditsecurity/core/ajax/auditsecurity.ajax.php'
  var GAUGE_LENGTH = 2 * Math.PI * 52

  var STATUS = {
    fail: { icon: 'fas fa-times', label: '{{Non conforme}}' },
    warn: { icon: 'fas fa-exclamation', label: '{{À améliorer}}' },
    pass: { icon: 'fas fa-check', label: '{{Conforme}}' },
    info: { icon: 'fas fa-info', label: '{{Information}}' },
    skip: { icon: 'fas fa-minus', label: '{{Non vérifiable}}' },
    pending: { icon: 'far fa-circle', label: '{{Non vérifié}}' }
  }
  var SEVERITY = {
    critical: '{{Critique}}',
    high: '{{Élevée}}',
    medium: '{{Moyenne}}',
    low: '{{Faible}}',
    info: '{{Info}}'
  }
  var VERDICT = {
    A: '{{Excellent}}',
    B: '{{Très bon niveau}}',
    C: '{{Correct, à renforcer}}',
    D: '{{Insuffisant}}',
    E: '{{Faible}}',
    F: '{{Critique}}'
  }
  var STATUS_ORDER = { fail: 0, warn: 1, skip: 2, pending: 3, info: 4, pass: 5 }
  var SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  var GRADE_COLORS = { A: '#22a861', B: '#7cb342', C: '#e0a800', D: '#f08c2a', E: '#e5532d', F: '#d32f2f' }
  // Durées proposées pour ignorer un contrôle, en jours (0 = sans limite) : identiques à auditsecurity::IGNORE_DAYS
  var IGNORE_DURATIONS = [
    [7, '{{7 jours}}'],
    [30, '{{30 jours}}'],
    [90, '{{3 mois}}'],
    [365, '{{1 an}}'],
    [0, '{{Sans limite}}']
  ]
  var COMMENT_MAX = 1000

  var state = {
    report: (typeof asReport !== 'undefined') ? asReport : null,
    filter: 'todo',
    category: '',
    search: '',
    open: {},
    // Formulaire ouvert dans une carte : {id, type: 'comment' | 'ignore'}
    editing: null,
    running: false
  }

  /* ----------------------------- Utilitaires ----------------------------- */

  function esc(_text) {
    return String(_text === null || _text === undefined ? '' : _text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;')
  }

  function alertMessage(_message, _level) {
    if (typeof jeedomUtils !== 'undefined' && typeof jeedomUtils.showAlert === 'function') {
      jeedomUtils.showAlert({ message: _message, level: _level || 'danger' })
    } else {
      window.alert(_message)
    }
  }

  function confirmDialog(_title, _message, _callback) {
    if (typeof jeeDialog !== 'undefined' && typeof jeeDialog.confirm === 'function') {
      jeeDialog.confirm({ title: _title, message: _message, callback: function (result) { if (result) _callback() } })
    } else if (window.confirm(_title + '\n\n' + _message)) {
      _callback()
    }
  }

  function request(_action, _data, _success, _always) {
    var body = new URLSearchParams()
    body.append('action', _action)
    Object.keys(_data || {}).forEach(function (key) { body.append(key, _data[key]) })
    fetch(AJAX_URL, { method: 'POST', body: body, credentials: 'same-origin' })
      .then(function (response) { return response.json() })
      .then(function (data) {
        if (data.state != 'ok') {
          alertMessage(data.result, 'danger')
          return
        }
        _success(data.result)
      })
      .catch(function (error) { alertMessage('{{Erreur de communication :}} ' + error, 'danger') })
      .finally(function () { if (_always) _always() })
  }

  function formatDate(_date) {
    if (!_date) return ''
    var d = new Date(_date.replace(' ', 'T'))
    if (isNaN(d.getTime())) return _date
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  function formatDay(_date) {
    if (!_date) return ''
    var d = new Date(_date.replace(' ', 'T'))
    return isNaN(d.getTime()) ? _date : d.toLocaleDateString()
  }

  function gradeFor(_score) {
    if (_score >= 90) return 'A'
    if (_score >= 80) return 'B'
    if (_score >= 65) return 'C'
    if (_score >= 50) return 'D'
    if (_score >= 35) return 'E'
    return 'F'
  }

  function isTodo(_check) {
    return !_check.ignored && ['fail', 'warn'].indexOf(_check.status) >= 0
  }

  /** Vrai si le contrôle correspond au filtre, à la catégorie et à la recherche courants. */
  function matches(_check, _ignoreFilter) {
    if (state.category != '' && _check.category != state.category) return false
    if (!_ignoreFilter) {
      var filter = state.filter
      if (filter == 'ignored' && !_check.ignored) return false
      if (filter != 'ignored' && filter != 'all' && _check.ignored) return false
      if (filter == 'todo' && !isTodo(_check)) return false
      if (filter == 'pass' && _check.status != 'pass') return false
      // Le filtre Informations regroupe aussi les contrôles non vérifiables
      if (filter == 'info' && ['info', 'skip'].indexOf(_check.status) < 0) return false
    }
    if (state.search != '') {
      var text = (_check.title + ' ' + _check.detail + ' ' + _check.description + ' ' + (_check.items || []).join(' ') + ' ' + (_check.comment ? _check.comment.text : '')).toLowerCase()
      if (text.indexOf(state.search) < 0) return false
    }
    return true
  }

  function byPriority(a, b) {
    return (STATUS_ORDER[a.status] - STATUS_ORDER[b.status]) || (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
  }

  function ring(_score, _size, _stroke) {
    var r = (_size - _stroke) / 2
    var length = 2 * Math.PI * r
    var color = (_score === null) ? 'transparent' : GRADE_COLORS[gradeFor(_score)]
    var offset = (_score === null) ? length : length * (1 - _score / 100)
    return '<svg class="auditsecurity-ring" width="' + _size + '" height="' + _size + '" viewBox="0 0 ' + _size + ' ' + _size + '" aria-hidden="true">'
      + '<circle class="auditsecurity-ring-track" cx="' + (_size / 2) + '" cy="' + (_size / 2) + '" r="' + r + '" stroke-width="' + _stroke + '"></circle>'
      + '<circle class="auditsecurity-ring-value" cx="' + (_size / 2) + '" cy="' + (_size / 2) + '" r="' + r + '" stroke-width="' + _stroke + '" stroke="' + color + '"'
      + ' stroke-dasharray="' + length.toFixed(2) + '" stroke-dashoffset="' + offset.toFixed(2) + '" transform="rotate(-90 ' + (_size / 2) + ' ' + (_size / 2) + ')"></circle>'
      + '</svg>'
  }

  /* ------------------------------- Rendu -------------------------------- */

  function render() {
    var report = state.report
    if (!report || !document.getElementById('div_asReport')) return
    renderHero(report)
    renderPriorities(report)
    renderCategories(report)
    renderChecks(report)
  }

  function renderHero(_report) {
    var color = GRADE_COLORS[_report.grade] || '#8a949e'
    var hero = document.getElementById('as_hero')
    hero.style.setProperty('--auditsecurity-grade-color', color)
    hero.classList.toggle('is-running', state.running || _report.running)
    hero.classList.toggle('is-empty', !_report.date)

    document.getElementById('as_grade').textContent = _report.grade || '?'
    document.getElementById('as_score').textContent = (_report.score === null) ? '-' : _report.score
    var gauge = document.getElementById('as_gauge_value')
    gauge.style.strokeDasharray = GAUGE_LENGTH.toFixed(2)
    // Animation : la jauge part de zéro au premier affichage
    requestAnimationFrame(function () {
      gauge.style.strokeDashoffset = (GAUGE_LENGTH * (1 - (_report.score || 0) / 100)).toFixed(2)
    })

    var verdict = '{{Pas encore évalué}}'
    var meta = '{{Lancez un premier audit pour obtenir la note de votre installation.}}'
    if (state.running || _report.running) {
      verdict = '{{Audit en cours...}}'
      meta = '{{Les contrôles prennent de quelques secondes à une minute.}}'
    } else if (_report.date) {
      verdict = VERDICT[_report.grade] || ''
      meta = '<i class="far fa-clock"></i> {{Dernier audit le}} ' + esc(formatDate(_report.date)) + ' · ' + esc(_report.duration) + ' s'
    }
    document.getElementById('as_verdict').textContent = verdict
    document.getElementById('as_meta').innerHTML = meta
    document.getElementById('as_cap').style.display = (_report.criticalCap && !state.running) ? '' : 'none'

    var button = document.getElementById('bt_asRunAudit')
    button.classList.toggle('is-disabled', state.running)
    button.querySelector('i').className = state.running ? 'fas fa-circle-notch fa-spin' : (_report.date ? 'fas fa-redo' : 'fas fa-play')
    button.querySelector('span').textContent = state.running ? '{{Audit en cours...}}' : (_report.date ? '{{Relancer l\'audit}}' : '{{Lancer l\'audit}}')

    var stats = [
      ['fail', 'fas fa-times-circle', '{{Non conformes}}', 'todo'],
      ['warn', 'fas fa-exclamation-circle', '{{À améliorer}}', 'todo'],
      ['pass', 'fas fa-check-circle', '{{Conformes}}', 'pass'],
      ['info', 'fas fa-info-circle', '{{Informations}}', 'info']
    ]
    var html = ''
    stats.forEach(function (stat) {
      var value = _report.date ? (_report.counts[stat[0]] || 0) : '-'
      html += '<a class="auditsecurity-stat auditsecurity-st-' + stat[0] + (value === 0 ? ' is-zero' : '') + '" data-filter="' + stat[3] + '">'
        + '<i class="' + stat[1] + '"></i><b>' + value + '</b><span>' + stat[2] + '</span></a>'
    })
    document.getElementById('as_stats').innerHTML = html
  }

  function renderPriorities(_report) {
    var section = document.getElementById('as_priorities_section')
    var list = _report.checks.filter(function (check) {
      return !check.ignored && (check.status == 'fail' || (check.status == 'warn' && SEVERITY_ORDER[check.severity] <= 1))
    }).sort(function (a, b) {
      return (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]) || (STATUS_ORDER[a.status] - STATUS_ORDER[b.status])
    }).slice(0, 3)
    if (list.length == 0 || state.running) {
      section.style.display = 'none'
      return
    }
    section.style.display = ''
    var html = ''
    list.forEach(function (check) {
      html += '<div class="auditsecurity-priority auditsecurity-st-' + esc(check.status) + '" data-id="' + esc(check.id) + '">'
        + '<div class="auditsecurity-priority-top"><span class="auditsecurity-sev auditsecurity-sev-' + esc(check.severity) + '">' + esc(SEVERITY[check.severity]) + '</span>'
        + '<span class="auditsecurity-priority-cat">' + esc(_report.categories[check.category].name) + '</span></div>'
        + '<div class="auditsecurity-priority-title">' + esc(check.title) + '</div>'
        + '<div class="auditsecurity-priority-detail">' + esc(check.detail) + '</div>'
        + '<div class="auditsecurity-priority-actions">'
      if (check.fix && check.fix.type == 'auto') {
        html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-accent auditsecurity-bt-fix" title="' + esc(check.fix.label) + '"><i class="fas fa-magic"></i> {{Corriger}}</a>'
      } else if (check.fix && check.fix.type == 'link') {
        html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost" href="' + esc(check.fix.url) + '" title="' + esc(check.fix.label) + '"><i class="fas fa-external-link-alt"></i> {{Ouvrir}}</a>'
      }
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-show"><i class="fas fa-search"></i> {{Détails}}</a></div></div>'
    })
    document.getElementById('as_priorities').innerHTML = html
  }

  function renderCategories(_report) {
    var html = ''
    Object.keys(_report.categories).forEach(function (id) {
      var category = _report.categories[id]
      var checks = _report.checks.filter(function (check) { return check.category == id })
      var todo = checks.filter(isTodo).length
      var sub = !_report.date ? checks.length + ' {{contrôles}}' : (todo > 0 ? todo + ' {{à traiter}}' : '{{Rien à signaler}}')
      html += '<a class="auditsecurity-category' + (state.category == id ? ' is-active' : '') + (todo > 0 ? ' has-todo' : '') + '" data-category="' + esc(id) + '">'
        + '<span class="auditsecurity-category-ring">' + ring(category.score, 46, 5) + '<i class="' + esc(category.icon) + '"></i></span>'
        + '<span class="auditsecurity-category-text"><b title="' + esc(category.name) + '">' + esc(category.name) + '</b><span>' + sub + '</span></span>'
        + '<span class="auditsecurity-category-score">' + (category.score === null ? '-' : category.score + '<small>%</small>') + '</span>'
        + '</a>'
    })
    document.getElementById('as_categories').innerHTML = html
  }

  function renderChecks(_report) {
    // Compteurs des filtres (dans la catégorie et la recherche courantes)
    var scoped = _report.checks.filter(function (check) { return matches(check, true) })
    var counts = { todo: 0, pass: 0, info: 0, ignored: 0, all: scoped.length }
    scoped.forEach(function (check) {
      if (check.ignored) { counts.ignored++; return }
      if (isTodo(check)) counts.todo++
      if (check.status == 'pass') counts.pass++
      if (check.status == 'info' || check.status == 'skip') counts.info++
    })
    document.querySelectorAll('#as_filters [data-count]').forEach(function (badge) {
      badge.textContent = counts[badge.getAttribute('data-count')]
    })
    document.querySelectorAll('#as_filters [data-filter]').forEach(function (button) {
      button.classList.toggle('is-active', button.getAttribute('data-filter') == state.filter)
    })

    var chip = document.getElementById('as_active_category')
    if (state.category != '' && _report.categories[state.category]) {
      chip.style.display = ''
      chip.innerHTML = '<span class="auditsecurity-chip"><i class="' + esc(_report.categories[state.category].icon) + '"></i> '
        + esc(_report.categories[state.category].name) + ' <a class="auditsecurity-chip-close" title="{{Toutes les catégories}}"><i class="fas fa-times"></i></a></span>'
    } else {
      chip.style.display = 'none'
    }

    var checks = _report.checks.filter(function (check) { return matches(check, false) }).sort(byPriority)
    var html = ''
    Object.keys(_report.categories).forEach(function (categoryId) {
      var list = checks.filter(function (check) { return check.category == categoryId })
      if (list.length == 0) return
      var category = _report.categories[categoryId]
      html += '<div class="auditsecurity-group"><div class="auditsecurity-group-title"><i class="' + esc(category.icon) + '"></i> ' + esc(category.name) + ' <span>' + list.length + '</span></div>'
      list.forEach(function (check) { html += renderCheck(check) })
      html += '</div>'
    })
    document.getElementById('as_checks').innerHTML = html

    var empty = document.getElementById('as_empty')
    if (checks.length > 0) {
      empty.style.display = 'none'
      return
    }
    empty.style.display = ''
    if (!_report.date) {
      empty.innerHTML = '<i class="fas fa-shield-alt"></i><b>{{Aucun audit pour le moment}}</b><span>{{Lancez un premier audit pour obtenir la note de votre installation.}}</span>'
    } else if (state.filter == 'todo' && state.search == '') {
      empty.innerHTML = '<i class="fas fa-trophy"></i><b>{{Rien à traiter : bravo !}}</b><span>{{Tous les contrôles de cette sélection sont conformes.}}</span>'
    } else {
      empty.innerHTML = '<i class="fas fa-search"></i><b>{{Aucun contrôle ne correspond.}}</b>'
    }
  }

  function renderCheck(_check) {
    var status = STATUS[_check.status] || STATUS.pending
    var isOpen = !!state.open[_check.id]
    var needsAction = ['fail', 'warn'].indexOf(_check.status) >= 0
    // Une information peut garder sa correction (ex. fail2ban sans exposition détectée)
    var canFix = _check.fix && _check.fix.type == 'auto' && !_check.ignored && (needsAction || _check.status == 'info')
    var html = '<article class="auditsecurity-check auditsecurity-st-' + esc(_check.status) + (_check.ignored ? ' is-ignored' : '') + (isOpen ? ' is-open' : '') + '" data-id="' + esc(_check.id) + '">'
    html += '<header class="auditsecurity-check-head">'
    html += '<span class="auditsecurity-status" title="' + esc(status.label) + '"><i class="' + status.icon + '"></i></span>'
    html += '<span class="auditsecurity-check-title"><b>' + esc(_check.title) + '</b>'
    if (_check.detail) html += '<span>' + esc(_check.detail) + '</span>'
    html += '</span><span class="auditsecurity-check-tags">'
    if (_check.comment) html += '<span class="auditsecurity-tag auditsecurity-tag-comment" title="' + esc(_check.comment.text) + '"><i class="far fa-comment-dots"></i></span>'
    if (_check.ignored) {
      html += '<span class="auditsecurity-tag"><i class="fas fa-eye-slash"></i> '
        + (_check.ignoredUntil ? '{{Ignoré jusqu\'au}} ' + esc(formatDay(_check.ignoredUntil)) : '{{Ignoré}}') + '</span>'
    }
    if (canFix && needsAction) html += '<span class="auditsecurity-tag auditsecurity-tag-fix" title="{{Correction automatique disponible}}"><i class="fas fa-magic"></i></span>'
    // La couleur de la gravité n'est utile que s'il y a quelque chose à traiter : sinon badge neutre
    var sevClass = 'auditsecurity-sev auditsecurity-sev-' + esc(_check.severity) + ((needsAction && !_check.ignored) ? '' : ' is-muted')
    html += '<span class="' + sevClass + '" title="{{Gravité si ce contrôle n\'est pas conforme}}">' + esc(SEVERITY[_check.severity] || _check.severity) + '</span>'
    html += '</span><i class="fas fa-chevron-down auditsecurity-chevron"></i></header>'

    html += '<div class="auditsecurity-check-body"><div class="auditsecurity-check-inner">'
    if (_check.items && _check.items.length > 0) {
      html += '<ul class="auditsecurity-items">'
      _check.items.forEach(function (item) { html += '<li>' + esc(item) + '</li>' })
      html += '</ul>'
    }
    html += '<div class="auditsecurity-explain">'
    html += '<div><h4><i class="far fa-lightbulb"></i> {{Pourquoi}}</h4><p>' + esc(_check.description) + '</p></div>'
    html += '<div><h4><i class="fas fa-route"></i> {{Que faire}}</h4><p>' + esc(_check.recommendation) + '</p></div>'
    html += '</div>'
    var editing = (state.editing && state.editing.id == _check.id) ? state.editing.type : null
    if (editing) {
      html += renderForm(_check, editing)
    } else if (_check.comment) {
      html += '<div class="auditsecurity-comment"><h4><i class="far fa-comment-dots"></i> {{Commentaire}}</h4><p>' + esc(_check.comment.text) + '</p>'
        + '<span class="auditsecurity-comment-meta">' + (_check.comment.by ? esc(_check.comment.by) + ', ' : '') + esc(formatDate(_check.comment.date)) + '</span></div>'
    }
    if (_check.ignored && !editing) {
      html += '<p class="auditsecurity-ignored-note"><i class="fas fa-eye-slash"></i> '
        + (_check.ignoredUntil
          ? '{{Ignoré depuis le}} ' + esc(formatDay(_check.ignoredSince)) + ' {{jusqu\'au}} ' + esc(formatDate(_check.ignoredUntil)) + '. {{Il comptera de nouveau dans la note ensuite.}}'
          : '{{Ignoré sans limite de durée depuis le}} ' + esc(formatDay(_check.ignoredSince)) + '.')
        + '</p>'
    }
    html += '<footer class="auditsecurity-actions">'
    if (canFix) {
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-accent auditsecurity-bt-fix"><i class="fas fa-magic"></i> ' + esc(_check.fix.label) + '</a>'
    }
    if (_check.fix && _check.fix.type == 'link') {
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost" href="' + esc(_check.fix.url) + '"><i class="fas fa-external-link-alt"></i> ' + esc(_check.fix.label) + '</a>'
    }
    html += '<span class="auditsecurity-spacer"></span>'
    html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-rerun"><i class="fas fa-redo"></i> {{Revérifier}}</a>'
    html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-edit" data-type="comment"><i class="far fa-comment-dots"></i> ' + (_check.comment ? '{{Modifier le commentaire}}' : '{{Commenter}}') + '</a>'
    if (_check.ignored) {
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-edit" data-type="ignore"><i class="far fa-clock"></i> {{Changer la durée}}</a>'
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-unignore"><i class="fas fa-eye"></i> {{Réintégrer dans la note}}</a>'
    } else if (_check.status != 'pass' && _check.severity != 'info') {
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-edit" data-type="ignore" title="{{Risque accepté : le contrôle ne compte plus dans la note}}"><i class="fas fa-eye-slash"></i> {{Ignorer}}</a>'
    }
    html += '</footer></div></div></article>'
    return html
  }

  /** Formulaire d'un contrôle : commentaire, ou durée d'ignorance avec sa raison. */
  function renderForm(_check, _type) {
    var text = _check.comment ? _check.comment.text : ''
    var html = '<div class="auditsecurity-form">'
    if (_type == 'ignore') {
      html += '<h4><i class="fas fa-eye-slash"></i> {{Ignorer ce contrôle}}</h4>'
        + '<p class="auditsecurity-form-help">{{Le contrôle ne compte plus dans la note pendant la durée choisie, puis il est de nouveau pris en compte.}}</p>'
        + '<label class="auditsecurity-form-row"><span>{{Durée}}</span><select class="auditsecurity-in-days">'
      IGNORE_DURATIONS.forEach(function (duration) {
        html += '<option value="' + duration[0] + '"' + (duration[0] == 30 ? ' selected' : '') + '>' + esc(duration[1]) + '</option>'
      })
      html += '</select></label>'
        + '<label class="auditsecurity-form-row auditsecurity-form-col"><span>{{Raison (facultatif, enregistrée comme commentaire)}}</span>'
    } else {
      html += '<h4><i class="far fa-comment-dots"></i> {{Commentaire}}</h4><label class="auditsecurity-form-row auditsecurity-form-col">'
    }
    html += '<textarea class="auditsecurity-in-comment" rows="3" maxlength="' + COMMENT_MAX + '" placeholder="{{Ex. : port volontairement ouvert, protégé par le pare-feu de la box}}">' + esc(text) + '</textarea></label>'
    html += '<div class="auditsecurity-form-actions">'
    if (_type == 'ignore') {
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-primary auditsecurity-bt-save-ignore"><i class="fas fa-eye-slash"></i> ' + (_check.ignored ? '{{Appliquer}}' : '{{Ignorer}}') + '</a>'
    } else {
      html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-primary auditsecurity-bt-save-comment"><i class="fas fa-check"></i> {{Enregistrer}}</a>'
      if (_check.comment) html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-del-comment"><i class="far fa-trash-alt"></i> {{Supprimer}}</a>'
    }
    html += '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-cancel">{{Annuler}}</a></div></div>'
    return html
  }

  /* ------------------------------ Actions ------------------------------- */

  function setReport(_report) {
    state.report = _report
    render()
  }

  function findCheck(_id) {
    var found = null
    state.report.checks.forEach(function (check) { if (check.id == _id) found = check })
    return found
  }

  function runAudit() {
    if (state.running) return
    state.running = true
    render()
    request('runAudit', {}, function (report) {
      state.running = false
      setReport(report)
      alertMessage('{{Audit terminé :}} ' + report.score + ' % (' + report.grade + ')', 'success')
    }, function () {
      if (state.running) {
        state.running = false
        render()
      }
    })
  }

  function busy(_id, _busy) {
    document.querySelectorAll('[data-id="' + _id + '"]').forEach(function (el) { el.classList.toggle('is-busy', _busy) })
  }

  function applyFix(_id) {
    var check = findCheck(_id)
    if (!check || !check.fix) return
    confirmDialog(check.fix.label, esc(check.fix.confirm || '') + '<br><br>{{Continuer ?}}', function () {
      busy(_id, true)
      request('applyFix', { id: _id }, function (result) {
        alertMessage(result.message, 'success')
        setReport(result.report)
      }, function () { busy(_id, false) })
    })
  }

  function rerun(_id) {
    busy(_id, true)
    request('rerunCheck', { id: _id }, setReport, function () { busy(_id, false) })
  }

  function closeForm() {
    state.editing = null
  }

  function editCheck(_id, _type) {
    state.editing = { id: _id, type: _type }
    state.open[_id] = true
    render()
    var field = document.querySelector('#as_checks .auditsecurity-check[data-id="' + _id + '"] .auditsecurity-in-comment')
    if (field) {
      field.focus()
      field.setSelectionRange(field.value.length, field.value.length)
    }
  }

  function formValue(_row, _selector) {
    var field = _row.querySelector(_selector)
    return field ? field.value : ''
  }

  function saveIgnore(_id, _row) {
    busy(_id, true)
    request('setIgnored', { id: _id, ignored: 1, days: formValue(_row, '.auditsecurity-in-days'), comment: formValue(_row, '.auditsecurity-in-comment') }, function (report) {
      closeForm()
      setReport(report)
    }, function () { busy(_id, false) })
  }

  function unignore(_id) {
    busy(_id, true)
    request('setIgnored', { id: _id, ignored: 0 }, setReport, function () { busy(_id, false) })
  }

  function saveComment(_id, _text) {
    busy(_id, true)
    request('setComment', { id: _id, text: _text }, function (report) {
      closeForm()
      setReport(report)
    }, function () { busy(_id, false) })
  }

  /** Affiche un contrôle déplié dans la liste (depuis une carte de priorité). */
  function showCheck(_id) {
    state.filter = 'all'
    state.category = ''
    state.search = ''
    document.getElementById('in_asSearch').value = ''
    state.open[_id] = true
    render()
    var row = document.querySelector('#as_checks .auditsecurity-check[data-id="' + _id + '"]')
    if (row) {
      row.scrollIntoView({ behavior: 'smooth', block: 'center' })
      row.classList.add('is-flash')
      setTimeout(function () { row.classList.remove('is-flash') }, 1600)
    }
  }

  /* ----------------------------- Événements ----------------------------- */

  /** Ouvre l'équipement de l'audit (même mécanisme que les cartes d'équipement du core). */
  function openEquipment() {
    if (typeof asEqLogicId === 'undefined') return
    if (typeof jeeFrontEnd !== 'undefined' && jeeFrontEnd.pluginTemplate && typeof jeeFrontEnd.pluginTemplate.displayEqlogic === 'function') {
      jeeFrontEnd.pluginTemplate.displayEqlogic('auditsecurity', asEqLogicId)
    } else {
      window.location.href = 'index.php?v=d&m=auditsecurity&p=auditsecurity&id=' + asEqLogicId
    }
  }

  /**
   * Rapport de diagnostic : la fenêtre s'ouvre tout de suite et déroule les étapes avec une barre de progression,
   * pour voir exactement où le processus s'arrête. Le rapport s'affiche ensuite, à copier ou télécharger
   * (lien réel, aucun clic simulé que le navigateur ou Jeedom pourraient intercepter).
   */
  var DIAGNOSTIC_STEPS = [
    '{{Envoi de la demande au serveur}}',
    '{{Préparation du rapport par le serveur}}',
    '{{Réception de la réponse}}',
    '{{Affichage du rapport}}'
  ]

  function downloadDiagnostic() {
    var button = document.getElementById('bt_asDiagnostic')
    if (button.classList.contains('is-disabled')) return
    button.classList.add('is-disabled')
    var ui = openDiagnosticModal()
    var started = Date.now()
    var elapsed = function () { return (Date.now() - started) + ' ms' }
    var current = 0
    var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null
    var timer = setTimeout(function () { if (controller) controller.abort() }, 90000)
    var finish = function () {
      clearTimeout(timer)
      button.classList.remove('is-disabled')
    }

    ui.step(0, 'running')
    var body = new URLSearchParams()
    body.append('action', 'getDiagnostic')
    fetch(AJAX_URL, { method: 'POST', body: body, credentials: 'same-origin', signal: controller ? controller.signal : undefined })
      .then(function (response) {
        ui.step(0, 'done', elapsed())
        current = 1
        ui.step(1, 'running')
        return response.text().then(function (raw) {
          var data = null
          try {
            data = JSON.parse(raw)
          } catch (e) {
            console.error('[auditsecurity] Réponse non JSON du diagnostic (HTTP ' + response.status + ') :', raw.slice(0, 2000))
            throw new Error('{{Réponse invalide du serveur}} (HTTP ' + response.status + ', ' + raw.length + ' {{octets}})')
          }
          if (data.state != 'ok') {
            throw new Error(String(data.result))
          }
          // Compatibilité : ancienne réponse en texte seul, nouvelle avec les étapes du serveur
          var result = (typeof data.result === 'string') ? { text: data.result, steps: [] } : data.result
          var serverSteps = result.steps || []
          var serverMs = serverSteps.length > 0 ? serverSteps[serverSteps.length - 1].ms + ' ms {{sur le serveur}}' : ''
          ui.step(1, 'done', serverMs, serverSteps)
          current = 2
          ui.step(2, 'done', raw.length + ' {{octets}}')
          return result.text || ''
        })
      })
      .then(function (text) {
        current = 3
        ui.step(3, 'running')
        if (String(text).trim() === '') {
          throw new Error('{{Le rapport de diagnostic est vide : passez le log du plugin en Debug, réessayez, puis consultez le log auditsecurity.}}')
        }
        ui.showReport(String(text))
        ui.step(3, 'done', elapsed())
      })
      .catch(function (error) {
        console.error('[auditsecurity] Diagnostic en échec à l\'étape ' + (current + 1) + ' :', error)
        var message = (error && error.name === 'AbortError')
          ? '{{Le diagnostic ne répond pas après 90 secondes. Passez le log du plugin en Debug, réessayez, puis consultez le log auditsecurity.}}'
          : (error && error.message ? error.message : String(error))
        ui.step(current, 'failed', message)
      })
      .finally(finish)
  }

  /** Ouvre la fenêtre du diagnostic et retourne ses commandes : step(), showReport(). */
  function openDiagnosticModal() {
    var old = document.getElementById('as_diagnostic_modal')
    if (old) old.remove()
    var modal = document.createElement('div')
    modal.id = 'as_diagnostic_modal'
    modal.className = 'auditsecurity-modal'
    var steps = ''
    DIAGNOSTIC_STEPS.forEach(function (label, index) {
      steps += '<li class="auditsecurity-step" data-step="' + index + '"><span class="auditsecurity-step-icon"><i class="far fa-circle"></i></span>'
        + '<span class="auditsecurity-step-body"><span class="auditsecurity-step-label">' + esc(label) + '</span><span class="auditsecurity-step-detail"></span>'
        + '<ul class="auditsecurity-step-sub"></ul></span></li>'
    })
    modal.innerHTML = '<div class="auditsecurity-modal-box" role="dialog" aria-modal="true">'
      + '<div class="auditsecurity-modal-head"><b><i class="fas fa-stethoscope"></i> {{Rapport de diagnostic}}</b><a class="auditsecurity-modal-close" title="{{Fermer}}"><i class="fas fa-times"></i></a></div>'
      + '<div class="auditsecurity-progressbar"><span></span></div>'
      + '<ol class="auditsecurity-steps">' + steps + '</ol>'
      + '<div class="auditsecurity-modal-report" style="display:none;">'
      + '<p class="auditsecurity-modal-help">{{Relisez-le avant de le partager : les adresses publiques, le domaine externe, les comptes et les e-mails sont masqués.}}</p>'
      + '<textarea class="auditsecurity-modal-text" readonly spellcheck="false"></textarea>'
      + '</div>'
      + '<div class="auditsecurity-modal-actions">'
      + '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-primary auditsecurity-bt-copy" style="display:none;"><i class="far fa-copy"></i> <span>{{Copier}}</span></a>'
      + '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-bt-download" style="display:none;" target="_blank" rel="noopener"><i class="fas fa-download"></i> {{Télécharger}}</a>'
      + '<span class="auditsecurity-spacer"></span>'
      + '<a class="auditsecurity-btn auditsecurity-btn-sm auditsecurity-btn-ghost auditsecurity-modal-close">{{Fermer}}</a>'
      + '</div></div>'
    document.body.appendChild(modal)

    var url = null
    var text = ''
    var bar = modal.querySelector('.auditsecurity-progressbar span')
    function close() {
      modal.remove()
      if (url) URL.revokeObjectURL(url)
      document.removeEventListener('keydown', onKey)
    }
    function onKey(event) {
      if (event.key === 'Escape') close()
    }
    document.addEventListener('keydown', onKey)
    modal.addEventListener('click', function (event) {
      // Le clic ne doit pas remonter jusqu'aux gestionnaires de la page Jeedom
      event.stopPropagation()
      if (event.target === modal || event.target.closest('.auditsecurity-modal-close')) {
        close()
        return
      }
      var copy = event.target.closest('.auditsecurity-bt-copy')
      if (copy) {
        var area = modal.querySelector('.auditsecurity-modal-text')
        var done = function () { copy.querySelector('span').textContent = '{{Copié}}' }
        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(text).then(done, function () { area.select(); document.execCommand('copy'); done() })
        } else {
          area.select()
          document.execCommand('copy')
          done()
        }
      }
    })

    return {
      /** État d'une étape : running, done ou failed, avec un détail et les sous-étapes du serveur. */
      step: function (_index, _state, _detail, _sub) {
        var item = modal.querySelector('.auditsecurity-step[data-step="' + _index + '"]')
        if (!item) return
        item.className = 'auditsecurity-step is-' + _state
        var icons = { running: 'fas fa-circle-notch fa-spin', done: 'fas fa-check', failed: 'fas fa-times' }
        item.querySelector('.auditsecurity-step-icon i').className = icons[_state] || 'far fa-circle'
        item.querySelector('.auditsecurity-step-detail').textContent = _detail ? (_state == 'failed' ? _detail : ' · ' + _detail) : ''
        if (_sub && _sub.length > 0) {
          var html = ''
          _sub.forEach(function (sub) { html += '<li>' + esc(sub.label) + ' <span>' + esc(sub.ms) + ' ms</span></li>' })
          item.querySelector('.auditsecurity-step-sub').innerHTML = html
        }
        var doneCount = modal.querySelectorAll('.auditsecurity-step.is-done').length
        bar.style.width = Math.round(100 * (doneCount + (_state == 'running' ? 0.5 : 0)) / DIAGNOSTIC_STEPS.length) + '%'
        bar.parentNode.classList.toggle('is-failed', _state == 'failed')
        bar.parentNode.classList.toggle('is-done', doneCount == DIAGNOSTIC_STEPS.length)
      },
      /** Affiche le rapport et active la copie et le téléchargement. */
      showReport: function (_text) {
        text = _text
        url = URL.createObjectURL(new Blob([_text], { type: 'text/plain;charset=utf-8' }))
        var area = modal.querySelector('.auditsecurity-modal-text')
        area.value = _text
        modal.querySelector('.auditsecurity-modal-report').style.display = ''
        // Le rapport s'ouvre sur son début (environnement, contrôles), pas sur la fin du log
        area.scrollTop = 0
        area.setSelectionRange(0, 0)
        var download = modal.querySelector('.auditsecurity-bt-download')
        download.href = url
        download.setAttribute('download', 'auditsecurity-diagnostic-' + new Date().toISOString().slice(0, 10) + '.txt')
        download.style.display = ''
        modal.querySelector('.auditsecurity-bt-copy').style.display = ''
      }
    }
  }

  /** Affiche le log du plugin dans la fenêtre standard de Jeedom. */
  function showLogs() {
    if (typeof jeeDialog !== 'undefined' && typeof jeeDialog.dialog === 'function') {
      jeeDialog.dialog({ id: 'jee_modal', title: '{{Log auditsecurity}}', contentUrl: 'index.php?v=d&modal=log.display&log=auditsecurity' })
    } else {
      window.open('index.php?v=d&p=log&logfile=auditsecurity', '_blank')
    }
  }

  if (document.getElementById('div_asReport')) {
    document.getElementById('bt_asRunAudit').addEventListener('click', runAudit)
    document.getElementById('bt_asEquipment').addEventListener('click', openEquipment)
    document.getElementById('bt_asDiagnostic').addEventListener('click', downloadDiagnostic)
    if (document.getElementById('bt_asLogs')) {
      document.getElementById('bt_asLogs').addEventListener('click', showLogs)
    }

    function setFilter(_filter) {
      state.filter = _filter
      render()
    }

    document.getElementById('as_filters').addEventListener('click', function (event) {
      var button = event.target.closest('[data-filter]')
      if (button) setFilter(button.getAttribute('data-filter'))
    })

    document.getElementById('as_stats').addEventListener('click', function (event) {
      var stat = event.target.closest('[data-filter]')
      if (!stat) return
      state.category = ''
      setFilter(stat.getAttribute('data-filter'))
      document.getElementById('as_filters').scrollIntoView({ behavior: 'smooth', block: 'center' })
    })

    document.getElementById('in_asSearch').addEventListener('input', function () {
      state.search = this.value.trim().toLowerCase()
      render()
    })

    document.getElementById('as_categories').addEventListener('click', function (event) {
      var card = event.target.closest('[data-category]')
      if (!card) return
      var id = card.getAttribute('data-category')
      state.category = (state.category == id) ? '' : id
      if (state.category != '') state.filter = 'all'
      render()
    })

    document.getElementById('as_active_category').addEventListener('click', function (event) {
      if (event.target.closest('.auditsecurity-chip-close')) {
        state.category = ''
        render()
      }
    })

    document.getElementById('as_priorities').addEventListener('click', function (event) {
      var card = event.target.closest('[data-id]')
      if (!card) return
      var id = card.getAttribute('data-id')
      if (event.target.closest('.auditsecurity-bt-fix')) {
        applyFix(id)
      } else if (event.target.closest('.auditsecurity-bt-show')) {
        showCheck(id)
      }
    })

    document.getElementById('as_checks').addEventListener('click', function (event) {
      var row = event.target.closest('.auditsecurity-check')
      if (!row) return
      var id = row.getAttribute('data-id')
      if (event.target.closest('.auditsecurity-bt-fix')) {
        applyFix(id)
      } else if (event.target.closest('.auditsecurity-bt-rerun')) {
        rerun(id)
      } else if (event.target.closest('.auditsecurity-bt-edit')) {
        editCheck(id, event.target.closest('.auditsecurity-bt-edit').getAttribute('data-type'))
      } else if (event.target.closest('.auditsecurity-bt-cancel')) {
        closeForm()
        render()
      } else if (event.target.closest('.auditsecurity-bt-save-ignore')) {
        saveIgnore(id, row)
      } else if (event.target.closest('.auditsecurity-bt-unignore')) {
        unignore(id)
      } else if (event.target.closest('.auditsecurity-bt-save-comment')) {
        saveComment(id, formValue(row, '.auditsecurity-in-comment'))
      } else if (event.target.closest('.auditsecurity-bt-del-comment')) {
        saveComment(id, '')
      } else if (event.target.closest('.auditsecurity-check-head')) {
        state.open[id] = !state.open[id]
        row.classList.toggle('is-open', state.open[id])
      }
    })

    render()
  }
})()
