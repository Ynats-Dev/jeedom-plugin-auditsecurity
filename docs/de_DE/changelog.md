---
layout: default
lang: de_DE
---

# Changelog Sicherheitsaudit

# 23/11/2026 - 0.2.0

- Neue Kategorie „Internet-Erreichbarkeit“: per UPnP am Internet-Router geöffnete Ports, von Shodan gesehene Erreichbarkeit, IP-Blacklists, HTTPS-Zertifikat des externen Zugriffs
- Prüfungen über externe Dienste (Shodan, Blacklists) in der Konfiguration aktivierbar, standardmäßig deaktiviert
- Neue Prüfungen: gefährliche lauschende Dienste, ausstehender Neustart, für alle lesbare sensible Ordner (mit automatischer Korrektur), SUID/SGID-Dateien
- fail2ban zählt nur zur Bewertung, wenn Jeedom aus dem Internet erreichbar ist
- Neue Oberfläche: Bewertungsanzeige, Urteil, Prioritäten, filterbare Bewertungen pro Kategorie, aufklappbare Karten
- Korrektur: Die Oberfläche blieb nach einem Audit auf „Audit läuft“

# 23/11/2026 - 0.1.0

- Erste Version (Beta)
- 38 Prüfungen in 8 Kategorien: Konten, Zugriff, API, Jeedom und Plugins, Webserver, System, Netzwerk, Sicherungen
- Bewertung von 100 Punkten und Note von A bis F, nach Schweregrad gewichtet; eine kritische Lücke begrenzt die Note auf D
- Korrektur mit einem Klick für 16 Prüfungen, mit Bestätigung und Rücknahme bei ungültiger Systemkonfiguration
- Prüfungen können ignoriert werden (akzeptiertes Risiko) und zählen dann nicht zur Bewertung
- Tägliches oder wöchentliches automatisches Audit, Jeedom-Nachricht bei neuen Problemen
- Gerät mit den Befehlen Bewertung, Note, Schwere Probleme, Nicht konform, Zu verbessern, Letztes Audit, Zusammenfassung und Audit starten
- Widget mit Note, Bewertung und Zählern
- Oberfläche auf Französisch, Englisch, Deutsch, Spanisch und Italienisch
