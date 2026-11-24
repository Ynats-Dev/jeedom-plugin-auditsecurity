---
layout: default
lang: it_IT
---

# Changelog Audit di sicurezza

# 23/11/2026 - 0.2.0

- Nuova categoria «Esposizione su Internet»: porte aperte sul router Internet tramite UPnP, esposizione vista da Shodan, liste nere di indirizzi IP, certificato HTTPS dell'accesso esterno
- Test tramite servizi esterni (Shodan, liste nere) attivabili nella configurazione, disattivati per impostazione predefinita
- Nuovi controlli: servizi pericolosi in ascolto, riavvio in attesa, cartelle sensibili leggibili da tutti (con correzione automatica), file SUID/SGID
- fail2ban conta nel punteggio solo se Jeedom è esposto su Internet
- Nuova interfaccia: indicatore del punteggio, verdetto, priorità, punteggi per categoria filtrabili, schede espandibili
- Correzione: l'interfaccia restava su «Audit in corso» dopo un audit

# 23/11/2026 - 0.1.0

- Prima versione (beta)
- 38 controlli in 8 categorie: account, accesso, API, Jeedom e plugin, server web, sistema, rete, backup
- Punteggio su 100 e lettera da A a F, ponderati per gravità; una falla critica limita la lettera a D
- Correzioni con un clic per 16 controlli, con conferma e ripristino se la configurazione di sistema non è valida
- Controlli ignorabili (rischio accettato), esclusi dal punteggio
- Audit automatico giornaliero o settimanale, messaggio Jeedom quando compare un nuovo problema
- Dispositivo con i comandi Punteggio, Lettera, Problemi gravi, Non conformi, Da migliorare, Ultimo audit, Riepilogo e Avvia l'audit
- Widget con la lettera, il punteggio e i contatori
- Interfaccia in francese, inglese, tedesco, spagnolo e italiano
