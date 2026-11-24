---
layout: default
lang: es_ES
---

# Changelog Auditoría de seguridad

# 23/11/2026 - 0.2.0

- Nueva categoría «Exposición a Internet»: puertos abiertos en el router de Internet por UPnP, exposición vista por Shodan, listas negras de direcciones IP, certificado HTTPS del acceso externo
- Pruebas mediante servicios externos (Shodan, listas negras) activables en la configuración, desactivadas por defecto
- Nuevos controles: servicios peligrosos a la escucha, reinicio pendiente, carpetas sensibles legibles por todos (con corrección automática), archivos SUID/SGID
- fail2ban solo cuenta en la nota si Jeedom está expuesto en Internet
- Nueva interfaz: indicador de la nota, veredicto, prioridades, notas por categoría filtrables, tarjetas desplegables
- Corrección: la interfaz se quedaba en «Auditoría en curso» tras una auditoría

# 23/11/2026 - 0.1.0

- Primera versión (beta)
- 38 controles en 8 categorías: cuentas, acceso, API, Jeedom y plugins, servidor web, sistema, red, copias de seguridad
- Nota sobre 100 y letra de la A a la F, ponderadas por la gravedad; un fallo crítico limita la letra a D
- Correcciones con un clic para 16 controles, con confirmación y vuelta atrás si la configuración del sistema no es válida
- Controles que se pueden ignorar (riesgo aceptado), excluidos de la nota
- Auditoría automática diaria o semanal, mensaje de Jeedom cuando aparece un nuevo problema
- Equipo con los comandos Nota, Letra, Problemas graves, No conformes, A mejorar, Última auditoría, Resumen y Ejecutar la auditoría
- Widget con la letra, la nota y los contadores
- Interfaz en francés, inglés, alemán, español e italiano
