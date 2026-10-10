# wp-guard

**Detecta y corrige malware en WordPress de forma segura, desde la línea de comandos y en minutos.**

wp-guard es un escáner y limpiador de seguridad para WordPress, libre (GPL-3.0) y escrito en Bash puro. Nació de limpiar un sitio real comprometido en hosting compartido, así que está pensado para la situación en la que están la mayoría de los dueños de sitios: acceso SSH, [wp-cli](https://wp-cli.org), sin root y sin servicios extra.

*English: [README.md](README.md)*

## ¿Es para ti?

**wp-guard necesita acceso SSH (línea de comandos) a tu hosting.** No es un plugin de WordPress ni tiene interfaz web.

| Tienes... | Entonces... |
|---|---|
| SSH en un hosting Linux (VPS, Hostinger, SiteGround, Cloudways, cPanel con Terminal/SSH) | **wp-guard es para ti.** Instala también [wp-cli](https://wp-cli.org) para las revisiones de base de datos y checksums. |
| Solo un panel, pero puedes crear **Cron Jobs** | En parte: programa `wp-guard watch` y recibe alertas por correo o chat. No podrás corregir desde ahí. Antes busca "Acceso SSH" en tu panel: a menudo es un interruptor sin activar. |
| Ni SSH ni cron | wp-guard no te sirve. Usa un plugin de seguridad (por ejemplo Wordfence o Sucuri) o pide a tu hosting que active SSH. |

Necesitas además Linux, bash 4+ y utilidades GNU (macOS, BSD y Windows no están soportados).

## Inicio rápido

```bash
# 1. instalar (sin root)
git clone https://github.com/balzatech/wp-guard.git && cd wp-guard && bash install.sh

# 2. configuración guiada, una sola vez, desde la carpeta de WordPress
wp-guard init

# 3. mirar y luego corregir
wp-guard scan         # solo lectura
wp-guard fix          # simulación: no cambia nada
wp-guard fix --apply  # pregunta antes; no se borra nada
```

> **Antes de corregir un sitio real, haz un backup** (panel del hosting, o `wp db export` más una copia de los archivos). wp-guard es cuidadoso, pero es una herramienta heurística.

Si ejecutas `wp-guard` sin argumentos en una terminal, aparece un menú.

## Comandos

| Comando | Qué hace | ¿Modifica el sitio? |
|---|---|---|
| `wp-guard init` | Configuración guiada: encuentra WordPress, lee la URL y los administradores, ofrece configurar alertas | No (escribe `~/.wp_auditor/config.sh`) |
| `wp-guard scan [quick]` | Auditoría completa y reporte. `quick` = solo archivos y servidor | No |
| `wp-guard fix [--apply]` | Muestra o aplica las correcciones seguras | Solo con `--apply` |
| `wp-guard undo CARPETA` | Devuelve lo que se puso en cuarentena | Sí (restaura archivos) |
| `wp-guard baseline` | Guarda el estado actual como "limpio" | No |
| `wp-guard watch` | Para cron: avisa solo si cambian las alertas | No |
| `wp-guard notify [setup\|status]` | Configura y prueba los canales de alerta | No |
| `wp-guard cron` | Imprime las líneas de crontab recomendadas | No |

Códigos de salida de `scan`/`watch`: `0` limpio, `1` avisos, `2` alertas.

`wp-guard scan --format json` imprime el resultado como JSON (y nada más) por la salida estándar, útil para scripts, CI o paneles; ver el esquema en [README.md](README.md#json-output). Cada escaneo guarda además una copia `report_*.json` en `~/.wp_auditor/reports/`.

## Ligero con tu servidor

El hosting compartido limita la CPU de toda la cuenta, así que un escáner a máxima velocidad puede hacer que te estrangulen. wp-guard se limita solo: por defecto, todo lo que lanza (`grep`, `find`, wp-cli, `curl`) usa en conjunto **como máximo medio núcleo**, pausando y reanudando sus propios procesos.

```bash
wp-guard scan            # por defecto: hasta 50 % de un núcleo (más lento, amable)
wp-guard scan --cpu 25   # aún más suave, para planes muy pequeños
wp-guard scan --fast     # sin límite: termina antes pero usa más de un núcleo
```

**Además evita repetir trabajo (escaneo incremental).** Tras cada escaneo recuerda qué archivos estaban limpios y qué plugins pasaron la verificación oficial. El siguiente escaneo solo lee lo nuevo o modificado y solo vuelve a lanzar wp-cli para los plugins que cambiaron. En un sitio real (22.000 archivos, 22 plugins) esto redujo la CPU a la mitad (66 s a 29 s) con los mismos hallazgos.

Está diseñado para no ocultar malware: solo se omiten archivos que **no coincidieron con nada**; "sin cambios" exige mismo tamaño, mtime **y ctime** (el ctime no se falsea con `touch`); el caché se descarta si cambian las reglas o la configuración, cada 7 días y con `--full`; y solo se guardan verificaciones exitosas.

```bash
wp-guard scan --full     # leer todo de nuevo, ignorando el caché
```

Medido en un sitio real: sin límite 41 s a ~160 % de CPU; por defecto 130 s a ~51 % la primera vez y unos 55 s en los siguientes escaneos.

## Qué hace `fix` (y qué no)

Solo con alta confianza y siempre después de una simulación:

- **Pone en cuarentena:** ejecutables dentro de `uploads/`, imágenes con PHP dentro, PHP en carpetas que no deberían tenerlo, PHP ajeno en la raíz, archivos con marcas conocidas del atacante, archivos extra en el núcleo o en plugins oficiales, carpetas de plugin falsas.
- **Restaura** el núcleo de WordPress modificado y **reinstala** plugins oficiales modificados (misma versión) desde wordpress.org.
- Quita permisos de escritura para todos, bloquea PHP en `uploads/` y baja de rol a administradores no autorizados.

**No** borra nada, no toca archivos de menos de 30 minutos (`MIN_AGE_MIN`), no limpia filas infectadas de la base de datos de forma automática ni "repara" temas de terceros o plugins premium. Lo que no puede corregir aparece en el reporte para revisión manual.

Red de seguridad: cuarentena con manifiesto (ruta original, sha256, motivo) en `~/.wp_auditor/quarantine/`; `wp-guard undo` restaura byte a byte; el tope `MAX_HEAL` (25) detiene la ejecución si demasiadas cosas parecen malas a la vez; y `fix` sin `--apply` nunca escribe.

## Alertas

```bash
wp-guard notify setup     # Slack / Discord / ntfy / Telegram / correo, con mensaje de prueba real
wp-guard notify status
```

`watch` avisa solo cuando el conjunto de alertas **cambia**. Si no hay ningún canal configurado, wp-guard lo dice en lugar de callar.

## Automatizar

`wp-guard cron` imprime las líneas. Lo habitual: un `watch` diario (solo lectura) y, tras una o dos semanas de simulaciones, un `fix --apply` periódico. En hostings sin `crontab` por SSH (p. ej. Hostinger) pégalas en la sección Cron Jobs del panel.

## Falsos positivos

Agrega la ruta o un fragmento de texto, uno por línea, a `~/.wp_auditor/allow.txt`.

## Requisitos

Linux con **bash 4+** y utilidades GNU (`find`, `stat`, `xargs`, `grep`, `awk`, `sed`). Se recomienda **wp-cli** (sin él se omiten la base de datos y los checksums oficiales) y `curl` para las pruebas HTTP y las alertas. Probado en hosting compartido (Hostinger).

## Limitaciones — léelas

- wp-guard es una **ayuda de detección y limpieza**, no un firewall ni una garantía. Puede dar falsos positivos y un atacante decidido puede evadirlo.
- Limpiar archivos no cierra la puerta por la que entró el atacante. Tras un incidente: actualiza todo, elimina plugins y temas sin uso, cambia todas las contraseñas y las claves/salts de `wp-config.php`, revisa los usuarios y, ante la duda, restaura desde un backup limpio.
- Mantén siempre **backups** y revisa la simulación antes de aplicar.
- Un antivirus puede marcar los archivos de reglas o de pruebas porque describen malware; contienen patrones, no malware funcional.

## Más información

Guía de reglas: [docs/rules.md](docs/rules.md) (en inglés) · Contribuir: [CONTRIBUTING.md](CONTRIBUTING.md) · Seguridad: [SECURITY.md](SECURITY.md) · Licencia: [GPL-3.0-or-later](LICENSE), sin garantía.
