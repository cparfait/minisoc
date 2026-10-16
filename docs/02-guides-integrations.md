# Guides d'installation des intégrations

Chaque intégration a son guide pas à pas : prérequis, étapes, vérification, dépannage. Il est affiché dans le
Mini-SOC (Intégrations › une fiche › onglet **Guide d'installation**, ouvert automatiquement à l'activation d'une
intégration pas encore raccordée), avec l'adresse du Mini-SOC déjà renseignée, et téléchargeable.

| Intégration | Mode | Guide |
| --- | --- | --- |
| Sophos Firewall (XGS) | syslog | [sophos_xgs.md](../backend/minisoc/guides/sophos_xgs.md) |
| Bitdefender GravityZone | API (HTTPS sortant) | [bitdefender.md](../backend/minisoc/guides/bitdefender.md) |
| HarfangLab EDR | API | [harfanglab.md](../backend/minisoc/guides/harfanglab.md) |
| CrowdSec | API locale | [crowdsec.md](../backend/minisoc/guides/crowdsec.md) |
| Active Directory / Windows, serveurs de fichiers | NXLog | [windows.md](../backend/minisoc/guides/windows.md) |
| Microsoft 365 / Entra ID | API Office 365 Management | [m365.md](../backend/minisoc/guides/m365.md) |
| Vectra AI | API (client d'API en lecture seule) ou syslog CEF | [vectra.md](../backend/minisoc/guides/vectra.md) |
| Varonis | syslog CEF | [varonis.md](../backend/minisoc/guides/varonis.md) |
| Autres équipements | syslog / CEF | [cef.md](../backend/minisoc/guides/cef.md) |
| Géolocalisation GeoLite2 | bases locales | [geoip.md](../backend/minisoc/guides/geoip.md) |
| Veille CISA KEV et CERT-FR | flux publics | [veille.md](../backend/minisoc/guides/veille.md) |
| Blocage d'IP sur le Sophos XGS | API XML | [xgs_response.md](../backend/minisoc/guides/xgs_response.md) |
| Assistant IA | API | [ai.md](../backend/minisoc/guides/ai.md) |
| Cyberwatch (vulnérabilités) | API (lecture seule) | [cyberwatch.md](../backend/minisoc/guides/cyberwatch.md) |
| OGO Security (WAF) | API (clé d'API, lecture seule) | [ogo.md](../backend/minisoc/guides/ogo.md) |
| NinjaOne, isolation de poste | à venir | [ninjaone.md](../backend/minisoc/guides/ninjaone.md), [edr_isolation.md](../backend/minisoc/guides/edr_isolation.md) |

Ordre conseillé pour la mise en service sur la VM : GeoIP et veille, Sophos XGS, Active Directory, HarfangLab
(déjà raccordé), Microsoft 365, CrowdSec, Bitdefender et Varonis (API, flux sortants), puis Vectra et OGO.
Le marqueur `{{MINISOC_HOST}}` des fichiers est remplacé à l'affichage par l'adresse du Mini-SOC.
