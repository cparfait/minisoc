# Autres équipements : syslog et CEF

Tout équipement capable d'envoyer du syslog peut être raccordé : bornes Wi-Fi, commutateurs, NAS, serveurs Linux,
autres outils de sécurité. Les messages au format **CEF** sont analysés (et leurs alertes reprises par la règle
NATIVE) ; les autres sont conservés et consultables comme « Syslog générique ».

## Paramètres à saisir sur l'équipement

| Champ | Valeur |
| --- | --- |
| Serveur syslog | {{MINISOC_HOST}} |
| Port | 514 |
| Protocole | TCP de préférence (UDP accepté) |
| Format | CEF si l'équipement le propose, sinon syslog standard (RFC 3164 ou 5424) |

## Exemple : serveur Linux (rsyslog)
Créer `/etc/rsyslog.d/90-minisoc.conf` :

```
auth,authpriv.*  @@{{MINISOC_HOST}}:514
```

puis `sudo systemctl restart rsyslog` (`@@` = TCP, `@` = UDP).

## Vérifier
- Mini-SOC › **Événements** : rechercher le nom de l'équipement.

## Bon à savoir
- Envoyer seulement les journaux utiles à la sécurité (authentification, administration, alertes) : le volume
  inutile ralentit les recherches et occupe le disque.
- Pour un outil qui a son propre format et de l'intérêt pour la détection, demandez l'ajout d'un analyseur dédié.
