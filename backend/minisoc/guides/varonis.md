# Varonis : alertes DatAlert en syslog CEF

Varonis DatAlert surveille l'accès aux données (partages, AD, Microsoft 365) et lève des alertes : accès massifs,
comportement de rançongiciel, modifications de droits. Ces alertes sont envoyées au Mini-SOC en CEF.

## Prérequis
- Le serveur Varonis (IDU / DatAlert) doit joindre le Mini-SOC **{{MINISOC_HOST}}** sur le port **514/TCP**.

## Étapes
1. Console Varonis › **DatAlert › Configuration › Méthodes d'alerte** (Alert Methods) › **Syslog**.
2. Renseigner le serveur syslog :

| Champ | Valeur |
| --- | --- |
| Serveur | {{MINISOC_HOST}} |
| Port | 514 |
| Protocole | TCP |
| Format du message | CEF |

3. Dans les **politiques / règles d'alerte** à transmettre (au minimum les règles de sévérité moyenne et plus,
   et toutes les règles « rançongiciel »), cocher la méthode d'alerte **Syslog**.
4. Enregistrer et envoyer un message de test si la console le propose.

## Vérifier
- Mini-SOC › **Événements**, source Varonis : les alertes apparaissent ; Mini-SOC › **Alertes** (règle NATIVE).

## Dépannage
- **Événements « Syslog générique »** : vérifier que le format choisi est bien CEF.
- **Rien n'arrive** : méthode Syslog non cochée sur les règles d'alerte, ou flux 514/TCP bloqué.
