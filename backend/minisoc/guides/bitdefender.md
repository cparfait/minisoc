# Bitdefender GravityZone : lecture des incidents par l'API

Le Mini-SOC **interroge** l'API publique de GravityZone chaque minute, en HTTPS sortant. Il n'est jamais
joignable depuis Internet : le service « Event Push », qui exigeait de publier une adresse sur Internet, n'est pas
utilisé.

Ce qui est remonté :
- les **incidents** EDR (Endpoint et Organisation) : nouveaux incidents et nouvelle activité sur un incident ; la
  sévérité suit le score de gravité de GravityZone (1 à 100) ; lien direct vers l'incident dans la console ;
- les **fichiers mis en quarantaine** (menace neutralisée par l'antivirus) ;
- la **clôture** : un incident clôturé ou classé faux positif dans GravityZone est clôturé dans le Mini-SOC, avec
  une trace dans l'historique. L'état « en investigation » est aussi affiché.

> Non disponibles par l'API : les détections antivirus nettoyées ou supprimées sans quarantaine, l'antihameçonnage,
> les attaques réseau et les modules désactivés (seulement par Event Push, non retenu car il exige une publication
> sur Internet). Les incidents EDR couvrent les attaques actives, dont les rançongiciels.

## Prérequis
- Une licence GravityZone donnant accès aux **incidents** (EDR ou XDR) ; sans elle, seule la quarantaine est lue.
- Accès HTTPS sortant du Mini-SOC vers `cloudgz.gravityzone.bitdefender.com` (port 443, déjà autorisé).

## Étapes
1. GravityZone › icône de profil › **Mon compte** › section **Control Center API** : noter l'**Access URL**
   (par exemple `https://cloudgz.gravityzone.bitdefender.com/api`).
2. **Clés API** › **Ajouter** : description « Mini-SOC (lecture) », cocher **Incidents API** et **Quarantine API**
   uniquement. Copier la clé (affichée une seule fois).
3. Dans cette fenêtre (onglet Configuration) : adresse d'accès et clé de lecture. **Enregistrer**, puis **Tester** :
   le test lit les incidents et la quarantaine des dernières 24 heures et indique ce qui est accessible.

> La clé « Incidents API » permet aussi, côté GravityZone, des actions (isolation, liste de blocage) : le Mini-SOC
> ne les utilise pas avec cette clé, mais elle est sensible. Elle est chiffrée dans le Mini-SOC et n'est jamais
> réaffichée. L'isolation de poste (Réponse) utilise une clé distincte, désactivée par défaut.

## Vérifier
- Mini-SOC › **Intégrations** : la fiche passe à « En service » au premier relevé (une minute).
- Mini-SOC › **Événements**, source Bitdefender : incidents et quarantaine des 7 derniers jours au premier relevé.

## Dépannage
- **« API Key is not allowed to access the selected API »** : l'API concernée n'est pas cochée sur la clé.
- **Incidents illisibles, quarantaine lisible** : licence sans accès aux incidents.
- **HTTP 429** : limite de requêtes de la clé ; le Mini-SOC attend et réessaie automatiquement.
