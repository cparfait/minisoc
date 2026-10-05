# Isolation de poste (HarfangLab, Bitdefender)

Depuis une alerte de l'EDR, un analyste peut **isoler le poste du réseau** : il ne communique plus qu'avec la console
de l'EDR (l'analyse à distance et la levée d'isolation restent possibles). C'est le geste d'urgence face à un
rançongiciel ou à un poste piloté à distance.

Garde-fous :
- fonction **désactivée par défaut** (interrupteur de cette fiche) ;
- **jeton ou clé dédiés**, distincts de ceux qui lisent les alertes (qui restent en lecture seule) ;
- seuls les postes cités dans les événements de l'alerte sont proposés (identifiant d'agent lu dans le journal de
  l'EDR) ;
- **confirmation** par la saisie du nom du poste et un motif ;
- trace dans l'historique de l'alerte, la chronologie de l'incident et le journal d'audit.

## HarfangLab
1. Console HarfangLab › *Administration › Utilisateurs* : créer un utilisateur `minisoc-isolation` dont le rôle
   permet **uniquement** l'isolation des agents (et la lecture des agents), puis générer son **jeton d'API**.
2. Vérifier que la **politique** des postes concernés autorise l'isolation (Windows et Linux : option
   « isolation » de la politique ; sinon HarfangLab refuse la demande et le Mini-SOC l'indique).
3. Dans cette fenêtre : « Jeton HarfangLab avec le droit d'isolation ». L'adresse de la console est celle de
   l'intégration HarfangLab.

## Bitdefender GravityZone
1. GravityZone › *Mon compte* › **Clés API** › Ajouter : cocher **Incidents API** (isolation) et **Network API**
   (lecture des postes, pour le test).
2. Dans cette fenêtre : adresse de l'API (celle affichée avec la clé, par défaut
   `https://cloud.gravityzone.bitdefender.com/api`) et la clé.

## Activer et vérifier
1. **Enregistrer**, puis **Tester** : le test lit la liste des agents (aucune isolation).
2. Activer l'interrupteur de la fiche.
3. Sur une alerte HarfangLab ou Bitdefender : bloc **Isoler le poste (EDR)** › Isoler le poste › motif › saisie du
   nom du poste › Confirmer. L'isolation s'applique au prochain contact de l'agent (moins d'une minute).
4. Pour lever : même bloc › **Lever l'isolation** (ou depuis la console de l'EDR).

## Bon à savoir
- Prévenir l'utilisateur : son poste n'a plus accès au réseau ni à Internet.
- Un serveur isolé rend ses services indisponibles : réserver l'isolation des serveurs aux cas graves.
- Définir en interne qui peut isoler et à quelles heures (procédure validée par la DSI).
