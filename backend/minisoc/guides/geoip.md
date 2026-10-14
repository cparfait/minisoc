# Géolocalisation GeoLite2 (MaxMind)

Ajoute à chaque adresse IP publique son **pays** et son **opérateur** (hébergeur, FAI). Indispensable pour les règles
« connexion depuis l'étranger » (UC-04, UC-34, UC-35, UC-37) et la qualification automatique des attaques VPN.
Les bases sont téléchargées par le Mini-SOC et interrogées **localement** : aucune adresse n'est envoyée à MaxMind.

## Prérequis
- Un compte **gratuit** MaxMind (GeoLite2). Accès HTTPS sortant vers `download.maxmind.com` (déjà autorisé).

## Étapes
1. Créer le compte sur maxmind.com (offre **GeoLite2**, gratuite).
2. Dans le compte MaxMind : *Account* › **Manage License Keys** › **Generate new license key**. Copier la **clé**
   (affichée une seule fois) et noter l'**Account ID** (numéro affiché dans *Account Information*).
3. Dans cette fenêtre (onglet Configuration) : identifiant du compte et clé de licence. **Enregistrer**, puis
   **Tester** : MaxMind confirme l'identifiant et la clé.
4. Activer l'intégration (interrupteur de la fiche). Le Mini-SOC télécharge les bases GeoLite2-City (pays) et
   GeoLite2-ASN (opérateur) dans les 5 minutes, puis les met à jour tous les 3 jours.
5. Renseigner vos **pays habituels** : Paramètres › Détection (codes ISO, ex. `FR`, ou `FR, BE`).

## Vérifier
- Mini-SOC › **Intégrations** : la fiche passe à « Active » et indique les bases chargées et leur date.
- Mini-SOC › **Événements** : les IP publiques affichent leur code pays.

## Dépannage
- **« identifiant de compte ou clé de licence MaxMind refusés »** : clé mal copiée ou révoquée ; en générer une
  nouvelle. L'identifiant est un nombre (Account ID), pas l'adresse e-mail du compte.
- **« Téléchargement en échec »** : nouvel essai automatique toutes les heures ; enregistrer une nouvelle clé relance
  le téléchargement tout de suite.

## Bon à savoir
- La licence GeoLite2 demande d'afficher l'attribution MaxMind (faite en bas de la liste des événements) et de
  garder les bases à jour (automatique).
