# Géolocalisation GeoLite2 (MaxMind)

Ajoute à chaque adresse IP publique son **pays** et son **opérateur** (hébergeur, FAI). Indispensable pour les règles
« connexion depuis l'étranger » (UC-04, UC-34, UC-35, UC-37) et la qualification automatique des attaques VPN.
Les bases sont téléchargées et interrogées **localement** : aucune adresse n'est envoyée à MaxMind.

## Prérequis
- Un compte **gratuit** MaxMind (GeoLite2), accès HTTPS sortant vers `updates.maxmind.com`.

## Étapes
1. Créer le compte sur maxmind.com (offre GeoLite2), puis *Manage license keys* › **Generate new license key**.
   Noter l'**Account ID** et la **clé** (affichée une seule fois).
2. Sur le serveur du Mini-SOC, dans le fichier `.env` :

```
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=la_cle
COMPOSE_PROFILES=geoip
```

3. Lancer le service de mise à jour (téléchargement immédiat, puis tous les 3 jours) :

```
docker compose up -d geoipupdate
```

4. Renseigner vos **pays habituels** : Paramètres › Détection (codes ISO, ex. `FR`, ou `FR, BE`).

## Vérifier
- Mini-SOC › **Intégrations** : la fiche indique les bases chargées (City, ASN).
- Mini-SOC › **Événements** : les IP publiques affichent leur code pays.

## Bon à savoir
- La licence GeoLite2 demande d'afficher l'attribution MaxMind (faite en bas de la liste des événements) et de
  garder les bases à jour (automatique avec `geoipupdate`).
- Sans compte, on peut déposer manuellement `GeoLite2-City.mmdb` et `GeoLite2-ASN.mmdb` dans `data/geoip/`.
