# HarfangLab EDR : lecture des alertes par l'API

Le Mini-SOC interroge la console HarfangLab chaque minute et récupère les nouvelles alertes (Sigma, YARA, IOC, IA,
RansomGuard). Chaque alerte garde un lien direct vers la console pour la traiter.

## Prérequis
- Le Mini-SOC doit joindre la console HarfangLab en HTTPS (ex. `https://xxxx.hurukai.io:8443` pour l'offre cloud,
  ou l'adresse du serveur interne).
- Un accès administrateur à la console HarfangLab pour créer le compte d'API.

## Étapes
1. Console HarfangLab › **Administration › Utilisateurs** › créer un utilisateur dédié, par exemple
   `minisoc-api`, avec un rôle **en lecture seule** (aucun droit d'action sur les postes).
2. Sur la fiche de cet utilisateur : **Générer un jeton d'API** ; copier le jeton (il ne sera plus affiché).
3. Dans cette fenêtre (onglet Configuration) :
   - **Adresse de la console** : l'URL de la console, sans chemin (ex. `https://xxxx.hurukai.io:8443`) ;
   - **Jeton d'API** : le jeton copié ;
   - **Vérifier le certificat** : coché (décocher seulement pour une console interne à certificat auto-signé).
4. **Enregistrer**, puis **Tester** : le test indique le nombre d'alertes accessibles.

Le rôle en lecture seule doit aussi pouvoir lire la **liste des agents** (Endpoints › Agents) : chaque heure, le
Mini-SOC signale les machines en service (relevé NinjaOne de moins de 7 jours) sans agent HarfangLab, ou dont l'agent
est muet depuis plus de 7 jours (règle UC-59 « Pas d'EDR sur … », après 24 heures de constat, close d'elle-même quand
l'agent revient). Les adresses IP des agents servent aussi à reconnaître une machine que Vectra ne connaît que par
son adresse. État : page **Veille** › Couverture antivirus et EDR.

## Vérifier
- Les alertes des dernières 24 h sont importées au premier passage ; Mini-SOC › **Alertes**, source HarfangLab.
- Sur une alerte : bouton « Gérer dans HarfangLab ↗ » qui ouvre l'alerte dans la console.

## Dépannage
- **HTTP 401/403** : jeton expiré, révoqué, ou utilisateur sans droit de lecture des alertes.
- **Erreur de certificat** : console interne à certificat privé : décocher « Vérifier le certificat » ou installer
  l'autorité de certification.
- Le statut d'une alerte (prise en charge, clôture) se gère dans la console HarfangLab ; le Mini-SOC ne le modifie
  pas (jeton en lecture seule).
