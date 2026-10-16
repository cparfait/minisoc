# OGO Security (WAF) : journal et état des sites par l'API

OGO protège les sites web publics (WAF, anti-DDoS, robots). Le Mini-SOC lit son API en **HTTPS sortant** : rien
à ouvrir en entrée, rien n'est modifié dans OGO.

- **Journal OGO**, chaque minute (7 derniers jours au premier passage) :
  - attaque en cours sur un site : pic de requêtes bannies, afflux de trafic ou de bande passante, limitation
    de débit atteinte → alerte **UC-17** ;
  - certificat en erreur ou bientôt expiré, DNS ne pointant plus vers OGO → alerte (règle NATIVE) ;
  - site supprimé, utilisateur invité, promu ou retiré, paramètres de protection modifiés → alerte **UC-60** ;
  - nouvelles IP bannies, erreurs 4xx/5xx, configuration courante → événements consultables dans Recherche.
- **État des sites**, chaque heure : protection contournée (*passthrough*), mode audit (détecte sans bloquer),
  site hors ligne ou DNS en erreur → alerte **UC-60** ; le retour à la normale est consigné.
- **Trafic des sites**, tous les quarts d'heure : requêtes reçues, bloquées et bannies sur 24 h, par site, et
  catégories d'attaques → carte « Sites web protégés par OGO » du tableau de bord, affichée dès que le
  connecteur est actif (masquable dans Personnaliser).

## Corrélations par adresse IP
- **UC-62** : une adresse bannie par OGO (ou en tête d'un pic de bannissements) obtient ensuite, sous 72 h, une
  connexion réussie (VPN, portail, Microsoft 365, poste) → alerte critique.
- **UC-61** : une même adresse IP publique en alerte sur au moins deux outils en 24 h (OGO, pare-feu, Microsoft
  365, CrowdSec…) → alerte haute, critique à partir de trois outils. Calculée toutes les 5 minutes.
- **« Vu par OGO »** : dans le détail de toute alerte qui cite une adresse IP publique, le Mini-SOC demande à OGO
  combien de requêtes cette adresse a envoyées aux sites sur 7 jours (bloquées, bannies, sites visés, types
  d'attaques). Réponse mise en cache 10 minutes.

L'API d'OGO ne fournit pas le détail requête par requête : pour enquêter sur une attaque, ouvrir le tableau de
bord OGO (lien « Ouvrir dans OGO Security » de l'alerte).

## Prérequis
- Un compte OGO avec une **clé d'API**. De préférence un compte dédié au rôle **Viewer** (lecture seule), avec
  la double authentification, plutôt que le compte d'un administrateur.
- La VM sort déjà en 443 vers Internet : rien à ajouter dans `sudo minisoc-setup`.

## Étapes
1. Tableau de bord OGO › **Mon compte › Mon profil › Authentification** › **Clé d'API** : générer la clé et la
   copier.
2. Facultatif : **Mon compte › Mon organisation › Paramètres** › **Code de l'organisation** (obligatoire si le
   compte appartient à plusieurs organisations).
3. Mini-SOC › **Intégrations › OGO Security › Configurer** :

| Champ | Valeur |
| --- | --- |
| E-mail du compte OGO | adresse de connexion au tableau de bord du compte qui porte la clé |
| Clé d'API | clé copiée à l'étape 1 |
| Code de l'organisation | vide si le compte n'a qu'une organisation |
| Adresse de l'API | `https://api.ogosecurity.com` (laisser la valeur par défaut) |

4. **Enregistrer**, activer l'intégration, puis **Tester** : le résultat donne l'organisation, le nombre de
   sites protégés et le nombre d'événements au journal sur 24 h.

La clé ne circule jamais : chaque requête porte l'en-tête `X-Ogo-Auth` = e-mail et empreinte MD5 du chemin
appelé et de la clé (méthode du fournisseur Terraform officiel d'OGO).

## Vérifier
- **Intégrations** : la fiche passe à « En service » dans la minute. Sans réponse d'OGO pendant 1 h (clé
  régénérée, compte désactivé), la source est signalée silencieuse (UC-16).
- **Recherche** : `module=ogo` ; à la première heure, un événement `site_state` par site protégé.
- **Tableau de bord** : la carte « Sites web protégés par OGO » apparaît ; chiffres sous un quart d'heure.
  Vide avec « synthèse du trafic indisponible » dans le journal du worker : le rôle du compte ne donne pas accès
  aux métriques (passer au rôle supérieur en lecture).
- Les premières alertes UC-17 donnent la sévérité OGO (1 à 3) : vérifier qu'elle correspond à celle du
  tableau de bord, et ajuster au besoin dans **Paramètres › Détection**.

## En cas d'échec
- « e-mail ou clé d'API refusés » : clé régénérée depuis, ou e-mail différent de celui du compte qui la porte.
- « accès refusé » : le rôle du compte ne donne pas accès au journal ou aux sites de l'organisation.
- « plusieurs organisations » : renseigner le code de l'organisation indiqué dans le message.
