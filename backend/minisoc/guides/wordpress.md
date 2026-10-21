# WordPress : mises à jour et failles connues des sites

Chaque jour, le Mini-SOC fait l'inventaire de chaque site WordPress déclaré : version de WordPress, extensions,
thèmes, et la dernière version publiée de chacun (api.wordpress.org). La page **Vulnérabilités** affiche, site par
site, ce qu'il faut mettre à jour. Avec un jeton **WPScan**, les failles connues des versions installées sont
ajoutées : une faille nouvelle donne l'alerte **UC-64**.

Tout se fait en **lecture seule** et en HTTPS sortant : le Mini-SOC ne modifie rien sur les sites et ne lance
aucune attaque (pas d'essai de mots de passe, pas de recherche de fichiers cachés).

## Deux façons d'inventorier un site
| | Avec mot de passe d'application (recommandé) | Sans identifiant |
| --- | --- | --- |
| Extensions et thèmes | liste exacte, actifs et désactivés (API REST) | seulement ceux visibles dans la page d'accueil |
| Versions | exactes | lues dans `readme.txt` / `style.css`, parfois absentes |
| Prérequis | compte administrateur sur le site | aucun |

La version de WordPress est lue dans la balise « generator » (page d'accueil ou flux RSS). Si une extension de
sécurité la masque, elle s'affiche « masquée » : vérifier alors dans le tableau de bord du site.

## Étapes
1. **Sur chaque site** (recommandé) : créer un compte administrateur dédié, par exemple `minisoc`, avec un mot de
   passe long. Lister les extensions demande le rôle Administrateur : WordPress n'a pas de rôle en lecture seule.
2. Se connecter avec ce compte › **Utilisateurs › Profil › Mots de passe d'application** : nom « Mini-SOC » ›
   **Ajouter un nouveau mot de passe d'application** ; copier le mot de passe affiché (une seule fois).
   Le Mini-SOC ne sert qu'à lire : ce mot de passe peut être révoqué à tout moment depuis le même écran.
3. Mini-SOC › Intégrations › **WordPress** › onglet Configuration › **Sites WordPress** : adresse du site
   (`https://www.mairie.fr`), identifiant et mot de passe d'application ; Ajouter. Sans identifiant ni mot de passe,
   le site est inventorié par sa partie publique.
4. Facultatif, pour les failles et les alertes : créer un compte gratuit sur **wpscan.com**, copier le jeton
   (Profil › API Token) dans « Jeton d'API WPScan ». L'offre gratuite donne 25 requêtes par jour : une par
   extension ou thème, une pour WordPress ; les réponses sont gardées 7 jours, le reste est vérifié les jours
   suivants.
5. Activer l'intégration, Enregistrer, **Tester** (inventaire du premier site), puis **Analyser maintenant**.

## Sites hébergés sur le réseau interne
Les conteneurs du Mini-SOC ne joignent Internet qu'en HTTPS et n'ont pas accès au réseau interne par défaut.
Pour un site interne, l'autoriser sur la VM : `sudo minisoc-setup` › Accès sortants › **Autres (LAN)** ›
`<IP du serveur>:443`.

## Vérifier
1. Intégrations › WordPress › **Tester** : « WordPress 6.x, N extension(s), N thème(s) — API REST (liste exacte) ».
2. **Analyser maintenant**, puis page **Vulnérabilités** › cadre « Sites WordPress » : une ligne par site, et le
   détail des composants à mettre à jour.

## Dépannage
- **« identifiant ou mot de passe d'application refusé »** : le compte n'est pas administrateur, le mot de passe
  d'application a été révoqué, ou une extension de sécurité bloque l'authentification de l'API REST (Wordfence,
  iThemes Security : autoriser les mots de passe d'application).
- **« API REST introuvable »** : une extension désactive l'API REST pour les visiteurs ; l'autoriser pour les
  utilisateurs connectés.
- **« site injoignable »** : site interne non autorisé en sortie (voir ci-dessus), ou certificat non reconnu
  (option « Vérifier le certificat des sites »).
- **Extension sans dernière version** : extension payante ou développée sur mesure, absente de l'annuaire
  wordpress.org ; vérifier ses mises à jour chez son éditeur.
- **Quota WPScan atteint** : signalé sur la fiche ; la vérification continue le lendemain.
