# Cyberwatch : vulnérabilités par actif (lecture seule)

Le Mini-SOC lit l'API v3 de Cyberwatch avec une clé d'API : uniquement des lectures (`GET`), aucun scan lancé,
aucune CVE ignorée, aucun correctif déclenché.

Ce qui est remonté (relevé toutes les 30 minutes, seulement ce qui change) :
- **faille activement exploitée présente** sur un actif : CVE non corrigée qui figure au catalogue CISA KEV
  (règle UC-48 ; haute sur un serveur, moyenne sur un poste) ;
- **nouvelles vulnérabilités prioritaires** d'un serveur selon la priorisation de Cyberwatch (UC-49) ;
- **système d'exploitation en fin de support** (UC-50) ;
- page **Veille** : actifs les plus exposés (failles KEV, vulnérabilités prioritaires, fin de support, redémarrage
  requis) avec un lien vers la fiche Cyberwatch ;
- classement **Machines à corriger en premier** (tableau de bord) et **inventaire des actifs** (machines ajoutées
  à la synchronisation).

> Le **premier relevé** (et celui d'un actif nouvellement ajouté) est un **état des lieux sans alerte** : sur un parc
> réel, des dizaines de failles connues, pas des nouveautés. Il est consultable sur la page Veille, dans le classement
> « À corriger en priorité » et dans la **recherche par CVE** (page Vulnérabilités). Ensuite, toute nouvelle faille
> KEV sur n'importe quelle machine est signalée ; l'anti-tempête regroupe les vagues.
> Les CVE triées dans Cyberwatch comme ignorées, risque accepté ou faux positif ne comptent plus comme présentes.

Contrairement à NinjaOne, Cyberwatch donne les numéros de CVE de chaque actif : le croisement avec le catalogue KEV
est fait sur les failles **présentes**, pas seulement sur celles citées par une détection (UC-22). Quand une CVE
entre au catalogue KEV, les actifs concernés sont signalés au relevé suivant, sans nouvelle analyse.

## Prérequis
- Accès HTTPS du Mini-SOC vers l'instance Cyberwatch (sur le réseau local).
- La veille CISA KEV active (Intégrations › Veille CISA KEV et CERT-FR) pour le croisement.

## Étapes
1. Cyberwatch › **Mon profil › Clés d'API › Ajouter** : nom « Mini-SOC », accès **en lecture seule**. Copier l'**ID
   de la clé d'accès** et son **secret** (affiché une seule fois).
2. Dans cette fenêtre (onglet Configuration) : adresse de l'instance (`https://cyberwatch.mairie.local`), ID et
   secret de la clé.
3. Certificat émis par une autorité interne : coller le certificat de l'autorité (PEM). Ne décocher « Vérifier le
   certificat » qu'en dernier recours.
4. **Enregistrer**, puis **Tester** : le test appelle `/api/v3/ping` puis lit une page des actifs.

## Vérifier
- Mini-SOC › **Veille** : carte « Vulnérabilités : actifs les plus exposés (Cyberwatch) » remplie après le premier
  relevé (de quelques secondes à quelques minutes selon la taille du parc).
- Mini-SOC › **Événements**, source Cyberwatch : changements détectés.

## Synchronisation des statuts
Option « Clôturer ici ce qui est corrigé dans Cyberwatch » (activée par défaut) : quand toutes les CVE signalées
par une alerte ont disparu de l'actif (corrigées, ou ignorées dans Cyberwatch : risque accepté) ou que le système a
été mis à niveau, l'alerte est clôturée dans le Mini-SOC avec une trace dans son historique. Rien n'est supprimé.

## Dépannage
- **« clé d'API Cyberwatch refusée »** (401) : ID ou secret mal copié, clé révoquée.
- **« droits insuffisants »** (403) : la clé n'a pas accès aux actifs ; vérifier les droits du compte qui l'a créée.
- **Erreur de certificat** : renseigner le certificat de l'autorité interne (PEM).
- **Gros parcs** : au plus 400 actifs relus en détail par relevé ; la suite est lue aux relevés suivants.
