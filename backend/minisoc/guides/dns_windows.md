# DNS des contrôleurs de domaine

Chaque poste demande au DNS les noms des sites et serveurs qu'il contacte. Ces requêtes révèlent ce que les autres
journaux ne voient pas : un logiciel malveillant qui cherche son serveur de commande, un tunnel DNS qui fait sortir
des données, un domaine publié comme malveillant par le CERT-FR.

Le Mini-SOC en tire :
- **la chasse aux IOC « domaine »** : un domaine malveillant est retrouvé, sous-domaines compris ;
- **UC-46 Tunnel DNS** : un poste demande des centaines de sous-domaines différents d'un même domaine en 10 minutes ;
- **UC-47 Domaine généré par algorithme** : nom imprononçable (longueur, entropie, peu de voyelles).

> Volume : chaque requête est un événement (plusieurs centaines de milliers par jour pour une collectivité). Les
> requêtes vers la zone interne et les résolutions inverses sont écartées dès le contrôleur (filtre NXLog).

## Prérequis
- NXLog Community Edition (gratuite) installé sur les contrôleurs de domaine qui servent le DNS (déjà le cas pour
  les journaux Windows).

> La lecture directe des événements du serveur DNS (fournisseur ETW) demande le module `im_etw`, réservé à l'édition
> payante de NXLog. Le Mini-SOC utilise donc le **journal de débogage DNS**, natif dans Windows et lisible par
> l'édition gratuite.

## Étapes
1. Console DNS › clic droit sur le serveur › **Propriétés › Journalisation de débogage** : cocher **Enregistrer les
   paquets pour le débogage**, sens **Entrant**, contenu **Requêtes/Transferts**, type **Requête**, protocoles
   **UDP** et **TCP** ; fichier `C:\Windows\System32\dns\dns.log`, taille maximale 500 Mo (500000000).
2. Dans `C:\Program Files\nxlog\conf\nxlog.conf` : décommenter la section **« Requêtes DNS »** de
   `deploy/nxlog/nxlog.conf` ainsi que la route `dns_vers_minisoc`.
3. Remplacer `(5)mairie(5)local(0)` par le nom de votre zone interne dans le filtre (chaque partie du nom est
   précédée de sa longueur : `ville.lan` s'écrit `(5)ville(3)lan(0)`).
4. Redémarrer le service NXLog : `Restart-Service nxlog`.
5. Activer l'intégration dans cette fenêtre.

> Quand le fichier atteint sa taille maximale, le serveur DNS le recrée et NXLog reprend la lecture du nouveau
> fichier. Le journal de débogage coûte un peu de disque et de processeur au contrôleur : surveiller sa charge les
> premiers jours.

## Vérifier
- Page Recherche : `module=dns | top dns.question.registered_domain` affiche les domaines les plus demandés.
- Après quelques jours, ajouter aux **domaines de confiance** (Paramètres › Détection) les éditeurs légitimes qui
  produiraient de faux tunnels (antivirus à réputation DNS, télémétrie).
