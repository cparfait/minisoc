# DNS des contrôleurs de domaine

Chaque poste demande au DNS les noms des sites et serveurs qu'il contacte. Ces requêtes révèlent ce que les autres
journaux ne voient pas : un logiciel malveillant qui cherche son serveur de commande, un tunnel DNS qui fait sortir
des données, un domaine publié comme malveillant par le CERT-FR.

Le Mini-SOC en tire :
- **la chasse aux IOC « domaine »** : un domaine malveillant est retrouvé, sous-domaines compris ;
- **UC-46 Tunnel DNS** : un poste demande des centaines de sous-domaines différents d'un même domaine en 10 minutes ;
- **UC-47 Domaine généré par algorithme** : nom imprononçable (longueur, entropie, peu de voyelles).

> Volume : chaque requête est un événement (plusieurs centaines de milliers par jour pour une collectivité). Les
> requêtes vers la zone interne et la résolution inverse sont écartées dès le contrôleur (filtre NXLog).

## Prérequis
- NXLog installé sur les contrôleurs de domaine qui servent le DNS (déjà le cas pour les journaux Windows).
- Windows Server 2016 ou plus récent (fournisseur ETW « Microsoft-Windows-DNSServer »).

## Étapes
1. Dans `C:\Program Files\nxlog\conf\nxlog.conf` : décommenter la section **« Requêtes DNS »** de
   `deploy/nxlog/nxlog.conf` (**option A**, ETW), ainsi que la route `dns_vers_minisoc`.
2. Remplacer `mairie\.local` par le nom de votre zone interne dans le filtre.
3. Redémarrer le service NXLog : `Restart-Service nxlog`.
4. Activer l'intégration dans cette fenêtre.

**Option B** (si l'ETW n'est pas disponible) : activer la journalisation de débogage du serveur DNS (Console DNS ›
Propriétés › Journalisation de débogage : paquets **entrants**, **requêtes**, UDP et TCP, fichier
`C:\Windows\System32\dns\dns.log`) et utiliser la seconde variante de la section NXLog.

## Vérifier
- Page Recherche : `module=dns | top dns.question.registered_domain` affiche les domaines les plus demandés.
- Après quelques jours, ajouter aux **domaines de confiance** (Paramètres › Détection) les éditeurs légitimes qui
  produiraient de faux tunnels (antivirus à réputation DNS, télémétrie).
