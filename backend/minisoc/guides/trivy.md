# Trivy : vulnérabilités des images Docker et des serveurs

Trivy (Aqua Security, open source) liste les composants vulnérables d'une image Docker ou d'un système : paquets
Alpine, Debian, Ubuntu, Red Hat, et bibliothèques (Python, Go, Node…). Le Mini-SOC l'utilise de deux façons.

- **VM du Mini-SOC** : rien à installer. Le service `minisoc-trivy` de la VM analyse chaque lundi matin, après
  chaque mise à jour et à la demande (« Analyser maintenant ») toutes les images de l'application (y compris
  celle de Trivy) et les paquets Debian de la VM.
- **Serveurs** : l'agent `minisoc-trivy-agent` analyse chaque semaine les images des conteneurs en service et les
  paquets du système, puis envoie son rapport au Mini-SOC en HTTPS, avec un jeton propre au serveur.

Ce qui est remonté :
- page **Vulnérabilités** : chaque source (dernière analyse, failles critiques et hautes corrigeables, failles
  activement exploitées) ; dans la fiche d'une CVE, l'image ou le serveur touché, le composant, la version
  installée et **la version qui corrige** ;
- **faille activement exploitée présente** (catalogue CISA KEV, règle UC-52) ;
- **faille critique corrigeable** (UC-53) ; aussi les failles hautes corrigeables si l'option est cochée.

> Seules les failles **nouvelles par rapport au rapport précédent** donnent une alerte, regroupées en une alerte par
> source et par nature. Le tout premier rapport d'une source signale donc ce qui est déjà présent ; les suivants,
> seulement ce qui apparaît. L'état complet reste consultable à tout moment sur la page Vulnérabilités.

## Sécurité
- Sur la VM, l'analyse tourne sur l'hôte (service systemd) : chaque image est exportée puis lue par un conteneur
  Trivy jetable, **sans socket Docker**, en lecture seule et sans privilège. Seule sortie : la base des failles de
  Trivy (`ghcr.io`, `pkg-containers.githubusercontent.com`, déjà autorisés pour l'installation).
- Un serveur n'envoie que des rapports : son jeton ne donne accès à rien d'autre dans le Mini-SOC. Il est
  révocable à tout moment et peut être limité à l'adresse du serveur.

## Images du Mini-SOC
1. Rien à configurer. La fiche montre la dernière analyse ; « Analyser maintenant » la relance (quelques minutes).
2. Une faille dans une image du Mini-SOC se corrige en appliquant le dernier paquet de mise à jour
   (`sudo minisoc-update`) : les images sont reconstruites avec les correctifs publiés, puis analysées de nouveau.
3. Sur la VM : `sudo systemctl status minisoc-trivy` (dernière analyse), `sudo systemctl start minisoc-trivy`
   (analyse immédiate), `systemctl list-timers minisoc-trivy.timer` (prochaine analyse).

## Raccorder un serveur Linux
1. **Trivy sur le serveur** : paquet `trivy` du dépôt d'Aqua Security (https://trivy.dev, rubrique installation),
   ou Docker (l'agent utilise alors l'image `aquasec/trivy`). Le serveur doit joindre `ghcr.io` en 443.
2. **Jeton** : ici, onglet Configuration › Serveurs : nom du serveur et, de préférence, son adresse IP ;
   **Créer le jeton**, puis le copier (il n'est affiché qu'une fois).
3. **Agent** : « Télécharger l'agent (Linux) », copier le fichier sur le serveur, puis en root :
   ```
   bash minisoc-trivy-agent.sh install <JETON> /chemin/autorite-minisoc.pem
   ```
   Le dernier argument est le certificat de l'autorité qui signe le certificat du Mini-SOC (autorité interne de
   Caddy ou PKI de la collectivité), s'il n'est pas déjà dans le magasin du serveur. L'installation lance une
   première analyse et l'envoie.
4. **Pare-feu de la VM** : `sudo minisoc-setup` › Entrants › **Serveurs Trivy** : ajouter l'adresse du serveur
   (443/TCP vers la VM), puis Appliquer. Autoriser aussi ce flux sur le XGS si le serveur est dans une autre zone.
   Cette liste ne donne que l'envoi des rapports (`POST /api/ingest/trivy`) : l'interface web et le reste de l'API
   répondent 403 à ces serveurs, sauf adresse aussi déclarée en administration ou en écran mural.
5. Vérifier : la ligne du serveur apparaît dans la fiche (« Dernier rapport ») et sur la page Vulnérabilités.

Réglages de l'agent : `/etc/minisoc-trivy-agent.conf` (images analysées : `running`, `all` ou `none` ; paquets du
système : `yes` ou `no`). Planification : `/etc/cron.d/minisoc-trivy-agent` (une fois par semaine, la nuit).
Analyse immédiate : `sudo minisoc-trivy-agent run`. Retrait : `sudo minisoc-trivy-agent uninstall`, puis
**Révoquer** le jeton ici.

## En cas de problème
- « Analyse de la VM en échec » : `sudo journalctl -u minisoc-trivy -n 50` (base des failles injoignable,
  disque plein…).
- Serveur refusé : HTTP 401 (jeton erroné ou révoqué), 403 avec un message (adresse non autorisée pour ce jeton,
  ou intégration désactivée), 403 sans message (envoi ailleurs qu'à `POST <adresse du Mini-SOC>/api/ingest/trivy`) ;
  aucune réponse : pare-feu de la VM (liste Serveurs Trivy) ou du XGS.
- Source silencieuse : aucun rapport depuis 8 jours (agent arrêté, cron supprimé, base des failles injoignable).
