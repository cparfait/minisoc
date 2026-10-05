# Mini-SOC

Centralisation, détection et alerting des journaux de sécurité (Sophos XGS, Bitdefender GravityZone,
HarfangLab, puis Vectra, Varonis, CrowdSec, NinjaOne, OGO Security…) en attendant un SOC.

**État : lot 1 (MVP) livré, enrichi** — collecte, normalisation, règles de détection rattachées à MITRE ATT&CK,
qualification automatique des alertes d'authentification, anti-tempête, notifications, interface web,
connexion Active Directory (LDAPS) avec double authentification, écran mural, assistant IA, escalade et résumé
quotidien, connecteurs CrowdSec et journaux Windows/AD, blocage d'IP sur le Sophos XGS, recette automatisée.
Avancement et reste à faire : [docs/00-suivi-projet.md](docs/00-suivi-projet.md).

## Architecture

```
Équipements ──syslog──► Vector ──HTTP──► API ──► Redis Streams ──► Worker ──► ClickHouse (événements, 90 j)
Bitdefender ──push HTTPS──► Caddy ► API ─┘                           │  └──► PostgreSQL (alertes, audit)
HarfangLab ◄──API REST── Worker (connecteur)                         └──► Notifications (e-mail, Teams, ntfy)
Navigateur ──HTTPS──► Caddy ──► interface React + API
```

| Composant | Rôle |
| --- | --- |
| `backend/minisoc/parsers` | Analyse Sophos (clé=valeur), CEF (Vectra, Varonis…), Bitdefender, HarfangLab → schéma ECS |
| `backend/minisoc/rules` | Moteur de règles YAML : `match`, `threshold`, `sequence`, `absence` |
| `backend/minisoc/qualify.py` | Qualification : attaque / erreur d'utilisateur / à vérifier |
| `backend/minisoc/alerts.py` | Déduplication, anti-tempête, exceptions |
| `backend/minisoc/worker.py` | Pipeline, règles planifiées (30 s), sources silencieuses, notifications |
| `backend/minisoc/api` | API (sessions + MFA, CSRF, rôles), réception syslog et Bitdefender, administration |
| `backend/minisoc/ldap_auth.py` | Authentification Active Directory en LDAPS, rôles par groupes AD |
| `backend/minisoc/settings_store.py` | Paramètres modifiables dans l'interface (AD, SMTP, IA), secrets chiffrés |
| `backend/minisoc/ai` | Assistant IA : contexte, pseudonymisation, fournisseurs (Claude, Ollama local) |
| `backend/minisoc/frameworks.py` | Référentiel MITRE ATT&CK et couverture des règles |
| `backend/rules` | Règles livrées et fiches réflexes (`playbooks/`) |
| `frontend` | Interface web (tableau de bord, alertes, événements, sources, règles, exceptions, assistant, écran mural, administration) |

## Installation

Prérequis : une VM Linux (Debian 12 / Ubuntu 24.04), 4 vCPU, 16 Go RAM, 500 Go SSD, Docker + Compose,
Python 3 (uniquement pour générer les secrets). Installation et durcissement de la VM sur le LAN (pare-feu local,
SSH, sauvegardes) : [docs/04-installation-durcissement-vm.md](docs/04-installation-durcissement-vm.md).

```bash
python3 scripts/init_env.py          # crée .env avec des secrets aléatoires
nano .env                            # nom DNS, adresses d'écoute, HarfangLab, notifications
docker compose up -d --build
docker compose exec api python -m minisoc.cli create-user --username alice --role admin
```

`create-user` crée un **compte local de secours** (utilisable même si l'annuaire est indisponible) : il demande
le mot de passe (12 caractères minimum) puis affiche le QR code à scanner dans une application d'authentification
(Microsoft Authenticator, FreeOTP…). Rôles : `admin`, `analyst`, `viewer`. Les comptes du quotidien viennent
ensuite de l'Active Directory (voir « Connexion »).

Interface : `https://<MINISOC_HOSTNAME>`. Le certificat est émis par l'autorité interne de Caddy : installer
son certificat racine sur les postes d'administration
(`docker compose cp web:/data/caddy/pki/authorities/local/root.crt .`) ou configurer un certificat de votre PKI
dans `deploy/caddy/Caddyfile`.

## Raccorder les sources

La page **Intégrations** est le catalogue des solutions compatibles : une fiche par solution (pare-feu, EDR,
NDR, identité, renseignement, enrichissement, réponse, IA) avec son état calculé en direct (active, en attente
de données, silencieuse, à configurer, désactivée, à venir), un interrupteur d'activation, la procédure de
raccordement, les paramètres et un bouton **Tester**. Désactiver une source ignore ses événements à la réception
(compteur affiché) et la retire de la surveillance « source silencieuse » (UC-16, qui suit automatiquement les
intégrations actives). Les solutions pas encore intégrées (NinjaOne, OGO, Microsoft 365, isolation de poste)
apparaissent comme « à venir ».

### Sophos XGS (syslog)
Dans la console (libellés selon la version de SFOS) : *Configurer > Services système > Paramètres des
journaux > Ajouter un serveur syslog* : IP de la VM, port **514**, **TCP**, format standard. Cocher au minimum :
**Authentification** (VPN SSL, IPsec, portail utilisateur, administration), **Événements d'administration**,
**IPS**, **ATP**, **Anti-virus / Sandstorm**. Éviter d'envoyer le trafic autorisé du pare-feu (volume).

Le format des journaux varie selon la version : envoyer quelques lignes réelles pour ajuster
`parsers/sophos.py` (notamment les libellés des motifs d'échec utilisés par la qualification).

### Bitdefender GravityZone (push)
Le push exige une URL HTTPS joignable par le cloud Bitdefender avec un certificat valide : publier
**uniquement** `/api/ingest/bitdefender` via un reverse proxy en DMZ, restreint aux IP de Bitdefender
(`MINISOC_BITDEFENDER_ALLOWED_IPS`). Activation par l'API publique (méthode `setPushEventSettings`,
voir la documentation de l'API GravityZone) avec :
- `serviceType` : `jsonRPC`
- `serviceSettings.url` : `https://<url publique>/api/ingest/bitdefender`
- `serviceSettings.authorization` : la valeur de `MINISOC_BITDEFENDER_TOKEN`
- `serviceSettings.requireValidSslCertificate` : `true`
- événements : `av`, `hd`, `avc`, `ransomware-mitigation`, `new-incident`, `network-monitor`, `aph`, `modules`

### HarfangLab (API)
Créer un compte d'API **en lecture seule** dans la console, puis *Intégrations > HarfangLab / CrowdSec* : adresse et jeton,
bouton **Tester HarfangLab**. Interrogation toutes les 60 s, reprise sans doublon après une coupure ; les
paramètres sont relus chaque minute (pas de redémarrage).

### CrowdSec (API locale)
Sur le serveur CrowdSec : `cscli bouncers add minisoc` (clé de bouncer, lecture seule), puis *Paramètres >
Connecteurs*. Les détections locales deviennent des alertes ; toutes les IP bannies (y compris la liste
communautaire, si cochée) **enrichissent chaque événement** (`threat.intel`). Règle UC-18 : connexion réussie
depuis une IP bannie par CrowdSec → critique.

### Active Directory / Windows (NXLog)
Installer NXLog Community Edition sur les contrôleurs de domaine (ou un collecteur Windows Event Forwarding) avec
`deploy/nxlog/nxlog.conf` (remplacer `MINISOC_IP`). Seuls les événements utiles sont envoyés : ouvertures de
session (4624/4625, Kerberos 4771, NTLM 4776, avec le motif d'échec), verrouillages (4740), comptes et groupes
(4720, 4726, 4728/4732/4756), journal effacé (1102), politique d'audit (4719), service installé (7045).
Règles : UC-12 ajout à un groupe à privilèges, UC-13 journal effacé, UC-14 verrouillages en masse, UC-21
pulvérisation de mots de passe. Ajouter `windows: 30m` à la règle UC-16 pour surveiller la source.

### Vectra, Varonis et autres outils CEF
Envoyer les alertes en syslog **CEF** vers la VM (port 514) : elles sont reconnues automatiquement et
reprises par la règle `NATIVE`. Connecteurs dédiés prévus au lot 2.

## Connexion : Active Directory et double authentification

*Paramètres > Annuaire Active Directory* (rôle admin), puis bouton **Tester** :
- serveur `ldaps://dc01.domaine.local:636` (LDAP en clair refusé ; certificat toujours vérifié : renseigner
  l'autorité de certification de l'AD et utiliser le nom DNS du certificat, pas l'adresse IP) ;
- compte de service simple utilisateur du domaine (lecture seule), base de recherche, filtre ;
- un groupe AD par rôle (`GG-MiniSOC-Admins`, `-Analystes`, `-Lecteurs`) ; groupes imbriqués pris en compte ;
  un compte AD sans aucun de ces groupes est refusé ; le rôle est resynchronisé à chaque connexion.

Boucle d'authentification : identifiant + mot de passe (compte local, sinon AD) → code TOTP. À la première
connexion d'un compte AD, l'enrôlement du MFA se fait par QR code. L'étape intermédiaire est conservée côté
serveur (5 min, 5 essais, liée à l'IP) ; le verrouillage s'applique par couple (identifiant, IP) **avant**
d'interroger l'AD, pour qu'un tiers ne puisse pas faire verrouiller le compte AD d'un collègue. Les motifs AD
« mot de passe expiré / à changer » sont affichés (l'AD ne les renvoie qu'avec le bon mot de passe).
*Utilisateurs* : désactiver un compte, réinitialiser son MFA (nouvel enrôlement), sessions fermées d'office.

## Réponse : blocage d'IP sur le Sophos XGS

Bouton **Bloquer sur le pare-feu** dans chaque alerte (y compris les centaines d'IP d'une alerte regroupée) :
aperçu des IP refusées (internes, réservées, liste « jamais bloquer »), durée, confirmation, levée automatique à
l'échéance, page **Blocages** pour débloquer. Chaque action est tracée dans le journal d'audit.

Préparation du pare-feu (une seule fois), puis *Intégrations > Blocage d'IP sur le Sophos XGS* et **Tester** :
1. Activer l'API XML (*Administration > Paramètres d'administration > API*) en n'autorisant que l'IP du Mini-SOC.
2. Compte d'administration dédié, profil limité aux objets hôtes.
3. Créer le groupe d'hôtes IP `MiniSOC-Blocages` (vide).
4. Règle de pare-feu en tête : source = ce groupe → *Abandonner*.
5. **Exception ACL de service local** (*Administration > Accès à l'appareil*) : source = ce groupe, services
   VPN SSL / IPsec / portail utilisateur → *Abandonner*. Le VPN étant hébergé par le pare-feu, la règle de
   pare-feu seule ne suffit pas à couper le botnet.
Les libellés exacts varient selon la version de SFOS.

## Messagerie (SMTP)

*Paramètres > Messagerie* : STARTTLS **obligatoire** avec vérification du certificat (587/25), TLS direct (465)
ou, pour un relais interne sans TLS uniquement, aucun chiffrement. Authentification facultative (relais
anonyme ou Microsoft 365 « Direct Send »). Bouton **Envoyer un e-mail de test**. Les e-mails d'alerte ont une
version texte et une version HTML (contenu échappé).

## Écran mural

Page `/wall` en plein écran (double-clic), lisible à distance, rafraîchie toutes les 15 s : alertes hautes et
critiques à traiter, bandeau d'état (rouge clignotant si une alerte critique n'est pas prise en charge),
sources, échecs d'authentification, IP les plus actives ; bandeau « données non mises à jour » si l'écran perd
la connexion ; bouton « ← Menu » à l'approche de la souris. Un écran sans clavier utilise un **jeton
d'affichage** en lecture seule, révocable, limitable à l'IP de l'écran, noms de comptes masqués par défaut :

```bash
docker compose exec api python -m minisoc.cli create-display-token --name "Écran bureau info" --ip 10.1.1.50
docker compose exec api python -m minisoc.cli list-display-tokens
docker compose exec api python -m minisoc.cli revoke-display-token --id 1
```

Le lien `https://…/wall#token=…` n'est affiché qu'une fois ; le jeton, placé après `#`, n'est jamais envoyé
au serveur dans l'URL ni journalisé.

## Assistant IA

*Intégrations > Assistant IA* : **Anthropic Claude** (cloud, modèle par défaut `claude-opus-5-5`) ou **Ollama**
(modèle local : aucune donnée ne quitte le réseau ; sous Docker Desktop, `http://host.docker.internal:11434`).
- Bouton **Analyser avec l'IA** dans chaque alerte (résumé, évaluation, actions priorisées, vérifications),
  puis questions de suivi ; page **Assistant IA** pour les questions sur la situation en cours.
- Clé d'API chiffrée côté serveur, jamais transmise au navigateur. Pour Claude, le serveur doit joindre
  `api.anthropic.com` en HTTPS (règle de sortie sur le pare-feu).
- Données envoyées au cloud **pseudonymisées** par défaut (comptes, postes, IP internes, e-mails → `USER_1`,
  `HOST_2`…), remises en clair dans la réponse affichée.
- Les journaux sont transmis comme **données non fiables** (un attaquant peut écrire dans un nom de compte) ;
  l'IA ne peut déclencher aucune action. Chaque demande est tracée dans le journal d'audit (qui, quoi,
  fournisseur, modèle, volume), sans le contenu. Limite : 40 demandes par heure et par utilisateur.

## Veille : CISA KEV et CERT-FR

Le worker relit chaque jour le catalogue **CISA KEV** (vulnérabilités activement exploitées) et toutes les 2 h
les **alertes et avis du CERT-FR** (page *Veille*, et section dans le résumé quotidien). Toute détection IPS,
EDR ou NDR mentionnant une CVE du catalogue déclenche la règle **UC-22** (tentative d'exploitation d'une faille
connue). Le serveur doit joindre `www.cisa.gov` et `www.cert.ssi.gouv.fr` en HTTPS ; désactivable dans
*Paramètres > Détection*.

## Origine géographique et qualification

Avec une base GeoIP, chaque événement porte le pays et l'opérateur de l'IP source : répartition par pays des
échecs d'authentification (tableau de bord, écran mural), pays affiché à côté des IP. La qualification des
alertes VPN tient compte du pays (*Paramètres > Détection > pays habituels*, FR par défaut), des hébergeurs et
relais d'anonymisation, et des bannissements CrowdSec : une IP « habituelle » mais bannie ou hébergée chez un
fournisseur de serveurs n'est plus classée « erreur d'utilisateur ».

## Référentiels : MITRE ATT&CK

Chaque règle déclare les techniques ATT&CK qu'elle détecte (`mitre: [T1110.003, T1133]`), affichées sur les
règles et les alertes avec lien vers la fiche officielle. La page *Règles* montre la **couverture par
tactique** (accès initial, accès aux identifiants, impact…) : ce qui est surveillé et ce qui ne l'est pas encore.
Prochaines étapes possibles : import de règles **Sigma** (communauté, format ouvert) pour les journaux Windows
et AD, alertes **CERT-FR** et catalogue **CISA KEV** pour prioriser les vulnérabilités NinjaOne.

## Règles de détection

Fichiers YAML dans `backend/rules/`, validés au démarrage et par
`docker compose exec api python -m minisoc.cli check-rules`. Après modification : `docker compose restart api worker`.

```yaml
id: UC-02a
name: Force brute VPN distribuée sur un compte (botnet)
type: threshold                 # match | threshold | sequence | absence
severity: critical
filter:                         # égalité, liste, {contains|cidr|not_cidr|gte…}, any/all/not
  event.category: authentication
  event.outcome: failure
group_by: [user.name]
window: 1h
condition: count_distinct(source.ip) >= 20
storm_limit: 3                  # au-delà de 3 alertes/heure : regroupement en une seule alerte
qualify: auth_account           # qualification automatique (attaque / erreur d'utilisateur)
playbook: playbooks/vpn-bruteforce.md
```

**Qualification des alertes d'authentification.** Un grand nombre d'échecs n'est pas forcément une attaque
(mot de passe expiré, téléphone qui réessaie un ancien mot de passe, faute de frappe). Chaque alerte UC-01,
UC-02a, UC-03a et UC-03b reçoit un verdict expliqué, fondé sur le motif d'échec, l'historique des connexions
réussies (30 jours) et le nombre de comptes visés. « Erreur d'utilisateur probable » abaisse la sévérité à
*faible* : pas de notification immédiate.

**Anti-tempête.** Une alerte par (règle, entité) tant qu'elle est ouverte ; au-delà de `storm_limit` alertes
par heure pour une règle, les nouvelles entités sont regroupées dans une seule alerte.

**Exceptions.** Page *Exceptions* : règle, champ, valeur exacte, justification et expiration obligatoires.

## Notifications

| Sévérité | Canaux (modifiables via `MINISOC_NOTIFY_ROUTES`) |
| --- | --- |
| Critique | ntfy (mobile), Teams, e-mail — 24 h/24 |
| Haute | Teams, e-mail |
| Moyenne | e-mail, en heures ouvrées uniquement (8 h–18 h, lun.–ven.) |
| Faible / info | aucune (consultation dans l'interface et résumé quotidien) |

*Paramètres > Notifications* : webhook Teams, ntfy (mobile), **escalade** (une alerte critique — ou haute —
toujours « Nouvelle » après 30 min relance un second contact par e-mail, mobile en priorité maximale et Teams)
et **résumé quotidien** à 8 h (alertes des 24 h, alertes graves ouvertes, alertes faibles non notifiées dont les
erreurs d'utilisateurs, sources silencieuses, IP les plus actives). Boutons de test et « Envoyer le résumé
maintenant ».

## Recette

```bash
docker compose exec -T api python - < tools/dev_seed_user.py > .dev-credentials.json   # compte de test local
python tools/replay_vpn_attack.py      # botnet de 200 IP + 3 utilisateurs légitimes en difficulté
python tools/smoke_api.py              # 22 contrôles : connexion en 2 étapes, anti-rejeu, CSRF, clôtures, en-têtes
python tools/dev_ai_check.py gemma4:26b-a4b-it-qat   # analyse réelle d'une alerte avec l'Ollama local
docker build --target test -t minisoc-test backend && docker run --rm minisoc-test   # tests unitaires
```

Résultat attendu du rejeu : 10 058 événements stockés, une alerte par (règle, entité), regroupement des
200 IP, c.bernard / s.petit / l.moreau qualifiés « erreur d'utilisateur » en sévérité faible, connexions
réussies depuis des IP du botnet qualifiées « attaque » en critique.

## Exploitation

- **Surveillance de l'outil (S-12)** : sonde externe (ex. Uptime Kuma, sur une autre machine) sur
  `https://<hôte>/api/health/full` — HTTP 503 si PostgreSQL, Redis, ClickHouse ou le worker sont en panne, ou si
  la file de traitement prend du retard. Un worker arrêté est détecté en 2 minutes.
- **Sauvegarde (S-13)** : `./scripts/backup.sh` chaque nuit (cron), base + paramètres + règles (+ événements avec
  `WITH_EVENTS=1`), chiffrement gpg avec `BACKUP_PASSPHRASE_FILE`, rétention 14 jours ; copier les archives hors
  du serveur. Restauration : `./scripts/restore.sh <archive>` — à tester chaque trimestre sur une machine de recette.
- **Schéma de la base** : migrations Alembic appliquées automatiquement au démarrage ;
  `docker compose exec api python -m minisoc.cli db-current` affiche la version.
- **GeoIP** : avec un compte MaxMind gratuit, renseigner `MAXMIND_ACCOUNT_ID` et `MAXMIND_LICENSE_KEY` dans `.env`,
  décommenter `COMPOSE_PROFILES=geoip` puis `docker compose up -d geoipupdate` (téléchargement et mise à jour
  automatique tous les 3 jours). Ou déposer manuellement `GeoLite2-City.mmdb` (ou `-Country`) et `GeoLite2-ASN.mmdb` (MaxMind, compte gratuit) ou les
  bases DB-IP Lite dans `data/geoip/` : pays et opérateur ajoutés aux événements, règle UC-04 (connexion VPN
  depuis un pays inhabituel) active ; bases relues à chaud, mise à jour mensuelle conseillée.
- Journaux : `docker compose logs -f worker api vector`
- Après modification de `deploy/vector/vector.yaml` : Vector la recharge seul ; en cas de doute,
  `docker compose up -d --force-recreate vector` (les journaux en tampon disque sont conservés).
- Intégrité du journal d'audit : `docker compose exec api python -m minisoc.cli verify-audit`
- Réinitialiser le MFA d'un compte : `docker compose exec api python -m minisoc.cli reset-mfa --username alice`
- Écran mural : `create-display-token`, `list-display-tokens`, `revoke-display-token` (voir « Écran mural »)
- Sauvegarde : volumes `pgdata` (alertes, audit, comptes) et `chdata` (événements), plus le fichier `.env`
  (contient la clé maître sans laquelle les secrets — MFA, mots de passe AD/SMTP, clé d'IA — sont illisibles).

## Avancement et reste à faire

Voir [docs/00-suivi-projet.md](docs/00-suivi-projet.md) (fait, reste à faire, actions de la DSI) et
[docs/02-guides-integrations.md](docs/02-guides-integrations.md) (guides d'installation de chaque intégration).
