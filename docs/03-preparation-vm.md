# Préparation de la mise en service : VM, flux réseau, accès

Tout ce qui pouvait être développé l'est ; la suite demande la VM sur le réseau de la collectivité et les accès
ci-dessous. Les secrets (mots de passe, jetons, clés) se saisissent **dans l'interface du Mini-SOC**
(Intégrations › Configurer, ou Paramètres), jamais par e-mail ou messagerie.

## 1. La VM

| Élément | Minimum | Conseillé |
| --- | --- | --- |
| Système | Debian 13 (ISO d'installation automatique : `deploy/iso`) ou Ubuntu Server 24.04 LTS | idem |
| Processeur | 4 vCPU | 8 vCPU |
| Mémoire | 8 Go | 16 Go |
| Disque | 200 Go SSD | 500 Go SSD (journaux conservés 365 jours) |
| Réseau | IP fixe + nom DNS interne (ex. `minisoc.mairie.local`), sur le LAN | idem, seule dans un VLAN dédié routé par le XGS |
| Logiciels | Docker Engine + extension Compose, `git`, `openssl` | idem |
| Sauvegarde | `scripts/backup.sh` chaque nuit (cron), copie hors de la VM | + snapshot de la VM avant chaque mise à jour |

Installation et durcissement pas à pas (pare-feu local, SSH, Docker, sauvegardes) :
[04-installation-durcissement-vm.md](04-installation-durcissement-vm.md). En résumé : copier le projet, `python3 scripts/init_env.py` (crée `.env` et ses
secrets), `docker compose up -d --build`, puis créer le premier compte administrateur
(`docker compose exec api python -m minisoc.cli create-user …`).

Reprise de la configuration du poste de développement (HarfangLab déjà réglé, etc.) : soit tout ressaisir dans
l'interface (plus propre), soit `scripts/backup.sh` ici puis `scripts/restore.sh` sur la VM **avec le même fichier
`.env`** (la clé maître déchiffre les secrets enregistrés).

## 2. Flux réseau à ouvrir

**Vers la VM**

| Depuis | Port | Pour |
| --- | --- | --- |
| Postes de la DSI, écran mural | 443/TCP | interface web |
| Sophos XGS | 514/TCP (ou 6514/TCP chiffré) | journaux VPN, pare-feu, IPS |
| Contrôleurs de domaine, serveurs de fichiers | 514/TCP (ou 6514/TCP) | journaux Windows (NXLog) |
| Vectra (et Varonis installé sur site) | 514/TCP | alertes CEF |
| Poste d'administration | 22/TCP | SSH |

**Depuis la VM**

| Vers | Port | Pour |
| --- | --- | --- |
| Contrôleurs de domaine | 636/TCP (LDAPS) | connexion AD, comptes sensibles |
| Relais SMTP | 587 ou 25/TCP | e-mails d'alerte, résumé, rapport |
| Sophos XGS (interface d'admin) | 4444/TCP | lecture des règles, blocage d'IP |
| Serveur CrowdSec | 8080/TCP | décisions de bannissement |
| Console HarfangLab (`…hurukai.io`) | 8443/TCP | alertes EDR, isolation |
| `login.microsoftonline.com`, `manage.office.com` | 443/TCP | Microsoft 365 / Entra ID |
| `download.maxmind.com` | 443/TCP | bases GeoIP |
| `www.cisa.gov`, `www.cert.ssi.gouv.fr` | 443/TCP | veille |
| Fournisseur d'IA choisi, ou serveur Ollama interne (11434/TCP) | 443/TCP | assistant IA |
| Webhook Teams, serveur ntfy | 443/TCP | notifications |
| `cloudgz.gravityzone.bitdefender.com` | 443/TCP | incidents et quarantaine GravityZone (API) |
| `<tenant>.varonis.io` | 443/TCP | alertes Varonis SaaS (API) |

## 3. Accès à préparer, par ordre de priorité

| # | Solution | Ce qu'il faut | Où le saisir |
| --- | --- | --- | --- |
| 1 | Active Directory | Compte de service **en lecture seule**, DN de la base, DN des groupes donnant les rôles admin / analyste / lecteur, certificat de l'autorité de l'AD (PEM) | Paramètres › Annuaire AD |
| 2 | Messagerie | Relais SMTP, adresse d'expédition, destinataires des alertes et du résumé | Paramètres › Messagerie |
| 3 | Sophos XGS | Serveur syslog vers la VM (aucun compte) ; puis compte d'API **en lecture seule** et IP de la VM autorisée dans l'API | Intégrations › Sophos / Blocage d'IP |
| 4 | Windows / AD | NXLog sur les contrôleurs et serveurs de fichiers, GPO d'audit (aucun compte) | Guide de la fiche Active Directory |
| 5 | HarfangLab | Déjà raccordé (jeton en lecture seule) ; à reprendre sur la VM | Intégrations › HarfangLab |
| 6 | Microsoft 365 | Inscription d'application Entra ID : ID du tenant, ID de l'application, secret (permission ActivityFeed.Read) | Intégrations › Microsoft 365 |
| 7 | Notifications | Webhook Teams (flux Workflows) et/ou sujet ntfy | Paramètres › Notifications |
| 8 | CrowdSec | Clé de bouncer (`cscli bouncers add minisoc`) | Intégrations › CrowdSec |
| 9 | Bitdefender | Clé d'API de lecture (Incidents API, Quarantine API) et Access URL | Intégrations › Bitdefender |
| 10 | Varonis SaaS | Clé d'API au rôle Threat Detection Integrator, adresse de l'instance | Intégrations › Varonis |
| 10 bis | Vectra | Client d'API en lecture seule (recommandé), ou destination syslog CEF vers la VM | Console Vectra |
| 11 | GeoIP | Nouvelle clé MaxMind (l'actuelle a servi aux essais) | Intégrations › Géolocalisation |
| 12 | Assistant IA | Clé du fournisseur choisi, ou adresse d'un Ollama joignable depuis la VM | Intégrations › Assistant IA |
| 13 | Isolation (après essais) | Jeton HarfangLab avec le droit d'isolation ; clé GravityZone Incidents + Network | Intégrations › Isolation de poste |
| — | NinjaOne | Exemple de réponse de l'API vulnérabilités (pour développer le connecteur) | à transmettre |
| — | OGO Security | Possibilités d'export de l'offre (syslog CEF ou API) | à transmettre |

## 4. Essais à mener sur la VM

- [ ] Connexion d'un compte AD à l'interface, avec la double authentification
- [ ] Échec VPN volontaire : visible dans Événements (Sophos) en moins d'une minute
- [ ] Mauvais mot de passe sur un poste du domaine : visible avec le poste d'origine (Windows)
- [ ] Alerte de test envoyée par e-mail, Teams et ntfy (Paramètres › Notifications › Tester)
- [ ] Lecture des règles du XGS (lecture seule), puis blocage d'une IP de test et levée automatique
- [ ] Microsoft 365 : bouton Tester, puis premières connexions sous quelques heures
- [ ] Isolation d'un **poste de test** (HarfangLab), puis levée
- [ ] Sauvegarde nocturne et restauration sur une machine de recette
