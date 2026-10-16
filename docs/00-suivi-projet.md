# Suivi du projet Mini-SOC

**Fichier de référence du suivi**, mis à jour à chaque séance de travail. Dernière mise à jour : **03/10/2026**.
Cahier des charges : [document Claude](https://claude.ai/code/artifact/2760bee3-0295-4c3e-9a63-a2e0bef1cbe5) ;
installation, raccordement des sources et exploitation : [README](../README.md).

Contexte : collectivité sans SOC ; les alertes des outils de sécurité (Sophos XGS, HarfangLab, Bitdefender
GravityZone, NinjaOne, OGO Security, CrowdSec, Vectra, Varonis) ne sont pas vues à temps — exemple déclencheur : un
botnet tente de se connecter au VPN Sophos depuis 4 jours sans que personne ne soit prévenu.

## 1. Jalons

| Date | Jalon | État |
|---|---|---|
| 02/10/2026 | Cahier des charges (exigences F-xx, sécurité S-xx, cas d'usage UC-xx) | ✅ |
| 02/10/2026 | Lot 1 (MVP) : collecte, normalisation, règles, alertes, interface web | ✅ sur le poste de développement |
| 03/10/2026 | Lot 1 enrichi : AD/LDAPS + double authentification, SMTP, écran mural, assistant IA (Claude / Ollama), MITRE ATT&CK, GeoIP MaxMind, veille KEV/CERT-FR, blocage XGS, catalogue des intégrations | ✅ sur le poste de développement |
| 03/10/2026 | Lecture (seule) des règles de pare-feu du Sophos XGS par l'API | 🟡 livré, essai réel en attente des accès XGS |
| 03/10/2026 | **HarfangLab de production raccordé** ; données de test purgées (seules les données réelles restent) | ✅ |
| À planifier | Installation sur une VM du réseau de la collectivité, essai réel de la collecte syslog (Sophos XGS, puis autres sources) | ⏳ à faire par la DSI |
| À planifier | Mise en production (sauvegardes, sonde externe, comptes AD, notifications réelles) | ⏳ |
| 03/10/2026 | Lot 2 : incidents (F-24), rapport mensuel (F-29), Vectra et Varonis dédiés, Microsoft 365, comptes AD, routage des notifications, IA multi-fournisseurs, syslog TLS ; restent NinjaOne et OGO (attente d'informations) | ✅ (hors NinjaOne, OGO) |
| 03/10/2026 | Lot 3 : isolation de poste (F-27, HarfangLab / Bitdefender) | 🟡 livré, à valider sur un poste de test |

Code non versionné à ce jour (pas de dépôt git, aucun commit demandé).

## 2. Fait

### 2.1 Socle technique

- Backend Python 3.12 / FastAPI, PostgreSQL 16 (comptes, alertes, audit, paramètres ; migrations Alembic appliquées au
  démarrage), ClickHouse (événements ; compression à 7 j, suppression à 365 j), Redis Streams (file de traitement).
- Collecte : Vector (syslog UDP/TCP 514, TLS 6514 prévu) avec tampon disque, rechargement automatique de sa
  configuration ; réception HTTPS (push Bitdefender) ; connecteurs API (HarfangLab, CrowdSec).
- Frontend React 19 / Vite / TypeScript, graphiques SVG maison, aucun `innerHTML` (rendu Markdown maison).
- Caddy en frontal (TLS, CSP stricte), Docker Compose (profil `geoip` optionnel).
- Exploitation : `/api/health/full` (503 si une brique ou le worker est en panne), signe de vie du worker, ménage
  automatique (alertes clôturées, sessions, défis expirés ; journal d'audit jamais purgé), scripts `backup.sh` /
  `restore.sh` (chiffrement gpg, rétention 14 j), `scripts/init_env.py` (génération du `.env` et des secrets).

### 2.2 Collecte et normalisation

- Format pivot inspiré d'ECS (utilisateur, IP, hôte, résultat, motif d'échec, pays, opérateur, renseignement).
- Analyseurs : Sophos XGS (syslog), CEF générique (Vectra, Varonis, OGO…), Bitdefender GravityZone (push),
  HarfangLab (API), CrowdSec (décisions LAPI), journaux Windows / AD via NXLog JSON (4624, 4625, 4771, 4776, 4740,
  4728, 4732, 4756, 4720, 4726, 1102, 104, 4719, 7045 ; modèle `deploy/nxlog/nxlog.conf`).
- Enrichissement : GeoIP MaxMind GeoLite2 (pays, opérateur ; mise à jour automatique tous les 3 jours via
  `geoipupdate`), réputation CrowdSec (IP et plages bannies), catalogue CISA KEV + flux CERT-FR.

### 2.3 Détection

- Moteur de règles YAML : correspondance, seuil, séquence, absence (`sources: auto`), nouveauté (pays inhabituel).
- Anti-tempête (regroupement au-delà d'un seuil : 200 IP d'un botnet → une alerte), dédoublonnage par
  (règle, entité), exceptions avec justification et échéance — y compris créées depuis une alerte (« faux positif »).
- **Qualification automatique** des alertes d'authentification : attaque / suspect / erreur d'utilisateur, d'après
  le motif d'échec, l'historique 30 j de l'IP et du compte, le nombre de comptes visés, le pays, l'hébergeur (ASN),
  la réputation CrowdSec. Réponse au besoin « un grand nombre d'échecs n'est pas forcément une attaque ».
- Règles livrées, rattachées à MITRE ATT&CK (page Règles : couverture par tactique) :

| Règle | Objet |
|---|---|
| UC-01 | Échecs VPN répétés depuis une IP |
| UC-02a / UC-02b | Botnet sur le VPN (un compte visé / tous comptes) |
| UC-03a / UC-03b | Connexion VPN réussie après des échecs (même IP / même compte) |
| UC-04 | Connexion VPN depuis un pays inhabituel |
| UC-05 / UC-06 | Malware non neutralisé / comportement de rançongiciel |
| UC-10 | Accès à l'administration du pare-feu depuis l'extérieur |
| UC-12 / UC-13 / UC-14 | Ajout à un groupe à privilèges / journal effacé / verrouillages en masse (AD) |
| UC-16 | Source silencieuse |
| UC-18 | Connexion réussie depuis une IP bannie par CrowdSec |
| UC-21 | Pulvérisation de mots de passe sur l'AD |
| UC-22 | Exploitation d'une vulnérabilité du catalogue KEV |
| UC-23 / UC-24 | Compte sensible verrouillé / verrouillages répétés d'un même compte |
| UC-25 / UC-26 / UC-27 | Compte de service en session interactive ou RDP / échecs d'un compte de service / d'un admin |
| UC-28 / UC-29 | Admin depuis un nouveau poste / mot de passe réinitialisé ou compte réactivé (compte sensible) |
| UC-30 / UC-31 | Kerberoasting (tickets RC4 en série) / mot de passe DSRM modifié |
| UC-32 / UC-33 | Renommages ou suppressions de fichiers en masse / extension de rançongiciel bloquée par FSRM |
| UC-34 / UC-35 | Microsoft 365 : connexion réussie depuis l'étranger (pays habituels du paramétrage) / voyage impossible |
| UC-36 / UC-37 / UC-38 | Microsoft 365 : pulvérisation de mots de passe / échecs répétés depuis l'étranger / fatigue MFA |
| UC-39 / UC-40 / UC-41 | Règle de transfert de messagerie / rôle d'administration Entra ou MFA désactivée / consentement d'application |
| NATIVE | Alertes natives des outils (CEF, EDR, antivirus) |

- Fiches réflexes (playbooks) par règle, affichées dans l'alerte.

### 2.4 Alertes, notifications, réponse

- Cycle de vie des alertes (nouvelle, prise en charge, clôturée, faux positif) avec historique et commentaires.
- Notifications e-mail (SMTP STARTTLS vérifié / TLS 465), Teams (carte adaptative), ntfy (mobile) ; routage par
  sévérité et heures ouvrées ; **escalade** (F-18) des alertes non prises en charge ; **résumé quotidien** (F-19).
- **Blocage d'IP sur le Sophos XGS** (F-26) par l'API XML : groupe `MiniSOC-Blocages`, durée, levée automatique,
  contrôle avant blocage (IP interne, déjà bloquée) ; désactivé par défaut.
- **Lecture seule des règles de pare-feu du XGS** : bouton « Lire les règles (lecture seule) » dans l'intégration,
  `GET /api/admin/integrations/xgs_response/rules`, commande `python -m minisoc.cli xgs-rules` ; lecture journalisée.
- **Synchronisation des statuts** avec HarfangLab et NinjaOne : une alerte traitée dans l'outil est clôturée dans le
  Mini-SOC, avec la trace (outil, statut, auteur, date) dans son historique et le journal d'audit ; rien n'est
  supprimé ; garde-fous (toutes les alertes d'origine traitées, relecture avant clôture, aucune clôture sur erreur).
- **Fiches des détections d'outils** (vue « Par détection ») : catégorie (menace, hygiène du parc, information)
  et sévérité recalibrée, appliquées aux nouvelles alertes et, à la demande, aux alertes ouvertes (trace dans
  l'historique) ; suggestions validées par la DSI (`minisoc/detection_suggestions.yaml`).
- **Priorité de traitement** (0-100, expliquée) : sévérité, serveur, compte à privilèges, catégorie, rareté de
  la détection, récence, nombre d'outils ; tri par défaut de la liste, carte « À traiter en priorité » de l'accueil.
- Alerte « source silencieuse » clôturée automatiquement au retour de la source ; la dernière activité d'une source
  ne recule plus lors d'un import d'historique (faux positif corrigé).
- Tests des notifications en tête de Paramètres › Notifications, dont « Tester le routage » par sévérité.

### 2.5 Interface

- Tableau de bord, alertes (détail, qualification, MITRE, événements liés, pays, IP bannie), événements (recherche),
  intégrations (catalogue : activer / désactiver / configurer / tester chaque solution ; remplace l'ancienne page
  Sources), règles, exceptions, blocages, veille, assistant IA, utilisateurs, paramètres (AD, SMTP, notifications,
  détection, conservation).
- **Liste des alertes** : actives par défaut (effectifs par statut), filtres sévérité / source / règle /
  qualification / assignation, sélecteur de période (24 h, 7 j, 30 j, dates choisies), tri, 50 à 500 par page.
- **Lien vers la console d'origine** (HarfangLab…) : bouton « Gérer dans … » sur l'alerte, flèche dans la liste
  des alertes et sur chaque événement — l'état de l'alerte dans l'outil se gère dans sa console.
- **Événement déplié** : journal brut lisible, « Copier le journal brut », « Copier avec le résumé », « Analyser avec
  l'IA » (si l'assistant est configuré ; contexte pseudonymisé : champs, journal brut, activité 7 j, alertes ouvertes).
- **Page Intégrations revue** : tuiles d'état cliquables, sections « À traiter / En service / Désactivées / À venir »,
  prochaine action affichée sur chaque fiche, bouton « Tester » direct.
- **Comptes AD** : comptes verrouillés (24 h) avec le poste à l'origine des échecs et l'état (encore verrouillé,
  déverrouillé par qui), comptes administrateurs et de service (lus dans l'AD chaque heure : adminCount=1, SPN,
  gMSA ; ou motifs de noms) avec activité 7 j et points d'attention (mot de passe sans expiration ou de plus d'un
  an, délégation non contrainte, session interactive d'un compte de service).
- **Incidents (F-24)** : regroupement d'alertes (cases à cocher dans la liste, ou depuis une alerte), statut
  (ouvert, en investigation, maîtrisé, clos), responsable, catégorie, case « données personnelles » (CNIL 72 h),
  chronologie (notes, actions menées), conclusion obligatoire à la clôture (les alertes sont clôturées avec),
  rapport Markdown téléchargeable.
- **Rapport mensuel (F-29)** : page Rapports (choix du mois), indicateurs (alertes et tendance, délais médians de
  prise en charge et de clôture, faux positifs, incidents, blocages, attaques par IP et par pays, volume par source),
  téléchargement Markdown, envoi par e-mail le 1er du mois (heure et destinataires du résumé quotidien).
- **Routage des notifications** dans l'interface : grille sévérité × canal (e-mail, Teams, ntfy), sévérités
  réservées aux heures ouvrées, jours et heures ouvrés réglables.
- **Assistant IA multi-fournisseurs** repris de LMU Stats Viewer : OpenAI, Anthropic, Google Gemini, OpenRouter,
  DeepSeek, Mistral, Ollama, fournisseurs personnalisés compatibles OpenAI ; clé par fournisseur (chiffrée), liste
  des modèles lue chez le fournisseur.
- **Isolation de poste (F-27)** sur les alertes HarfangLab / Bitdefender ; **syslog chiffré (TLS 6514)** ;
  traitement CEF dédié **Vectra** (UC-19) et **Varonis**.
- **Machines concernées** (03/10) : pastilles des postes dans la liste des alertes, bloc « Machines concernées » en
  tête de chaque alerte (détections, règles, événements du poste, console EDR), recherche par poste y compris dans
  les regroupements ; bouton « Dégrouper » ; HarfangLab relu sur 30 jours au raccordement (sans notification des
  alertes anciennes, alertes clôturées dans HarfangLab gardées comme événements), seuil anti-tempête des alertes
  d'outils porté à 30 postes / heure.
- **Refonte graphique** (03/10) : système de design complet (police Inter et icônes Lucide embarquées, conforme à
  la CSP), menu par sections avec compteurs, en-têtes illustrés, indicateurs à halo, badges à pastille, tableaux et
  graphiques en dégradé, page de connexion illustrée, thème clair / sombre au choix, écran mural harmonisé.
- **Guides d'installation** des 16 intégrations ([index](02-guides-integrations.md)) : onglet « Guide
  d'installation » dans chaque fiche, ouvert automatiquement à l'activation, adresse du Mini-SOC pré-remplie.
- **Écran mural** (diffusion sur écran, jeton dédié révocable, retour au menu), badges de sévérité alignés.

### 2.5 bis Briques SIEM (03/10/2026)

- **Recherche** dans tous les journaux (page Recherche) : langage `champ=valeur`, jokers, réseaux CIDR, contient,
  comparaisons, ET/OU/NON (en français ou en anglais), texte libre ; étapes `count by`, `top`, `distinct … by`,
  `timeline`, `head` ; affinage au clic, recherches enregistrées (personnelles ou partagées), export CSV ; SQL
  paramétré (aucune valeur concaténée), chaque recherche tracée dans le journal d'audit.
- **Import de règles Sigma** : conversion fidèle (sélections, `1 of`/`all of`, modificateurs, insensible à la
  casse) pour les journaux de sécurité Windows, Microsoft 365 et pare-feu ; refus motivé des règles portant sur
  des données non collectées (processus, registre : domaine de l'EDR). Règles importées stockées en base,
  désactivées par défaut, rechargées à chaud par l'API et le worker.
- **Rejeu** d'une règle (correspondance ou seuil) sur 7 à 365 jours avant activation : alertes estimées, entités,
  répartition par jour, exemples. **Couverture MITRE** fusionnée : règles du Mini-SOC et techniques détectées par
  les outils (étiquettes Sigma des alertes HarfangLab).
- **Inventaire des actifs** (page Inventaire) : machines et comptes avec criticité, propriétaire, service ;
  alimenté par NinjaOne, l'annuaire (ordinateurs et OU, comptes sensibles) et les alertes, import CSV ; une fiche
  classée n'est plus modifiée par les synchronisations. La criticité entre dans la priorité (vitale +20, haute +10,
  basse −10) ; propriétaire et service s'affichent avec les machines touchées.
- **Chasse aux IOC** (page IOC) : IP / réseaux, domaines, empreintes, URL (formes neutralisées acceptées) ;
  chaque nouvel IOC recherché sur tout l'historique, puis tous les IOC sur les journaux reçus (date de réception :
  rien n'est manqué lors d'un import) ; contrôle des limites (pas de faux positif « notevil.com ») ; listes
  externes relues chaque jour ; alerte UC-42, notifiée même pour une correspondance ancienne.
- **Archives scellées** : un fichier JSON compressé par jour, SHA-256 chaîné à la veille, manifeste vérifiable
  sans le Mini-SOC ; vérification de toute la chaîne et téléchargement (tracés) ; dernière empreinte ancrée dans le
  résumé quotidien par e-mail. Volume Docker `archives`.
- **Export vers un SIEM ou un SOC** (intégration) : syslog RFC 5424 en TLS, TCP ou UDP, JSON ECS ou CEF ; alertes
  seules ou tous les événements ; file d'attente bornée (une cible injoignable ne ralentit jamais la détection).

### 2.5 ter Détection avancée (04/10/2026)

- **Score de risque par machine et par compte** (7 jours) : chaque détection compte une fois par entité, pondérée
  par sévérité, catégorie (hygiène ×0,2), diffusion (répandue ×0,5), tactiques MITRE (+10 chacune) et criticité de
  l'inventaire ; alerte UC-43 au-delà du seuil (Paramètres › Détection, 60 par défaut), clôturée automatiquement
  quand le score redescend. Accueil, fiche machine et fiche d'alerte détaillent la composition du score.
- **Chaînes d'attaque** (UC-44) : 3 tactiques MITRE en 24 h sur une entité, dont une étape avancée ; incident ouvert
  automatiquement avec les alertes rattachées (réglable). Tactiques des alertes d'outils lues dans leurs étiquettes.
  Les regroupements anti-tempête sont exclus (machines mêlées).
- **Leurres** (UC-45, critique, jamais regroupée) : comptes, dossiers, machines, chaînes secrètes ; guide de mise
  en place [05-leurres.md](05-leurres.md).
- **DNS des contrôleurs de domaine** : analyseur ETW et journal de débogage, champs `dns.question.name` et
  `dns.question.registered_domain` ; UC-46 tunnel DNS, UC-47 domaine généré par algorithme ; IOC « domaine »
  appliqués aux sous-domaines ; intégration et guide `dns_windows`, section NXLog.
- **NXLog validé pour l'édition gratuite** (Community Edition 3.2, 07/10) : configuration limitée aux modules
  gratuits (la collecte DNS par ETW, `im_etw`, est réservée à l'édition payante : remplacée par le journal de débogage
  DNS) ; heure exacte ajoutée en UTC (`EventTimeUTC`), l'édition gratuite datant en heure locale sans fuseau (sans
  elle, les événements Windows étaient décalés de 1 à 2 heures) ; requête XPath répartie sur deux sélections.
- **Exposition réelle** : « à corriger en priorité » (accueil et inventaire), d'après vulnérabilités, antivirus et
  menaces (NinjaOne), alertes de menace, failles KEV citées, exposition à Internet (case de l'inventaire) et
  criticité ; actions conseillées.
- **Réparation** des 555 alertes HarfangLab tronquées (`minisoc.cli repair-harfanglab`) : 555 / 555 relues.
- Corrections : le parseur HarfangLab ne prend plus le nom de domaine pour un compte ; comptes système exclus du
  score de risque.

### 2.5 quater Suivi des alertes (04/10/2026)

Principe retenu par la DSI : **lecture seule sur les outils**. Le Mini-SOC suit qui traite quoi et indique comment
agir dans l'outil ; il ne modifie jamais HarfangLab, NinjaOne ni les autres.

- Assignation à tout analyste ou administrateur (fiche et actions groupées), e-mail à la personne assignée.
- Statut « En attente » avec motif (utilisateur, prestataire, éditeur, correctif planifié, autre) : alerte toujours
  ouverte, échéances suspendues.
- Échéances par sévérité (Paramètres › Suivi : prise en charge en heures, traitement en jours), badge « en retard »,
  date de prise en charge enregistrée (premier changement de statut ou première assignation).
- État lu dans l'outil d'origine : HarfangLab « nouvelle » ou « en investigation » (par qui, depuis quand), relevé
  par la synchronisation et tracé dans l'historique quand il change.
- « Agir dans l'outil » : marche à suivre par outil (HarfangLab, NinjaOne, Sophos, Bitdefender, AD, Microsoft 365)
  et indication du lieu de clôture (automatique pour HarfangLab et NinjaOne, ici pour les autres et pour les
  alertes calculées par le Mini-SOC).
- Vues de suivi dans la liste : mes alertes, non assignées, en attente, en retard ; actions groupées.

### 2.6 Sécurité de l'outil

- Connexion **Active Directory en LDAPS** (certificat toujours vérifié, compte de service, groupes imbriqués,
  rôle resynchronisé à chaque connexion) ou compte local ; **double authentification TOTP** obligatoire avec
  anti-rejeu ; connexion en 2 étapes (défi serveur 5 min, 5 essais, lié à l'IP) ; verrouillage par (compte, IP)
  avant toute requête à l'AD.
- Mots de passe Argon2id, secrets chiffrés AES-256-GCM (clé maître dans `.env`), cookies HttpOnly / Secure /
  SameSite=Strict, protection CSRF, en-têtes `no-store`, journal d'audit chaîné (`verify-audit`).

### 2.7 Assistant IA

- Analyse d'alerte et conversation, en flux : **Claude** (API Anthropic) ou **Ollama local** au choix.
- Pseudonymisation avant envoi (utilisateurs, postes, IP internes, e-mails) et restauration à l'affichage ;
  données des journaux traitées comme non fiables (protection contre l'injection de consignes).

### 2.8 Recette réalisée (poste de développement)

- 178 tests unitaires, ruff sans remarque ; `tools/smoke_api.py` (22 contrôles).
- Rejeu de l'attaque VPN : 10 058 événements, botnet de 200 IP regroupé, 3 utilisateurs légitimes qualifiés
  « erreur d'utilisateur », connexions réussies depuis le botnet qualifiées « attaque » en critique.
- Essais avec simulateurs : AD (LDAP), SMTP / Teams / ntfy / résumé / escalade, XGS (blocage), Ollama.
- Essais réels : bases MaxMind, catalogue KEV (1 733 CVE), flux CERT-FR, Ollama local (lent : carte graphique
  partagée avec d'autres applications, délai porté à 600 s).
- Restauration d'une sauvegarde, migration Alembic d'une base existante, santé en 503 worker arrêté.

## 3. Reste à faire

### 3.1 Actions de la DSI (bloquantes pour les essais réels)

| Action | Pour |
|---|---|
| Saisir l'accès API du XGS dans Intégrations › Blocage d'IP sur le Sophos XGS › Configurer (`https://<XGS>:4444`, compte API en lecture seule, blocage désactivé) et autoriser l'IP source dans *Administration › API* du XGS | Essai de lecture des règles |
| Installer le Mini-SOC sur une VM du réseau (README « Installation » : `scripts/init_env.py`, `docker compose up -d --build`, `create-user`) | Essai réel de la collecte |
| Sur le XGS : *Configurer › Services système › Paramètres des journaux › Ajouter un serveur syslog* vers l'IP de la VM, port 514 TCP, format standard | Remontée des journaux VPN / pare-feu |
| Renouveler la clé de licence MaxMind utilisée pendant les essais, puis la reporter dans `.env` de la VM | Sécurité |
| Fournir un exemple de réponse de l'API vulnérabilités NinjaOne | Connecteur NinjaOne, UC-15 |
| Indiquer si le XGS est géré dans Sophos Central | Choix API Central vs API locale |

### 3.2 Développement

| Sujet | Réf. | État |
|---|---|---|
| Incidents : regrouper plusieurs alertes, suivi, chronologie (migration Alembic 0002) | F-24 | ✅ 03/10 |
| Rapport mensuel : volumes, alertes par sévérité et règle, délais de prise en charge et de clôture, incidents, attaques | F-29 | ✅ 03/10 (page Rapports, Markdown, e-mail le 1er) |
| Connecteur NinjaOne repris de sesame-ia (alertes, vulnérabilités critiques UC-15, antivirus UC-11, menaces UC-05, postes exposés sur la page Veille) ; pas de croisement KEV possible (l'API ne donne pas les CVE) | UC-11, UC-15 | 🟡 03/10 livré, à raccorder (identifiant et secret de l'application NinjaOne) |
| Connecteur Cyberwatch en lecture seule (API v3, clé d'API) : CVE par actif croisées avec le catalogue KEV, faille activement exploitée présente (UC-48), vulnérabilités prioritaires des serveurs (UC-49), système en fin de support (UC-50), actifs exposés sur la page Veille, classement « à corriger », inventaire, clôture automatique quand les CVE disparaissent ; corrige aussi la clôture automatique des changements de posture NinjaOne (jamais relus jusque-là) | UC-48 à UC-50 | ✅ 07/10 raccordé (58 actifs) ; premier relevé = état des lieux sans alerte |
| Connecteurs API en lecture seule pour les outils cloud, le Mini-SOC n'étant jamais joignable depuis Internet : **Varonis SaaS** (alertes des modèles de menace, délai activité → alerte mesuré, tactiques MITRE, clôture des alertes fermées dans Varonis) et **GravityZone** (incidents EDR par `getIncidentsList`, fichiers mis en quarantaine, clôture des incidents traités) ; le service Event Push de GravityZone et sa publication en DMZ sont abandonnés | — | 🟡 07/10 livré, à raccorder (clés d'API) |
| Recherche par CVE (page Vulnérabilités) : machines touchées d'après Cyberwatch en direct (vulnérables, corrigées avec dates, écartées au triage ; dernier relevé si l'instance est injoignable), fiche KEV, CERT-FR, détections et alertes qui citent la CVE ; liste des CVE présentes sur le parc, KEV d'abord. NinjaOne ne donne pas les CVE par poste | — | ✅ 07/10 |
| **Trivy** : analyse des images Docker du Mini-SOC et des paquets de la VM par le service hôte `minisoc-trivy` (chaque lundi, après chaque mise à jour, bouton « Analyser maintenant » ; conteneur Trivy jetable sans socket Docker, image corrigée `minisoc-trivy`), agent pour les serveurs Linux (jeton par serveur, filtrage IP, rapport compressé vers `/api/ingest/trivy`, liste « Serveurs Trivy » du pare-feu) ; failles fusionnées dans la page Vulnérabilités (composant, version installée → version corrigée), alertes sur les nouvelles failles KEV (UC-52) et critiques corrigeables (UC-53) | UC-52, UC-53 | ✅ 15/10 (testé de bout en bout sur une pile d'essai : 8 cibles, agent, refus 401/403/422) ; à valider sur la VM |
| Vectra (quadrants menace/certitude, lien console, UC-19) et Varonis (comptes, rançongiciel → UC-06) : traitement CEF dédié | — | ✅ 03/10 |
| Connecteur **OGO Security** (WAF) en lecture seule, API v2 (en-tête `X-Ogo-Auth` : e-mail + MD5 du chemin et de la clé, d'après le fournisseur Terraform officiel) : journal chaque minute (attaque en cours → UC-17 ; certificat, DNS → NATIVE ; site supprimé, utilisateur invité ou promu, paramètres de protection → UC-60), état des sites chaque heure (passthrough, mode audit, hors ligne → UC-60), trafic et blocages par site (carte du tableau de bord). L'API ne donne pas le détail des requêtes. **Corrélation par IP** : même IP publique en alerte sur plusieurs outils en 24 h (UC-61, calculée), IP bannie par OGO puis connexion réussie (UC-62), panneau « Vu par OGO » dans le détail des alertes (requêtes de l'IP vers les sites sur 7 jours) | UC-17, UC-60, UC-61, UC-62 | 🟡 16/10 développé et testé (API simulée) ; à valider avec la clé réelle (Tester, sévérités OGO 1 à 3) |
| Routage des notifications par sévérité depuis l'interface (grille sévérité × canal, heures et jours ouvrés) | F-31 | ✅ 03/10 |
| Syslog chiffré TLS 6514 (service vector-tls, profil syslog-tls, scripts/syslog_cert.sh, variante NXLog om_ssl) | — | ✅ 03/10 |
| Isolation de poste depuis une alerte (HarfangLab, Bitdefender), confirmation par nom du poste, désactivée par défaut | F-27 | ✅ 03/10 (à valider sur un poste de test avec un jeton dédié) |
| Connecteur IA multi-fournisseurs repris de LMU Stats Viewer (OpenAI, Anthropic, Gemini, OpenRouter, DeepSeek, Mistral, Ollama, fournisseurs personnalisés, liste des modèles) | — | ✅ 03/10 |
| Titre UC-22 : afficher le poste quand l'outil ne fournit pas d'IP destination (« visant ? ») | — | ✅ 03/10 |
| Connecteur Microsoft 365 / Entra ID (journal d'audit unifié, sans licence P1) : développé et testé (API simulée) | — | 🟡 attend l'inscription d'application Entra ID (ActivityFeed.Read) |
| Croisement des données : **identités unifiées** (un compte sous toutes ses formes — `MAIRIE\jdupont`, UPN et adresses Microsoft 365, nom affiché — d'après l'AD ; une machine par nom court, FQDN ou adresse IP d'après les agents HarfangLab/GravityZone/NinjaOne), colonnes `user_key`/`host_key` à l'ingestion, règles, exceptions, risque et rôles des comptes rapprochés ; **événements en retard** (M365) rattrapés : filigrane sur la date de réception, fenêtres glissantes exactes sur 2 h de marge ; **corrélations entre sources** UC-54 (échecs puis connexion M365 depuis l'étranger), UC-55 (connexion étrangère puis transfert de messagerie), UC-56 (administrateur sur une machine signalée par l'EDR), UC-57 (VPN en France puis M365 à l'étranger) ; **couverture** : machine sans antivirus Bitdefender (UC-58) ou sans EDR HarfangLab (UC-59), le « NONE » de NinjaOne n'alerte plus ; **corroboration** : une machine signalée par plusieurs outils gagne en priorité et en risque | UC-54 à UC-59 | ✅ 14/10 (testé sur ClickHouse 26.9) ; clé GravityZone : ajouter Network API |
| Mise à jour du cahier des charges : règles UC-21 à UC-41 (§4), état de réalisation F-01 à F-31 et ajouts hors cahier (§11) | — | ✅ 03/10 |

### 3.3 Mise en production

- Installation et durcissement de la VM sur le LAN (pas de réseau d'administration) selon
  [04-installation-durcissement-vm.md](04-installation-durcissement-vm.md) : pare-feu local en liste blanche
  (machine + chaîne DOCKER-USER, script validé sur Debian 12), SSH par clé, Docker durci, syslog TLS,
  règle de sortie Internet par FQDN sur le XGS ; option conseillée : VLAN dédié derrière le XGS.
- ✅ 13/10 : **ISO d'installation automatique Debian 13 pour vSphere/VxRail** (`deploy/iso`, doc 04 § 2 bis) :
  installation sans intervention (UEFI + Secure Boot), disque de données, Docker (plage d'adresses choisie),
  durcissement (§ 4, fail2ban, pwquality, modules bloqués), Mini-SOC construit et démarré, pare-feu actif en mode
  initial, sauvegardes planifiées ; console `sudo minisoc-setup` (menus, retour arrière automatique) pour les
  adresses du site, les clés SSH, le certificat web (PKI ou wildcard), le compte de secours. Bases de données sur
  un réseau Docker `internal` (aucune sortie). Testée sous QEMU (UEFI Secure Boot, VMXNET3, 2 disques) ; reste à
  valider sur le VxRail.
- ✅ 15/10 : **images Docker sans faille connue** (Cyberwatch, gestion des correctifs) : Vector, ClickHouse, Redis
  et PostgreSQL sont reconstruites sur la VM à chaque mise à jour, avec les correctifs Alpine publiés depuis
  l'image officielle (`deploy/images/alpine-patch.Dockerfile`) ; ClickHouse en variante Alpine (même serveur,
  même compte) ; `gosu` (Go ancien) remplacé par su-exec ; pip retiré de l'image de l'application, Caddy et Debian
  mis à jour. Sorties nécessaires en plus : `dl-cdn.alpinelinux.org` et `deb.debian.org` en 443.
- Sauvegarde nocturne chiffrée (`backup.sh` en cron), récupérée par un serveur tiers en lecture seule ; essai de
  restauration trimestriel.
- Sonde externe de disponibilité (ex. Uptime Kuma) sur `/api/health/full` (S-12).
- Comptes : groupe AD des administrateurs et des lecteurs, compte de service LDAPS ; enrôlement MFA de chacun.
- Notifications réelles (SMTP de la collectivité, canal Teams, ntfy) et plages horaires.
- Écran mural : créer le jeton d'affichage du poste de diffusion.
- Réglage des seuils et exceptions après 2 à 4 semaines de journaux réels.

## 4. Points d'attention

- Le poste de développement n'est pas joignable depuis Internet : la collecte syslog du XGS distant ne peut pas
  y être testée, d'où la VM sur le réseau.
- L'API XML du XGS sert à la configuration uniquement (pas de lecture des journaux) : les journaux passent par syslog.
- L'Ollama local est partagé avec d'autres applications : réponses lentes possibles ; Claude reste disponible.
- `.env` contient la clé maître : sans elle, les secrets enregistrés (MFA, mots de passe AD/SMTP, clés d'API)
  sont illisibles — à sauvegarder à part.
