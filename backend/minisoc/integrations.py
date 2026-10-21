"""Catalogue des intégrations (le « store ») : solutions compatibles, paramètres, procédure, état.

Une seule source de vérité : les champs (libellés, aides) sont décrits ici et affichés tels quels par l'interface.
Désactiver une intégration de source : ses événements sont ignorés à la réception, elle n'est plus surveillée
(source silencieuse) et son connecteur d'API cesse d'interroger l'outil.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class FieldUI:
    key: str  # clé du magasin de paramètres
    label: str
    kind: str = "text"  # text | secret | bool | int | pem | list | choice
    help: str = ""
    placeholder: str = ""
    choices: tuple[tuple[str, str], ...] = ()
    required: bool = False


@dataclass(frozen=True)
class Integration:
    id: str
    name: str
    vendor: str
    category: str
    modes: tuple[str, ...]
    description: str
    enable_key: str = ""  # paramètre booléen d'activation ("" = toujours actif)
    modules: tuple[str, ...] = ()  # modules d'événements produits (état « données reçues »)
    silence_minutes: int = 0  # surveillance « source silencieuse » (0 = non surveillée)
    fields: tuple[FieldUI, ...] = ()
    test: str = ""  # identifiant du test de connexion
    setup: str = ""  # procédure de raccordement (Markdown simple)
    planned: bool = False  # intégration à venir
    status_kind: str = "source"  # source | feature


CATALOG: tuple[Integration, ...] = (
    Integration(
        id="sophos_xgs", name="Sophos Firewall (XGS)", vendor="Sophos", category="Pare-feu",
        modes=("syslog",), enable_key="src_sophos_xgs_enabled", modules=("sophos_xgs",), silence_minutes=30,
        description="Authentifications VPN (SSL, IPsec, portail), administration, IPS, ATP, antivirus.",
        setup=(
            "1. Configurer > Services système > Paramètres des journaux > Ajouter un serveur syslog.\n"
            "2. Adresse du Mini-SOC, port **514**, **TCP**, format standard.\n"
            "3. Cocher : Authentification (VPN SSL, IPsec, portail, administration), événements "
            "d'administration, IPS, ATP, Anti-virus / Sandstorm.\n"
            "4. Ne pas envoyer le trafic autorisé du pare-feu (volume inutile)."
        ),
    ),
    Integration(
        id="bitdefender", name="Bitdefender GravityZone", vendor="Bitdefender", category="EDR / antivirus",
        modes=("API",), enable_key="src_bitdefender_enabled", modules=("bitdefender",), silence_minutes=30,
        description="Incidents EDR (dont rançongiciel) et fichiers mis en quarantaine, lus par l'API publique "
                    "(HTTPS sortant : le Mini-SOC n'est jamais exposé) ; clôture ici des incidents traités dans "
                    "GravityZone.",
        fields=(
            FieldUI("bitdefender_api_url", "Adresse d'accès à l'API (Access URL)",
                    placeholder="https://cloudgz.gravityzone.bitdefender.com/api",
                    help="Mon compte › Control Center API › Access URL."),
            FieldUI("bitdefender_read_api_key", "Clé d'API de lecture", "secret", required=True,
                    help="API cochées : Incidents, Quarantaine et Réseau (liste des postes protégés, règle UC-58) "
                    "seulement. Distincte de la clé d'isolation."),
            FieldUI("bitdefender_history_days", "Historique relu au raccordement (jours, 0 = tout)", "int",
                    help="365 par défaut ; rattrapé par tranches de 30 jours, une par minute."),
            FieldUI("bitdefender_sync_status", "Clôturer ici ce qui est traité dans GravityZone", "bool",
                    help="Incident clôturé ou classé faux positif dans GravityZone : l'alerte est clôturée dans le "
                    "Mini-SOC avec une trace dans son historique. Rien n'est supprimé."),
        ),
        test="gravityzone",
        setup=(
            "1. GravityZone › Mon compte › **Clés API** › Ajouter : cocher **Incidents API**, **Quarantine API** et "
            "**Network API** (machines sans antivirus, UC-58) uniquement. Copier la clé et l'**Access URL** "
            "(section Control Center API).\n"
            "2. Renseigner l'adresse d'accès et la clé ici, Enregistrer, puis Tester.\n"
            "3. Le Mini-SOC interroge l'API chaque minute (incidents modifiés, fichiers mis en quarantaine) : aucune "
            "publication sur Internet, aucun envoi « Event Push »."
        ),
    ),
    Integration(
        id="harfanglab", name="HarfangLab EDR", vendor="HarfangLab", category="EDR / antivirus",
        modes=("API",), enable_key="src_harfanglab_enabled", modules=("harfanglab",), silence_minutes=15,
        description="Alertes de l'EDR (règles Sigma, YARA, IOC, IA), interrogées chaque minute.",
        fields=(
            FieldUI("harfanglab_url", "Adresse de la console", placeholder="https://edr.mairie.local", required=True),
            FieldUI("harfanglab_token", "Jeton d'API (lecture seule)", "secret", required=True),
            FieldUI("harfanglab_verify_tls", "Vérifier le certificat", "bool"),
            FieldUI("harfanglab_history_days", "Historique relu au raccordement (jours, 0 = tout)", "int",
                    help="Alertes passées importées (sans notification), 0 = toutes depuis l'origine ; "
                    "« Relire l'historique » relance la lecture."),
            FieldUI("harfanglab_sync_status", "Clôturer ici ce qui est traité dans HarfangLab", "bool",
                    help="Faux positif ou clôturée dans HarfangLab : l'alerte est clôturée dans le Mini-SOC, avec la "
                    "trace (statut, auteur, date) dans son historique. Rien n'est supprimé."),
        ),
        test="harfanglab",
        setup="Créer un compte d'API **en lecture seule** dans la console HarfangLab (lecture des alertes et de la "
              "liste des agents : machines sans EDR, UC-59), puis saisir son jeton.",
    ),
    Integration(
        id="crowdsec", name="CrowdSec", vendor="CrowdSec", category="Renseignement / IPS",
        modes=("API",), enable_key="src_crowdsec_enabled", modules=("crowdsec",), silence_minutes=15,
        description="Décisions de bannissement : détections locales en alertes, IP bannies (dont liste "
                    "communautaire) pour enrichir tous les événements (règle UC-18).",
        fields=(
            FieldUI("crowdsec_url", "API locale (LAPI)", placeholder="http://crowdsec.mairie.local:8080",
                    required=True),
            FieldUI("crowdsec_api_key", "Clé de bouncer", "secret", "Créée avec : cscli bouncers add minisoc",
                    required=True),
            FieldUI("crowdsec_community", "Inclure la liste communautaire (enrichissement)", "bool"),
        ),
        test="crowdsec",
        setup="Sur le serveur CrowdSec : `cscli bouncers add minisoc`, puis saisir l'adresse de l'API et la clé.",
    ),
    Integration(
        id="windows", name="Active Directory / Windows", vendor="Microsoft", category="Identité",
        modes=("syslog", "NXLog"), enable_key="src_windows_enabled", modules=("windows",), silence_minutes=30,
        description="Ouvertures de session (dont Kerberos, NTLM), comptes verrouillés, comptes administrateurs et de "
                    "service, groupes à privilèges, kerberoasting, journaux effacés ; serveurs de fichiers : "
                    "renommages en masse et extensions de rançongiciel (FSRM).",
        setup=(
            "1. Installer NXLog Community Edition (gratuite, MSI « Windows x86-64 » ; pas NXLog Agent ni Platform, "
            "payants) sur les contrôleurs de domaine (ou un collecteur WEF) et sur les serveurs de fichiers.\n"
            "2. Utiliser `deploy/nxlog/nxlog.conf` en remplaçant `MINISOC_IP` (port 514 TCP).\n"
            "3. GPO des contrôleurs : audit avancé « Validation des informations d'identification », « Service "
            "d'authentification Kerberos », « Opérations de ticket du service Kerberos », « Ouvrir la session », "
            "« Gestion des comptes d'utilisateur », « Gestion des groupes de sécurité » (succès et échec).\n"
            "4. Serveurs de fichiers : audit « Système de fichiers » (succès) et, sur chaque dossier partagé, une "
            "entrée d'audit « Tout le monde » pour le droit **Suppression** (sous-dossiers et fichiers). En "
            "complément, un filtre de fichiers FSRM « rançongiciel » en mode passif (journalisation seule).\n"
            "5. Pour identifier les comptes sensibles : compte de service LDAPS dans Paramètres › Annuaire AD, et/ou "
            "motifs de noms dans Paramètres › Détection. Suivi dans la page Comptes AD."
        ),
    ),
    Integration(
        id="dns_windows", name="DNS des contrôleurs de domaine", vendor="Microsoft", category="Réseau / DNS",
        modes=("NXLog",), enable_key="src_dns_enabled", modules=("dns",), silence_minutes=60,
        description="Requêtes DNS des postes : domaines malveillants (IOC, sous-domaines compris), tunnels DNS et "
                    "exfiltration (UC-46), domaines générés par algorithme (UC-47).",
        setup=(
            "1. Sur chaque contrôleur de domaine qui sert le DNS : activer le journal de débogage DNS (requêtes "
            "entrantes, UDP et TCP), puis décommenter la section « Requêtes DNS » de `deploy/nxlog/nxlog.conf` "
            "(NXLog Community Edition, gratuit).\n"
            "2. Adapter le filtre de la zone interne (`(5)mairie(5)local(0)`) pour écarter les requêtes internes.\n"
            "3. Vérifier dans Recherche : `module=dns | top dns.question.registered_domain`.\n"
            "4. Ajuster les domaines de confiance (Paramètres › Détection) après quelques jours."
        ),
    ),
    Integration(
        id="vectra", name="Vectra AI (NDR)", vendor="Vectra", category="Réseau / NDR",
        modes=("API", "syslog CEF"), enable_key="src_vectra_enabled", modules=("vectra",),
        description="Détections réseau et entités priorisées : scores de menace et de certitude, entité critique "
                    "(UC-19), techniques MITRE, lien vers la console. Lues par l'API ou reçues en syslog CEF.",
        fields=(
            FieldUI("vectra_url", "Adresse de Vectra (API)", placeholder="https://brain.mairie.local",
                    help="Brain sur site ou plateforme SaaS (https://<id>.portal.vectra.ai). Vide si Vectra envoie "
                    "en syslog CEF (guide)."),
            FieldUI("vectra_client_id", "Identifiant du client d'API",
                    help="Paramètres › Clients d'API (API Clients), rôle en lecture seule."),
            FieldUI("vectra_client_secret", "Secret du client d'API", "secret"),
            FieldUI("vectra_verify_tls", "Vérifier le certificat de Vectra", "bool"),
            FieldUI("vectra_ca_cert", "Certificat d'autorité du Brain (PEM)", "pem",
                    help="Si le Brain sur site utilise un certificat émis par une autorité interne."),
        ),
        test="vectra",
        setup=(
            "**Par l'API (recommandé)** : dans Vectra, Paramètres › Clients d'API › Ajouter, rôle **lecture seule** ; "
            "renseigner l'adresse, l'identifiant et le secret, Enregistrer, Tester. Le Mini-SOC lit chaque minute les "
            "détections et les scores des hôtes et des comptes (API v3.4, HTTPS sortant). Brain sur site : autoriser "
            "`<ip-du-brain>:443` dans les sorties LAN de la VM (sudo minisoc-setup › Sortants).\n"
            "**Par syslog** : réglages de notification syslog, format **CEF**, vers le Mini-SOC port 514 (TCP)."
        ),
    ),
    Integration(
        id="varonis", name="Varonis", vendor="Varonis", category="Données",
        modes=("API SaaS", "syslog CEF"), enable_key="src_varonis_enabled", modules=("varonis",),
        description="Alertes des modèles de menace : accès anormaux aux données, Active Directory (force brute, "
                    "kerberoasting, groupes à privilèges…), rançongiciel ; délai entre l'activité et l'alerte mesuré ; "
                    "clôture ici des alertes fermées dans Varonis.",
        fields=(
            FieldUI("varonis_url", "Adresse de l'instance SaaS", placeholder="https://<tenant>.varonis.io",
                    help="Varonis SaaS uniquement. Varonis installé sur site : syslog CEF (guide)."),
            FieldUI("varonis_api_key", "Clé d'API", "secret",
                    help="Configuration › API Keys, rôle « Threat Detection Integrator »."),
            FieldUI("varonis_sync_status", "Clôturer ici ce qui est fermé dans Varonis", "bool",
                    help="Alerte fermée dans Varonis : clôturée ici avec une trace (motif « activité légitime » : "
                    "faux positif). Rien n'est supprimé."),
        ),
        test="varonis",
        setup=(
            "**Varonis SaaS** : Configuration › API Keys › New API Key, rôle **Threat Detection Integrator** ; "
            "renseigner l'adresse de l'instance et la clé, Enregistrer, Tester. Le Mini-SOC lit les alertes chaque "
            "minute en HTTPS sortant (aucune ouverture depuis Internet).\n"
            "**Varonis sur site** : DatAlert, destination syslog, format **CEF**, vers le Mini-SOC port 514 (TCP)."
        ),
    ),
    Integration(
        id="cef", name="Autres équipements (syslog / CEF)", vendor="Divers", category="Divers",
        modes=("syslog", "CEF"), enable_key="src_syslog_enabled", modules=("syslog",),
        description="Tout équipement capable d'envoyer du syslog (NAS, sauvegarde, commutateurs) : conservé et "
                    "consultable ; les alertes CEF d'autres éditeurs sont reprises par la règle NATIVE.",
        setup="Configurer l'équipement pour envoyer son syslog au Mini-SOC, port 514 (UDP ou TCP).",
    ),
    Integration(
        id="geoip", name="Géolocalisation GeoLite2", vendor="MaxMind", category="Enrichissement",
        modes=("bases locales",), enable_key="geoip_enabled", status_kind="feature",
        description="Pays et opérateur des IP publiques, sans appel externe : bases GeoLite2 téléchargées et mises "
                    "à jour par le Mini-SOC. Règle UC-04 (pays inhabituel), connexions « depuis l'étranger ».",
        fields=(
            FieldUI("maxmind_account_id", "Identifiant du compte MaxMind (Account ID)", placeholder="123456",
                    help="maxmind.com, compte GeoLite2 gratuit : numéro affiché dans Account › Account Information."),
            FieldUI("maxmind_license_key", "Clé de licence", "secret",
                    help="Account › Manage License Keys › Generate new license key."),
        ),
        test="geoip",
        setup=(
            "1. Créer un compte **GeoLite2** gratuit sur maxmind.com.\n"
            "2. Account › **Manage License Keys** › Generate new license key : copier la clé (affichée une seule fois).\n"
            "3. Ici : identifiant du compte (Account ID) et clé ; **Enregistrer**, **Tester**, puis activer. Le Mini-SOC "
            "télécharge les bases dans les 5 minutes, puis les met à jour tous les 3 jours."
        ),
    ),
    Integration(
        id="veille", name="Veille CISA KEV et CERT-FR", vendor="CISA / ANSSI", category="Enrichissement",
        modes=("flux publics",), enable_key="threat_feeds_enabled", status_kind="feature",
        description="Vulnérabilités activement exploitées et publications du CERT-FR ; règle UC-22.",
        setup="Autoriser le serveur à joindre www.cisa.gov et www.cert.ssi.gouv.fr en HTTPS.",
    ),
    Integration(
        id="xgs_response", name="Blocage d'IP sur le Sophos XGS", vendor="Sophos", category="Réponse",
        modes=("API XML",), enable_key="response_enabled", status_kind="feature",
        description="Bouton « Bloquer sur le pare-feu » dans les alertes, avec expiration et traçabilité.",
        fields=(
            FieldUI("xgs_url", "Adresse de l'API", placeholder="https://xgs.mairie.local:4444", required=True),
            FieldUI("xgs_user", "Compte d'API (droits limités aux objets hôtes)", required=True),
            FieldUI("xgs_password", "Mot de passe du compte d'API", "secret", required=True),
            FieldUI("xgs_verify_tls", "Vérifier le certificat du pare-feu", "bool"),
            FieldUI("xgs_ca_cert", "Certificat d'autorité du pare-feu (PEM)", "pem"),
            FieldUI("xgs_block_group", "Groupe d'hôtes des adresses bloquées"),
            FieldUI("block_default_hours", "Durée de blocage par défaut (heures)", "int"),
            FieldUI("never_block", "Adresses jamais bloquables (réseaux)", "list",
                    "Réseaux internes, IP publiques de vos sites, partenaires, prestataires."),
        ),
        test="xgs",
        setup=(
            "1. Activer l'API XML en n'autorisant que l'IP du Mini-SOC ; compte d'API dédié.\n"
            "2. Créer le groupe d'hôtes IP `MiniSOC-Blocages`.\n"
            "3. Règle de pare-feu en tête : source = ce groupe → Abandonner.\n"
            "4. **Exception ACL de service local** (Accès à l'appareil) : source = ce groupe, VPN SSL / IPsec / "
            "portail → Abandonner (indispensable : le VPN est hébergé par le pare-feu)."
        ),
    ),
    Integration(
        id="ai", name="Assistant IA", vendor="Multi-fournisseurs", category="Intelligence artificielle",
        modes=("API",), enable_key="ai_enabled", status_kind="feature",
        description="Analyse des alertes et des événements, questions sur la situation. Fournisseurs : OpenAI, "
                    "Anthropic, Google Gemini, OpenRouter, DeepSeek, Mistral, Ollama (local) et tout service "
                    "compatible OpenAI ajouté à la main (Groq, xAI, LM Studio, vLLM…).",
        fields=(
            FieldUI("ai_provider", "Fournisseur actif"),
            FieldUI("ai_model", "Modèle"),
            FieldUI("ai_base_url", "Adresse du serveur Ollama", placeholder="http://serveur-ia:11434",
                    help="Uniquement pour Ollama."),
            FieldUI("ai_effort", "Niveau de réflexion (Claude)", "choice", choices=(
                ("low", "Faible"), ("medium", "Moyen (recommandé)"), ("high", "Élevé"))),
            FieldUI("ai_max_tokens", "Longueur maximale de réponse (jetons)", "int"),
            FieldUI("ai_pseudonymize", "Pseudonymiser avant envoi hors du réseau (RGPD)", "bool"),
            FieldUI("ai_org_networks", "IP publiques de la collectivité (pseudonymisées)", "list",
                    "Adresses ou plages publiques de vos sites (sorties Internet, services exposés). "
                    "Les IP des attaquants restent visibles."),
            FieldUI("ai_internal_domains", "Domaines internes (pseudonymisés)", "list",
                    "Ex. mairie.local, ville.fr. Le domaine de l'annuaire LDAP et les suffixes .local, .lan, "
                    ".intra, .corp sont déjà pris en compte."),
        ),
        test="ai",
        setup="Ajouter un fournisseur et sa clé, choisir le modèle dans la liste lue chez le fournisseur, puis Tester.",
    ),
    # --- À venir ---------------------------------------------------------------------------------------
    Integration(
        id="ninjaone", name="NinjaOne (parc et vulnérabilités)", vendor="NinjaOne", category="Vulnérabilités",
        modes=("API",), enable_key="src_ninjaone_enabled", modules=("ninjaone",), silence_minutes=60,
        description="Alertes du parc, vulnérabilités critiques non corrigées (UC-15), antivirus coupé ou obsolète "
                    "(UC-11), menaces actives (UC-05) ; postes les plus exposés sur la page Veille.",
        fields=(
            FieldUI("ninjaone_instance", "Instance", "choice", choices=(
                ("eu", "Europe (eu.ninjarmm.com)"), ("us", "États-Unis (app.ninjarmm.com)"),
                ("ca", "Canada (ca.ninjarmm.com)"), ("oc", "Océanie (oc.ninjarmm.com)"))),
            FieldUI("ninjaone_client_id", "Identifiant client (Client ID)", required=True),
            FieldUI("ninjaone_client_secret", "Secret client", "secret", required=True),
            FieldUI("ninjaone_sync_status", "Clôturer ici ce qui est résolu dans NinjaOne", "bool",
                    help="Alerte réinitialisée ou problème de posture résolu : l'alerte est clôturée dans le "
                    "Mini-SOC avec une trace dans son historique. Rien n'est supprimé."),
        ),
        test="ninjaone",
        setup="Application « Services API (machine à machine) » en portée Surveillance (lecture seule), puis Tester.",
    ),
    Integration(
        id="cyberwatch", name="Cyberwatch (vulnérabilités)", vendor="Cyberwatch", category="Vulnérabilités",
        modes=("API",), enable_key="src_cyberwatch_enabled", modules=("cyberwatch",), silence_minutes=120,
        description="CVE présentes sur chaque actif, croisées avec le catalogue CISA KEV : faille activement "
                    "exploitée présente (UC-48), nouvelles vulnérabilités prioritaires (UC-49), système en fin de "
                    "support (UC-50) ; actifs les plus exposés sur la page Veille et dans « Machines à corriger ».",
        fields=(
            FieldUI("cyberwatch_url", "Adresse de l'instance", placeholder="https://cyberwatch.mairie.local",
                    required=True),
            FieldUI("cyberwatch_access_key", "ID de la clé d'accès API", required=True),
            FieldUI("cyberwatch_secret_key", "Secret de la clé d'accès API", "secret", required=True),
            FieldUI("cyberwatch_verify_tls", "Vérifier le certificat de l'instance", "bool"),
            FieldUI("cyberwatch_ca_cert", "Certificat d'autorité de l'instance (PEM)", "pem",
                    help="Si l'instance utilise un certificat émis par une autorité interne."),
            FieldUI("cyberwatch_sync_status", "Clôturer ici ce qui est corrigé dans Cyberwatch", "bool",
                    help="CVE corrigées ou ignorées, système mis à niveau : l'alerte est clôturée dans le Mini-SOC "
                    "avec une trace dans son historique. Rien n'est supprimé."),
        ),
        test="cyberwatch",
        setup=(
            "1. Dans Cyberwatch : Mon profil › Clés d'API › Ajouter, avec un accès **en lecture seule**.\n"
            "2. Renseigner l'adresse de l'instance, l'ID et le secret de la clé, puis Tester.\n"
            "3. Le Mini-SOC n'utilise que des lectures (`/api/v3/ping`, `/api/v3/vulnerabilities/servers`) : il ne "
            "lance aucun scan et ne modifie rien dans Cyberwatch.\n"
            "4. Le croisement avec les failles activement exploitées demande la veille CISA KEV "
            "(Intégrations › Veille)."
        ),
    ),
    Integration(
        id="ogo", name="OGO Security (WAF)", vendor="OGO", category="Pare-feu applicatif",
        modes=("API",), enable_key="src_ogo_enabled", modules=("ogo",), silence_minutes=60,
        description="Attaques web en cours sur les sites protégés : pic de bannissements, afflux de trafic, "
                    "limitation de débit (UC-17) ; protection contournée ou en mode audit, site supprimé, "
                    "utilisateur invité ou promu (UC-60) ; certificats et DNS. Lus par l'API (HTTPS sortant).",
        fields=(
            FieldUI("ogo_email", "E-mail du compte OGO", required=True, placeholder="soc@mairie.fr",
                    help="Adresse de connexion au tableau de bord OGO du compte qui porte la clé d'API."),
            FieldUI("ogo_api_key", "Clé d'API", "secret", required=True,
                    help="Tableau de bord OGO › Mon compte › Mon profil › Authentification › Clé d'API."),
            FieldUI("ogo_organization", "Code de l'organisation",
                    help="Mon compte › Mon organisation › Paramètres. Vide : la seule organisation du compte."),
            FieldUI("ogo_api_url", "Adresse de l'API",
                    help="https://api.ogosecurity.com, sauf instance OGO dédiée."),
        ),
        test="ogo",
        setup=(
            "1. Dans OGO, de préférence un compte dédié au rôle **Viewer** (lecture seule), avec la double "
            "authentification.\n"
            "2. Ce compte › Mon compte › Mon profil › Authentification : générer la **clé d'API** et la copier.\n"
            "3. Ici : e-mail du compte, clé d'API, code de l'organisation (facultatif) ; Enregistrer, puis Tester.\n"
            "4. Le Mini-SOC lit le journal OGO chaque minute (7 derniers jours au premier passage) et l'état des "
            "sites chaque heure, en HTTPS sortant : rien à ouvrir en entrée, rien n'est modifié dans OGO."
        ),
    ),
    Integration(
        id="wordpress", name="WordPress (sites web)", vendor="WordPress.org / WPScan", category="Vulnérabilités",
        modes=("API REST", "détection publique"), enable_key="src_wordpress_enabled", modules=("wordpress",),
        silence_minutes=3 * 24 * 60,
        description="Inventaire quotidien des sites WordPress : version du cœur, extensions et thèmes, mises à jour "
                    "disponibles (api.wordpress.org) et, avec un jeton WPScan, failles connues des versions "
                    "installées (UC-63). Liste par site sur la page Vulnérabilités. Lecture seule, HTTPS sortant.",
        fields=(
            FieldUI("wordpress_wpscan_token", "Jeton d'API WPScan (failles connues)", "secret",
                    help="Facultatif. Compte gratuit sur wpscan.com › Profil › API Token. Sans jeton : mises à "
                    "jour seulement, sans alerte."),
            FieldUI("wordpress_wpscan_daily", "Requêtes WPScan par jour", "int",
                    help="25 pour l'offre gratuite. Les réponses sont gardées 7 jours : au-delà du quota, la suite "
                    "est vérifiée les jours suivants."),
            FieldUI("wordpress_verify_tls", "Vérifier le certificat des sites", "bool"),
        ),
        test="wordpress",
        setup=(
            "1. Sur chaque site (recommandé) : compte administrateur dédié « minisoc », puis Utilisateurs › Profil › "
            "**Mots de passe d'application** › nom « Mini-SOC » › Ajouter ; copier le mot de passe affiché.\n"
            "2. Ici, onglet Configuration : ajouter le site (adresse, identifiant, mot de passe d'application). "
            "Sans identifiant, seule la partie visible du site est inventoriée (liste parfois incomplète).\n"
            "3. Facultatif : jeton WPScan pour les failles connues et les alertes.\n"
            "4. Activer, Enregistrer, puis Tester et « Analyser maintenant ». Site interne : l'autoriser en sortie "
            "(sudo minisoc-setup › Accès sortants › Autres (LAN), adresse:443)."
        ),
    ),
    Integration(
        id="m365", name="Microsoft 365 / Entra ID", vendor="Microsoft", category="Identité",
        modes=("API Office 365 Management",), enable_key="src_m365_enabled", modules=("m365",),
        silence_minutes=1440,
        description="Connexions Entra ID (depuis l'étranger, voyage impossible, pulvérisation, fatigue MFA), rôles "
                    "d'administration, consentements d'applications, règles de transfert de messagerie. Sans "
                    "licence Entra ID P1 (journal d'audit unifié, délai de 30 min à quelques heures).",
        fields=(
            FieldUI("m365_tenant_id", "Identifiant du tenant (ID de l'annuaire)", required=True,
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    help="Entra › Inscriptions d'applications › Mini-SOC › Vue d'ensemble : « ID de l'annuaire "
                    "(locataire) »."),
            FieldUI("m365_client_id", "Identifiant de l'application (client)", required=True,
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
                    help="Même page : « ID d'application (client) »."),
            FieldUI("m365_client_secret", "Secret client", "secret", required=True,
                    help="Certificats & secrets : colonne « Valeur » (≈ 40 caractères avec ~ . _), copiée à la "
                    "création. Pas la colonne « ID de secret » (format xxxxxxxx-xxxx-…)."),
            FieldUI("m365_exchange", "Règles de transfert de messagerie (journal Exchange)", "bool"),
        ),
        test="m365",
        setup=(
            "1. Centre d'administration Entra › Inscriptions d'applications › **Nouvelle inscription** "
            "(« Mini-SOC », comptes de cet annuaire uniquement, sans URI de redirection).\n"
            "2. Autorisations des API › Ajouter › **Office 365 Management APIs** › Autorisations d'application › "
            "**ActivityFeed.Read**, puis **Accorder le consentement administrateur**.\n"
            "3. Certificats et secrets › Nouveau secret client (24 mois au plus) : copier tout de suite la colonne "
            "**Valeur** (pas « ID de secret »), masquée dès qu'on quitte la page.\n"
            "4. Vérifier que l'audit est actif : portail Microsoft Purview › Audit (actif par défaut).\n"
            "5. Ici : **ID de l'annuaire (locataire)** et **ID d'application (client)** (page Vue d'ensemble de "
            "l'application), **Valeur** du secret ; Enregistrer, puis Tester. Premières données sous 30 min à "
            "quelques heures. Renseigner les pays habituels dans Paramètres › Détection."
        ),
    ),
    Integration(
        id="siem_export", name="Export vers un SIEM ou un SOC", vendor="Syslog (JSON ECS ou CEF)",
        category="Réponse", modes=("syslog",), enable_key="export_enabled", status_kind="feature",
        description="Transfère les alertes (et, si demandé, tous les événements normalisés) vers un SIEM ou un "
        "SOC externe : SOC mutualisé, CSIRT régional, Microsoft Sentinel, Splunk, Wazuh…",
        fields=(
            FieldUI("export_host", "Adresse du collecteur", placeholder="soc.exemple.fr", required=True),
            FieldUI("export_port", "Port", "int", help="6514 en TLS, 514 en TCP ou UDP."),
            FieldUI("export_protocol", "Transport", "choice", choices=(
                ("tls", "TLS (chiffré, recommandé)"), ("tcp", "TCP"), ("udp", "UDP"))),
            FieldUI("export_tls_verify", "Vérifier le certificat du collecteur", "bool"),
            FieldUI("export_format", "Format", "choice", choices=(
                ("json", "JSON (champs ECS)"), ("cef", "CEF (ArcSight, la plupart des SIEM)"))),
            FieldUI("export_scope", "Contenu", "choice", choices=(
                ("alerts", "Alertes seulement"), ("both", "Alertes et tous les événements"))),
            FieldUI("export_min_severity", "Sévérité minimale des alertes", "choice", choices=(
                ("info", "Info"), ("low", "Faible"), ("medium", "Moyenne"), ("high", "Haute"),
                ("critical", "Critique"))),
            FieldUI("export_hostname", "Nom d'émetteur (syslog)",
                    help="Nom sous lequel le Mini-SOC apparaît chez le destinataire."),
        ),
        test="export",
        setup="Demander au destinataire l'adresse et le port de son collecteur syslog (TLS de préférence), "
        "autoriser le flux sortant sur le pare-feu, puis **Tester**. Les données sortent de la collectivité : "
        "vérifier le cadre contractuel (convention, RGPD) avant d'exporter tous les événements.",
    ),
    Integration(
        id="edr_isolation", name="Isolation de poste (HarfangLab, Bitdefender)", vendor="HarfangLab / Bitdefender",
        category="Réponse", modes=("API",), enable_key="isolation_enabled", status_kind="feature",
        description="Bouton « Isoler le poste » dans les alertes EDR : le poste ne communique plus qu'avec la console "
                    "de l'EDR. Confirmation par le nom du poste, traçabilité complète (F-27).",
        fields=(
            FieldUI("harfanglab_isolation_token", "Jeton HarfangLab avec le droit d'isolation", "secret",
                    help="Distinct du jeton de lecture des alertes ; l'adresse de la console est celle de "
                         "l'intégration HarfangLab."),
            FieldUI("bitdefender_api_url", "Adresse de l'API GravityZone",
                    placeholder="https://cloudgz.gravityzone.bitdefender.com/api"),
            FieldUI("bitdefender_api_key", "Clé d'API GravityZone (droits Incidents et Network)", "secret"),
        ),
        test="isolation",
        setup="Jeton ou clé d'API dédiés à l'isolation, puis activer l'interrupteur de la fiche.",
    ),
)

BY_ID = {i.id: i for i in CATALOG}
DROPPED_KEY = "minisoc:sources:dropped"  # hash module -> événements ignorés (intégration désactivée)
GEOIP_STATUS_KEY = "minisoc:status:geoip"
SOURCE_MODULES = {m: i for i in CATALOG for m in i.modules}


def disabled_modules(cfg: dict) -> set[str]:
    return {m for i in CATALOG if i.enable_key and i.modules and not cfg.get(i.enable_key, False) for m in i.modules}


def configured_missing(cfg: dict) -> set[str]:
    """Modules dont l'intégration n'est pas encore configurée : jamais signalés comme silencieux."""
    return {m for i in CATALOG for m in i.modules if any(f.required and not cfg.get(f.key) for f in i.fields)}


def monitored_sources(cfg: dict) -> dict[str, timedelta]:
    """Sources surveillées (UC-16) : intégrations actives ayant un délai de silence."""
    return {m: timedelta(minutes=i.silence_minutes) for i in CATALOG if i.silence_minutes and not i.planned
            and cfg.get(i.enable_key, False) for m in i.modules}


def status(item: Integration, cfg: dict, last_seen: dict[str, datetime], extra: dict | None = None) -> dict:
    """État affiché sur la fiche : planned | disabled | not_configured | active | waiting | silent."""
    extra = extra or {}
    enabled = bool(cfg.get(item.enable_key, False)) if item.enable_key else True
    seen = [last_seen[m] for m in item.modules if m in last_seen]
    last = max(seen) if seen else None
    missing = [f.label for f in item.fields if f.required and not cfg.get(f.key)]
    if item.planned:
        state = "planned"
    elif not enabled:
        state = "disabled"
    elif missing:
        state = "not_configured"
    elif item.status_kind == "feature":
        state = "active" if extra.get("ready", True) else "waiting"
    elif last is None:
        state = "waiting"
    elif item.silence_minutes and datetime.now(timezone.utc) - last > timedelta(minutes=item.silence_minutes):
        state = "silent"
    else:
        state = "active"
    return {
        **{k: v for k, v in asdict(item).items() if k not in ("fields",)},
        "fields": [asdict(f) for f in item.fields],
        "enabled": enabled,
        "state": state,
        "missing": missing,
        "last_seen": last.isoformat() if last else None,
        "detail": extra.get("detail", ""),
    }

