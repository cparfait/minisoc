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
        modes=("push HTTPS",), enable_key="src_bitdefender_enabled", modules=("bitdefender",),
        description="Malware, rançongiciel, HyperDetect, incidents EDR, antiphishing, modules désactivés.",
        fields=(
            FieldUI("bitdefender_token", "Valeur attendue de l'en-tête Authorization", "secret",
                    "À reprendre à l'identique dans serviceSettings.authorization (setPushEventSettings).",
                    required=True),
            FieldUI("bitdefender_allowed_ips", "Plages d'IP autorisées à pousser", "list",
                    "IP du service push de Bitdefender ; vide = pas de filtrage (déconseillé).",
                    "203.0.113.0/24"),
            FieldUI("bitdefender_console_url", "Adresse de la console", placeholder=(
                "https://cloud.gravityzone.bitdefender.com")),
        ),
        setup=(
            "1. Publier **uniquement** `/api/ingest/bitdefender` via un reverse proxy en DMZ (certificat valide).\n"
            "2. API publique GravityZone, méthode `setPushEventSettings` : serviceType `jsonRPC`, url "
            "`https://<adresse publique>/api/ingest/bitdefender`, authorization = la valeur ci-dessus, "
            "requireValidSslCertificate `true`.\n"
            "3. Événements : av, hd, avc, ransomware-mitigation, new-incident, network-monitor, aph, modules."
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
        setup="Créer un compte d'API **en lecture seule** dans la console HarfangLab, puis saisir son jeton.",
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
            "1. Installer NXLog Community Edition sur les contrôleurs de domaine (ou un collecteur WEF) et sur les "
            "serveurs de fichiers.\n"
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
            "1. Sur chaque contrôleur de domaine qui sert le DNS, NXLog (déjà installé pour les journaux "
            "Windows) : décommenter la section « Requêtes DNS » de `deploy/nxlog/nxlog.conf` (option A, ETW).\n"
            "2. Adapter le filtre de la zone interne (`mairie.local`) pour écarter les requêtes internes.\n"
            "3. Vérifier dans Recherche : `module=dns | top dns.question.registered_domain`.\n"
            "4. Ajuster les domaines de confiance (Paramètres › Détection) après quelques jours."
        ),
    ),
    Integration(
        id="vectra", name="Vectra AI (NDR)", vendor="Vectra", category="Réseau / NDR",
        modes=("syslog CEF",), enable_key="src_vectra_enabled", modules=("vectra",),
        description="Détections réseau et entités priorisées, reçues en CEF : scores de menace et de certitude, "
                    "quadrant critique (UC-19), lien vers la console.",
        setup="Dans Vectra : réglages de notification syslog, format **CEF**, vers le Mini-SOC port 514 (TCP).",
    ),
    Integration(
        id="varonis", name="Varonis", vendor="Varonis", category="Données",
        modes=("syslog CEF",), enable_key="src_varonis_enabled", modules=("varonis",),
        description="Alertes DatAlert : accès anormaux aux partages, rançongiciel, changements de droits.",
        setup="Dans Varonis DatAlert : destination syslog, format **CEF**, vers le Mini-SOC port 514 (TCP).",
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
        description="Pays et opérateur des IP publiques, sans appel externe. Règle UC-04 (pays inhabituel).",
        setup=(
            "1. Compte gratuit sur maxmind.com, puis Manage license keys > Generate new license key.\n"
            "2. Dans `.env` : `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, `COMPOSE_PROFILES=geoip`.\n"
            "3. `docker compose up -d geoipupdate` (mise à jour automatique tous les 3 jours)."
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
        id="ogo", name="OGO Security (WAF)", vendor="OGO", category="Pare-feu applicatif",
        modes=("API / export",), planned=True,
        description="Attaques web bloquées, bots, IP bannies sur les sites protégés (UC-17).",
        setup="Vérifier avec l'éditeur les possibilités d'export (API ou syslog) de votre offre.",
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
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),
            FieldUI("m365_client_id", "Identifiant de l'application (client)", required=True,
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),
            FieldUI("m365_client_secret", "Secret client", "secret", required=True,
                    help="Valeur du secret (pas son identifiant). Noter sa date d'expiration pour le renouveler."),
            FieldUI("m365_exchange", "Règles de transfert de messagerie (journal Exchange)", "bool"),
        ),
        test="m365",
        setup=(
            "1. Centre d'administration Entra › Inscriptions d'applications › **Nouvelle inscription** "
            "(« Mini-SOC », comptes de cet annuaire uniquement, sans URI de redirection).\n"
            "2. Autorisations des API › Ajouter › **Office 365 Management APIs** › Autorisations d'application › "
            "**ActivityFeed.Read**, puis **Accorder le consentement administrateur**.\n"
            "3. Certificats et secrets › Nouveau secret client (24 mois au plus) : copier la **valeur**.\n"
            "4. Vérifier que l'audit est actif : portail Microsoft Purview › Audit (actif par défaut).\n"
            "5. Saisir ici l'ID du tenant, l'ID de l'application et le secret, puis Tester. Premières données sous "
            "30 min à quelques heures. Renseigner les pays habituels dans Paramètres › Détection."
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
                    placeholder="https://cloud.gravityzone.bitdefender.com/api"),
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
    return {m for i in CATALOG if i.enable_key and i.modules and not cfg.get(i.enable_key, True) for m in i.modules}


def configured_missing(cfg: dict) -> set[str]:
    """Modules dont l'intégration n'est pas encore configurée : jamais signalés comme silencieux."""
    return {m for i in CATALOG for m in i.modules if any(f.required and not cfg.get(f.key) for f in i.fields)}


def monitored_sources(cfg: dict) -> dict[str, timedelta]:
    """Sources surveillées (UC-16) : intégrations actives ayant un délai de silence."""
    return {m: timedelta(minutes=i.silence_minutes) for i in CATALOG if i.silence_minutes and not i.planned
            and cfg.get(i.enable_key, True) for m in i.modules}


def status(item: Integration, cfg: dict, last_seen: dict[str, datetime], extra: dict | None = None) -> dict:
    """État affiché sur la fiche : planned | disabled | not_configured | active | waiting | silent."""
    extra = extra or {}
    enabled = bool(cfg.get(item.enable_key, True)) if item.enable_key else True
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

