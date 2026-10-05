"""Tables PostgreSQL : utilisateurs, sessions, alertes, exceptions, journal d'audit."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

ALERT_STATUSES = ("new", "in_progress", "waiting", "resolved", "false_positive")
OPEN_STATUSES = ("new", "in_progress", "waiting")  # « en attente » (tiers, correctif planifié) : toujours ouverte
WAITING_REASONS = ("utilisateur", "prestataire", "editeur", "correctif", "autre")
ROLES = ("admin", "analyst", "viewer")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)  # en minuscules
    auth_source: Mapped[str] = mapped_column(String(8), default="local")  # local | ldap
    display_name: Mapped[str] = mapped_column(String(256), default="")
    email: Mapped[str] = mapped_column(String(256), default="")
    password_hash: Mapped[str] = mapped_column(String(255), default="")  # vide pour un compte AD
    totp_secret_enc: Mapped[str] = mapped_column(String(255), default="")  # vide = MFA à enrôler
    totp_last_step: Mapped[int] = mapped_column(BigInteger, default=0)  # anti-rejeu d'un code TOTP
    role: Mapped[str] = mapped_column(String(16), default="analyst")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuthChallenge(Base):
    """Étape intermédiaire de connexion (mot de passe validé, second facteur attendu), conservée côté serveur."""

    __tablename__ = "auth_challenges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 du jeton
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # totp | enroll
    pending_secret_enc: Mapped[str] = mapped_column(String(255), default="")  # clé MFA en cours d'enrôlement
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    ip: Mapped[str] = mapped_column(String(64), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class LoginThrottle(Base):
    """Échecs de connexion par (identifiant, IP) : un tiers ne peut pas verrouiller le compte d'un collègue."""

    __tablename__ = "login_throttle"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Setting(Base):
    """Paramètres modifiables depuis l'interface (AD, SMTP, IA). Les secrets sont chiffrés (AES-256-GCM)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # SHA-256 du jeton, jamais le jeton
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(256), default="")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_dedup", "rule_id", "entity_key", "status"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(256))
    severity: Mapped[int] = mapped_column(Integer, index=True)
    title: Mapped[str] = mapped_column(String(300))
    entity_key: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(16), default="new", index=True)
    assignee: Mapped[str | None] = mapped_column(String(64))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # prise en charge (échéances)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    metric: Mapped[int] = mapped_column(Integer, default=0)
    event_ids: Mapped[list] = mapped_column(JSONB, default=list)
    modules: Mapped[list] = mapped_column(JSONB, default=list)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    reference: Mapped[str] = mapped_column(String(512), default="")
    notify_pending: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reminded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # relance (escalade F-18)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


INCIDENT_STATUSES = ("open", "investigating", "contained", "closed")
INCIDENT_CATEGORIES = ("compromission_compte", "malware", "rancongiciel", "hameconnage", "intrusion", "fuite_donnees",
                       "deni_service", "autre")


DETECTION_CATEGORIES = ("threat", "hygiene", "info")


class DetectionProfile(Base):
    """Fiche d'une détection d'outil (ex. « Recommended driver block list » de HarfangLab) : catégorie et
    sévérité recalibrée, appliquées à ses alertes. Réglage de la DSI, tracé dans le journal d'audit."""

    __tablename__ = "detection_profiles"
    __table_args__ = (Index("ux_detection_profiles", "module", "detection", unique=True),)

    id: Mapped[int] = mapped_column(primary_key=True)
    module: Mapped[str] = mapped_column(String(64))
    detection: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(16), default="threat")  # threat, hygiene, info
    severity: Mapped[int | None] = mapped_column(Integer)  # None : sévérité de l'outil
    note: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())


class SavedSearch(Base):
    """Recherche enregistrée (page Recherche) : personnelle ou partagée avec l'équipe."""

    __tablename__ = "saved_searches"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    query: Mapped[str] = mapped_column(Text)
    period: Mapped[str] = mapped_column(String(16), default="24h")
    owner: Mapped[str] = mapped_column(String(64), index=True)
    shared: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CustomRule(Base):
    """Règle ajoutée depuis l'interface (import Sigma) : stockée en base, chargée avec les règles des fichiers."""

    __tablename__ = "custom_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), unique=True)
    source: Mapped[str] = mapped_column(String(16), default="sigma")
    original: Mapped[str] = mapped_column(Text, default="")  # règle d'origine (YAML Sigma)
    definition: Mapped[dict] = mapped_column(JSONB)  # règle Mini-SOC convertie
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)  # activée après rejeu sur l'historique
    author: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())


ASSET_KINDS = ("host", "account")
CRITICALITIES = ("low", "normal", "high", "vital")


class Asset(Base):
    """Inventaire : machine ou compte, avec sa criticité, son propriétaire et son service."""

    __tablename__ = "assets"
    __table_args__ = (Index("ux_assets_kind_name", "kind", "name", unique=True),)

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # host | account
    name: Mapped[str] = mapped_column(String(256))  # en minuscules (clé)
    display_name: Mapped[str] = mapped_column(String(256))
    criticality: Mapped[str] = mapped_column(String(16), default="normal")
    owner: Mapped[str] = mapped_column(String(256), default="")
    service: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    asset_type: Mapped[str] = mapped_column(String(32), default="")  # serveur, poste, admin, service…
    source: Mapped[str] = mapped_column(String(32), default="manual")  # manual, ad, ninjaone, events
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)  # classé par la DSI
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)  # service accessible depuis Internet
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=func.now())


IOC_TYPES = ("ip", "domain", "hash", "url")


class Ioc(Base):
    """Indicateur de compromission recherché dans tout l'historique des journaux."""

    __tablename__ = "iocs"
    __table_args__ = (Index("ux_iocs_type_value", "type", "value", unique=True),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(128), default="manuel")
    description: Mapped[str] = mapped_column(Text, default="")
    author: Mapped[str] = mapped_column(String(64), default="")
    hits: Mapped[int] = mapped_column(Integer, default=0)
    last_hit: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hunted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # dernière chasse complète
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IocFeed(Base):
    """Liste externe d'IOC (une valeur par ligne), relue chaque jour."""

    __tablename__ = "ioc_feeds"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    url: Mapped[str] = mapped_column(String(512))
    type: Mapped[str] = mapped_column(String(16))  # ip, domain, hash, url ou auto
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")


class Archive(Base):
    """Archive scellée d'une journée d'événements : empreinte du fichier, chaînée à la précédente."""

    __tablename__ = "archives"

    id: Mapped[int] = mapped_column(primary_key=True)
    day: Mapped[str] = mapped_column(String(10), unique=True)  # AAAA-MM-JJ (UTC)
    path: Mapped[str] = mapped_column(String(256))
    events: Mapped[int] = mapped_column(Integer)
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    chain_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Incident(Base):
    """Incident (F-24) : plusieurs alertes liées, suivies ensemble jusqu'à la clôture (conclusion obligatoire)."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(32), default="autre")
    severity: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    owner: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(64))
    personal_data: Mapped[bool] = mapped_column(Boolean, default=False)  # données personnelles concernées (CNIL)
    conclusion: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentEntry(Base):
    """Chronologie d'un incident : notes, actions menées, changements d'état, alertes rattachées."""

    __tablename__ = "incident_entries"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16))  # note, action, status, alert_added, alert_removed, created, update
    detail: Mapped[str] = mapped_column(Text, default="")


class AlertHistory(Base):
    __tablename__ = "alert_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(64))  # utilisateur ou « système »
    action: Mapped[str] = mapped_column(String(32))  # created, escalated, status, assign, comment, notified
    detail: Mapped[str] = mapped_column(Text, default="")


class RuleException(Base):
    __tablename__ = "rule_exceptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)  # « * » = toutes les règles
    field: Mapped[str] = mapped_column(String(64))  # champ ECS
    value: Mapped[str] = mapped_column(String(512))
    reason: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Journal en ajout seul ; chaque ligne porte l'empreinte de la précédente (chaîne vérifiable)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    object: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class DisplayToken(Base):
    """Jeton d'un écran mural : lecture seule, limité au tableau de bord d'affichage, révocable."""

    __tablename__ = "display_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256, jamais le jeton
    allowed_ips: Mapped[list] = mapped_column(JSONB, default=list)  # vide = toutes
    mask_users: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ip: Mapped[str] = mapped_column(String(64), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Block(Base):
    """Adresse IP bloquée sur le pare-feu à partir du Mini-SOC (réponse à incident, F-26)."""

    __tablename__ = "blocks"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(String(512), default="")
    alert_id: Mapped[int | None] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)  # active | removed | failed
    detail: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_by: Mapped[str] = mapped_column(String(64), default="")
