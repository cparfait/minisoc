# Veille : CISA KEV et CERT-FR

Le Mini-SOC télécharge chaque jour le catalogue **CISA KEV** (vulnérabilités activement exploitées) et toutes les
deux heures les publications du **CERT-FR** (alertes, avis, actualités). Une alerte d'un outil qui mentionne une CVE
du catalogue KEV est signalée (badge KEV, règle UC-22), et la page Veille liste les publications récentes.

## Prérequis
Accès HTTPS sortant du serveur du Mini-SOC vers :
- `www.cisa.gov` (catalogue KEV) ;
- `www.cert.ssi.gouv.fr` (flux RSS du CERT-FR).

## Étapes
1. Autoriser ces deux destinations sur le pare-feu (ou le proxy) pour l'adresse du serveur du Mini-SOC.
2. Si un **proxy** est obligatoire, l'indiquer aux conteneurs dans `.env` (transmis aux services `api` et
   `worker`), en excluant les services internes et votre domaine, puis `docker compose up -d` :

```
HTTPS_PROXY=http://proxy.mairie.local:3128
NO_PROXY=localhost,127.0.0.1,postgres,redis,clickhouse,.mairie.local
```
3. Paramètres › Détection : « Veille automatique » cochée (par défaut).

## Vérifier
- Mini-SOC › **Veille** : le nombre de vulnérabilités du catalogue KEV et les dernières publications du CERT-FR.
- Mini-SOC › **Intégrations** : la fiche indique le nombre de CVE chargées.

## Dépannage
- `docker compose logs worker | grep -i kev` : message d'erreur de téléchargement (proxy, filtrage TLS).
