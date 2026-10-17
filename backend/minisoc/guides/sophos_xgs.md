# Sophos Firewall (XGS) : envoi des journaux en syslog

Le pare-feu envoie ses journaux au Mini-SOC en temps réel. C'est la source des règles VPN (UC-01 à UC-04), de
l'accès à l'administration (UC-10), de l'IPS et des vulnérabilités exploitées (UC-22).

## Prérequis
- Le pare-feu doit joindre le Mini-SOC **{{MINISOC_HOST}}** sur le port **514/TCP**. Le trafic émis par le pare-feu
  lui-même est autorisé par défaut ; si le Mini-SOC est derrière un autre pare-feu, ouvrir ce flux.
- Compte administrateur de la console Sophos (SFOS 19 ou plus récent).

## Étapes
1. Console Sophos › **Configurer › Services système › Paramètres des journaux** (Log settings).
2. Bouton **Ajouter** dans la partie « Serveurs syslog » :

| Champ | Valeur |
| --- | --- |
| Nom | Mini-SOC |
| Adresse IP / domaine | {{MINISOC_HOST}} |
| Port | 514 |
| Protocole | TCP |
| Fonction (Facility) | DAEMON |
| Niveau (Severity) | **Information** (le niveau minimal envoyé : « Emergency » n'enverrait presque rien) |
| Format | **Standard syslog protocol** (recommandé par Sophos ; l'ancien « Device standard format » reste lu) |

3. Enregistrer, puis dans le tableau des journaux, cocher pour le serveur **Mini-SOC** :
   - **Authentification** : VPN SSL, VPN IPsec, portail utilisateur, authentification de l'administration ;
   - **Événements d'administration** ;
   - **IPS**, **ATP**, **Anti-virus / Sandstorm** (sandbox) ;
   - **Pare-feu** : seulement le trafic **refusé** si vous le souhaitez, jamais le trafic autorisé (volume énorme
     et inutile pour la détection).
4. Enregistrer.

> **Variante chiffrée (recommandée si le flux traverse un réseau non maîtrisé)** : sur le serveur du Mini-SOC,
> `./scripts/syslog_cert.sh {{MINISOC_HOST}}` puis ajouter `syslog-tls` à `COMPOSE_PROFILES` dans `.env` et
> `docker compose up -d vector-tls`. Sur le XGS : même serveur syslog avec le port **6514** et l'option **Connexion
> sécurisée (TLS)** cochée ; importer `data/syslog-tls/ca.crt` comme autorité de certification si le XGS vérifie
> le certificat. Sur un réseau interne, le TCP 514 reste acceptable.

## Vérifier
1. Se connecter au portail VPN avec un mauvais mot de passe (compte de test).
2. Mini-SOC › **Événements**, source Sophos XGS : l'échec apparaît en moins d'une minute.
3. Mini-SOC › **Intégrations** : la fiche passe à « En service ».

## Dépannage
- **Rien n'arrive** : le Mini-SOC ne répond pas au ping du pare-feu (seuls les postes DSI peuvent le pinger), ce
  test ne prouve donc rien. Vérifier que l'adresse d'émission du XGS figure dans les sources syslog 514/TCP de
  `sudo minisoc-setup` (sinon `journalctl -k | grep minisoc-docker-refus-entree` sur le Mini-SOC montre les refus),
  qu'aucun pare-feu intermédiaire ne bloque le 514/TCP, puis `docker compose logs vector` sur le Mini-SOC.
- **Événements « Syslog générique » au lieu de « Sophos XGS »** : format autre que « Standard syslog protocol » ou
  « Device standard format » (par exemple CEF).
- **Trop de volume** : décocher les journaux de trafic du pare-feu.
