# Vectra AI (NDR) : détections par l'API ou en syslog CEF

Vectra fournit ses détections et le score des hôtes et des comptes. Le Mini-SOC crée une alerte pour chaque
détection notable (règle NATIVE) et pour chaque hôte ou compte passé en gravité critique (UC-19). Deux façons de
les recevoir : l'**API** (recommandée, le Mini-SOC va les chercher) ou le **syslog CEF** (Vectra les envoie). Ne
pas activer les deux à la fois : chaque détection arriverait en double.

## Par l'API (recommandé)

Le Mini-SOC interroge Vectra chaque minute en HTTPS sortant (API v3.4) : détections, scores des hôtes et des
comptes. Il reprend au dernier événement lu après une coupure. Il ne modifie rien dans Vectra.

### Prérequis
- Vectra avec l'API v3.4 : plateforme SaaS (`https://<id>.portal.vectra.ai`) ou Brain sur site récent.
- Brain sur site : la VM du Mini-SOC doit le joindre en **443/TCP**. Sur la VM : `sudo minisoc-setup` ›
  **Sortants** › « autres (LAN) » : ajouter `<ip-du-brain>:443`, puis **Appliquer**.

### Étapes
1. Console Vectra › **Paramètres › Clients d'API** (*API Clients*) › **Ajouter**.
2. Nom : `Mini-SOC` ; rôle : **lecture seule** (*Read-Only*). Copier l'**identifiant** et le **secret** (le secret
   n'est affiché qu'une fois).
3. Mini-SOC › **Intégrations › Vectra AI › Configurer** :

| Champ | Valeur |
| --- | --- |
| Adresse de Vectra (API) | `https://brain.mairie.local` ou `https://<id>.portal.vectra.ai` |
| Identifiant du client d'API | identifiant copié à l'étape 2 |
| Secret du client d'API | secret copié à l'étape 2 |
| Vérifier le certificat | coché (décocher seulement pour un essai) |
| Certificat d'autorité du Brain | Brain sur site avec un certificat de la PKI interne : l'autorité racine, en PEM |

4. **Enregistrer**, puis **Tester** : le résultat donne le nombre de détections et de scores des dernières 24 h.

### Vérifier
- Mini-SOC › **Intégrations** : la fiche passe à « En service » dans la minute ; le lien « Voir les événements
  reçus » ouvre les événements Vectra.
- Au premier passage, le Mini-SOC lit les 7 derniers jours.

## Par syslog CEF

### Prérequis
- Vectra doit joindre le Mini-SOC **{{MINISOC_HOST}}** sur le port **514/TCP**. Sur la VM : `sudo minisoc-setup` ›
  **Entrants** › « syslog 514/TCP » : ajouter l'adresse de Vectra, puis **Appliquer**.
- Laisser vides l'adresse et les identifiants d'API de la fiche Vectra.

### Étapes
1. Console Vectra › **Paramètres › Notifications** (ou *Configuration › Notifications › Syslog* selon la version).
2. Ajouter une destination syslog :

| Champ | Valeur |
| --- | --- |
| Destination | {{MINISOC_HOST}} |
| Port | 514 |
| Protocole | TCP |
| Format | CEF |

3. Types de messages : **Détections**, **Score des hôtes**, **Score des comptes**, **Audit** (connexions à la
   console Vectra).
4. Enregistrer et utiliser le bouton de **test** de la destination.

### Vérifier
- Sur la VM : `sudo tcpdump -ni any port 514` montre les messages de Vectra arriver.
- Mini-SOC › **Événements**, source Vectra : le message de test ou les premières détections apparaissent.
- Mini-SOC › **Intégrations** : la fiche passe à « En service ».

## Dépannage
- **Test « identifiants refusés »** : secret mal copié ou client d'API supprimé ; en recréer un.
- **Test « HTTP 404 »** : Vectra trop ancien pour l'API v3.4 ; passer par le syslog CEF.
- **Test « injoignable »** : adresse, sortie `<ip-du-brain>:443` non autorisée sur la VM, ou certificat (autorité
  à fournir pour un Brain sur site).
- **SNMP** : les traps SNMP de Vectra signalent l'état de l'appliance, pas les détections. Le Mini-SOC ne les lit
  pas : utiliser l'API ou le syslog CEF.
- **Événements « Syslog générique »** : le format syslog n'est pas CEF.
