# Vectra AI (NDR) : détections en syslog CEF

Vectra envoie ses détections et le score des hôtes et comptes au format CEF. Le Mini-SOC les reçoit et crée une
alerte pour chaque détection notable (règle NATIVE).

## Prérequis
- Vectra (Brain ou plateforme) doit joindre le Mini-SOC **{{MINISOC_HOST}}** sur le port **514/TCP**.

## Étapes
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
4. Enregistrer et utiliser le bouton de **test** de la destination s'il existe.

## Vérifier
- Mini-SOC › **Événements**, source Vectra : le message de test ou les premières détections apparaissent.
- Mini-SOC › **Intégrations** : la fiche passe à « En service ».

## Dépannage
- **Événements « Syslog générique »** : le format n'est pas CEF.
- **Rien n'arrive** : pare-feu entre Vectra et le Mini-SOC ; `docker compose logs vector`.
