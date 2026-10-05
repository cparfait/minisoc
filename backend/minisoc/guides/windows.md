# Active Directory / Windows : journaux des contrôleurs de domaine et des serveurs de fichiers

Les serveurs Windows enregistrent dans leur journal « Sécurité » les ouvertures de session, échecs, verrouillages,
modifications de comptes et de groupes. Un agent gratuit, **NXLog Community Edition**, les envoie au Mini-SOC.

Ce qui est détecté :
- comptes verrouillés et leur origine (UC-14, UC-23, UC-24 et page Comptes AD) ;
- pulvérisation de mots de passe (UC-21) ;
- comptes administrateurs et de service (UC-25 à UC-29) ;
- ajouts aux groupes à privilèges (UC-12) ;
- kerberoasting (UC-30) ;
- journal effacé (UC-13) ;
- sur les serveurs de fichiers : renommages en masse et extensions de rançongiciel (UC-32, UC-33).

## Prérequis
- Les serveurs doivent joindre le Mini-SOC **{{MINISOC_HOST}}** sur le port **514/TCP**.
- Le fichier de configuration fourni avec le Mini-SOC : `deploy/nxlog/nxlog.conf`.

## 1. Installer NXLog (contrôleurs de domaine et serveurs de fichiers)
1. Télécharger **NXLog Community Edition** (MSI 64 bits) sur nxlog.co et l'installer (service « nxlog »).
2. Copier `deploy/nxlog/nxlog.conf` vers `C:\Program Files\nxlog\conf\nxlog.conf`.
3. Dans ce fichier, remplacer `MINISOC_IP` par **{{MINISOC_HOST}}**.
4. Redémarrer le service (PowerShell administrateur) :

```
Restart-Service nxlog
Test-NetConnection {{MINISOC_HOST}} -Port 514
```

Le fichier ne transmet que les événements utiles : les connexions des comptes machine, les tickets Kerberos AES
et les lectures de fichiers sont filtrés pour limiter le volume.

> **Envoi chiffré (TLS, port 6514)** : sur le Mini-SOC, `./scripts/syslog_cert.sh NOM_DNS_DU_MINISOC` puis profil
> `syslog-tls` (voir le guide Sophos XGS) ; sur chaque serveur, copier `data/syslog-tls/ca.crt` dans
> `C:\Program Files\nxlog\cert\` et utiliser le bloc `om_ssl` commenté à la fin de `nxlog.conf`.

> Variante centralisée : au lieu d'installer NXLog sur chaque serveur, configurer le transfert d'événements Windows
> (WEF) vers un serveur collecteur et n'installer NXLog que sur celui-ci (le fichier lit déjà `ForwardedEvents`).

## 2. Activer l'audit (GPO des contrôleurs de domaine)
Dans une GPO liée à l'unité d'organisation **Domain Controllers** : *Configuration ordinateur › Stratégies ›
Paramètres Windows › Paramètres de sécurité › Configuration avancée de la stratégie d'audit*.

| Catégorie | Sous-catégorie | Réglage |
| --- | --- | --- |
| Connexion de compte | Validation des informations d'identification | Succès et échec |
| Connexion de compte | Service d'authentification Kerberos | Succès et échec |
| Connexion de compte | Opérations de ticket du service Kerberos | Succès et échec |
| Ouverture/fermeture de session | Ouvrir la session | Succès et échec |
| Gestion des comptes | Gestion des comptes d'utilisateur | Succès et échec |
| Gestion des comptes | Gestion des groupes de sécurité | Succès |
| Changement de stratégie | Auditer la modification de la stratégie | Succès |

Puis, dans *Options de sécurité* : **Audit : force les paramètres de sous-catégorie de stratégie d'audit à se
substituer aux paramètres de catégorie** = Activé. Agrandir le journal Sécurité (1 à 4 Go). Appliquer avec
`gpupdate /force` sur les contrôleurs.

## 3. Serveurs de fichiers : renommages en masse et rançongiciel
1. GPO des serveurs de fichiers : *Accès à l'objet › Auditer le système de fichiers* = **Succès**.
2. Sur chaque dossier partagé : *Propriétés › Sécurité › Avancé › Audit › Ajouter* : principal **Tout le monde**,
   type **Succès**, s'applique à « Ce dossier, les sous-dossiers et les fichiers », autorisation avancée
   **Suppression** uniquement (un renommage est journalisé comme une suppression).
3. Facultatif mais recommandé : rôle **Gestionnaire de ressources du serveur de fichiers (FSRM)**, groupe de
   fichiers « Rançongiciel » (extensions `*.locky`, `*.encrypted`, `*.crypt`, notes `*READ_ME*`…), filtre de
   fichiers **passif** (journalisation seule) sur les partages, avec écriture dans le journal des événements.

## 4. Comptes sensibles
- Paramètres › **Annuaire AD** : compte de service LDAPS en lecture seule. Le Mini-SOC lit chaque heure les
  administrateurs (adminCount=1) et les comptes de service (SPN, gMSA).
- Et/ou Paramètres › **Détection** : motifs de noms (`adm-*`, `svc*`…).

## Vérifier
1. Se tromper de mot de passe sur un poste du domaine.
2. Mini-SOC › **Événements**, source Windows / AD : l'échec (4771 ou 4625) apparaît avec le poste d'origine.
3. Page **Comptes AD** : comptes sensibles listés, verrouillages visibles.

## Dépannage
- **Rien n'arrive** : `C:\Program Files\nxlog\data\nxlog.log` sur le serveur ; `Test-NetConnection` ci-dessus.
- **Pas d'échecs Kerberos ou NTLM** : la GPO d'audit n'est pas appliquée (`auditpol /get /category:*` sur le
  contrôleur).
- **Pas de poste d'origine sur les verrouillages** : normal pour certains échecs Kerberos ; l'adresse IP est alors
  indiquée.
