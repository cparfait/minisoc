# NinjaOne : parc et vulnérabilités (lecture seule)

Le Mini-SOC lit NinjaOne avec une application « machine à machine » en portée **Surveillance** (lecture seule,
aucune action possible sur les postes).

Ce qui est remonté :
- **alertes actives** de NinjaOne (toutes les 2 minutes) : disque plein, service arrêté, agent hors ligne… ;
- **état de sécurité du parc** (toutes les 30 minutes), seulement quand il change :
  - nouvelles **vulnérabilités critiques non corrigées** (règle UC-15 ; haute sur un serveur, moyenne sur un poste) ;
  - **antivirus désactivé** ou à définitions obsolètes (UC-11) ;
  - **menace active** signalée par l'antivirus (UC-05, critique) ;
  - correctifs Windows en échec ;
- page **Veille** : postes les plus exposés (vulnérabilités, correctifs en attente, antivirus, menaces) avec un lien
  vers la fiche NinjaOne de chaque appareil.

> L'API NinjaOne donne le nombre de vulnérabilités par gravité, pas leurs numéros CVE : le croisement avec le
> catalogue des vulnérabilités activement exploitées (KEV) reste fait sur les alertes des IPS et EDR (UC-22).

## Prérequis
- Accès HTTPS sortant du Mini-SOC vers votre instance (`eu.ninjarmm.com` pour l'Europe).
- Un compte administrateur NinjaOne pour créer l'application.

## Étapes
1. NinjaOne › **Administration › Applications › API** › **Ajouter une application client**.
2. Type **Services API (de machine à machine)** ; nom « Mini-SOC » ; redirection des URI `https://localhost`
   (champ obligatoire, inutilisé ici) ; champ d'applications **Surveillance** uniquement (ni Gestion, ni Contrôle) ;
   types d'autorisation : **Identifiants du client** uniquement (décocher « Code d'autorisation »). Enregistrer.
3. Copier l'**identifiant client** et le **secret client** (affiché une seule fois).
4. Dans cette fenêtre (onglet Configuration) : instance (Europe), identifiant client, secret. **Enregistrer**, puis
   **Tester** : le test lit une page de l'inventaire et compte les alertes actives.

## Vérifier
- Mini-SOC › **Événements**, source NinjaOne : les alertes actives apparaissent sous 2 minutes.
- Mini-SOC › **Veille** : carte « Parc : postes les plus exposés » remplie après le premier relevé (≈ 1 minute).

## Dépannage
- **« identifiants NinjaOne refusés »** : secret mal copié, application désactivée, ou portée « Surveillance » non
  cochée.
- **Lecture incomplète** dans le journal du worker : NinjaOne a renvoyé moins de lignes qu'annoncé ; nouvel essai
  automatique au relevé suivant.
