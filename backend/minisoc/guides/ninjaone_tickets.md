# Tickets NinjaOne

Depuis une alerte, un analyste peut **ouvrir un ticket dans NinjaOne** et en suivre l'état sans quitter le Mini-SOC.

Garde-fous :
- fonction **désactivée par défaut** (interrupteur de cette fiche) ;
- **application NinjaOne dédiée**, distincte de l'application de lecture en portée Surveillance, qui reste en lecture
  seule ;
- le sujet et le texte sont **relus et modifiables avant l'envoi** ; les journaux bruts ne sont jamais transmis ;
- un seul ticket par alerte ;
- traçabilité : journal d'audit, historique de l'alerte, chronologie de l'incident.

Suivi : l'état du ticket est relu **toutes les 5 minutes** et affiché sur l'alerte et dans la liste ; chaque changement
est inscrit dans l'historique. **Le ticket ne clôture jamais l'alerte** : résoudre un ticket ne prouve pas que la
menace est traitée.

## Prérequis
- Module **Ticketing** activé dans NinjaOne, avec au moins un formulaire de ticket.
- Accès HTTPS sortant du Mini-SOC vers votre instance (`eu.ninjarmm.com` pour l'Europe).

## Étapes
1. NinjaOne › **Administration › Applications › API** › **Ajouter une application client**.
2. Type **Services API (de machine à machine)** ; nom « Mini-SOC tickets » ; champs d'applications **Surveillance** et
   **Gestion** ; type d'autorisation **Identifiants du client** uniquement. Enregistrer.
3. Copier l'**identifiant client** et le **secret client** (affiché une seule fois).
4. Dans cette fenêtre : instance, identifiant et secret. **Enregistrer**, puis **Tester** : le test n'ouvre aucun
   ticket et affiche les numéros d'organisation et de formulaire.
5. Renseigner ces deux numéros, **Enregistrer**, **Tester** de nouveau, puis activer l'interrupteur.

## Vérifier
- Ouvrir une alerte de test › **Que faire › Ouvrir un ticket NinjaOne**, envoyer, puis contrôler le ticket dans la
  console : organisation, formulaire, appareil et texte.
- Changer son état dans NinjaOne : la fiche de l'alerte le reflète sous 5 minutes.

## Dépannage
- **« accès refusé par NinjaOne »** : portée Gestion non cochée, droits de l'application, ou module Ticketing inactif.
- **« NinjaOne refuse le ticket : HTTP 400 »** : le message de NinjaOne indique le champ en cause, par exemple un champ
  rendu obligatoire dans le formulaire choisi.
- **Lien du ticket incorrect** : ouvrir le ticket par son numéro dans la console.
