# Protection WAF affaiblie (OGO)

## Vérifier
1. Qui a fait le changement et quand : journal d'activité OGO (lien « Ouvrir dans OGO »), Recherche :
   `module=ogo host.name=<site>`.
2. Intervention prévue (mise en production, diagnostic avec le prestataire) ? Demander à la personne concernée.
3. Site injoignable ou DNS en erreur : l'enregistrement DNS du site pointe-t-il toujours vers OGO ? Sinon le
   trafic arrive directement sur le serveur, sans filtrage.

## Agir
1. Changement non prévu : remettre la protection (désactiver passthrough ou audit), retirer l'utilisateur invité
   ou rétablir son rôle ; changer le mot de passe et régénérer la clé d'API du compte OGO à l'origine.
2. Intervention légitime : fixer avec le demandeur la date de retour à la protection normale ; vérifier
   ensuite qu'une alerte « protection rétablie » est arrivée (événement `site_state`).
3. DNS : corriger l'enregistrement (CNAME ou adresse du cluster OGO) ; vérifier que le serveur d'origine
   n'accepte que les adresses d'OGO (liste « IP sortantes des clusters » dans OGO).
