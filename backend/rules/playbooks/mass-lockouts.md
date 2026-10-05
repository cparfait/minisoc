# Verrouillages en masse / pulvérisation de mots de passe

## Vérifier
1. D'où viennent les échecs ? (adresse IP ou poste indiqué dans l'alerte et les événements)
2. Est-ce un service mal configuré après un changement de mot de passe (compte de service) ? Dans ce cas, un seul
   compte est concerné, pas des dizaines.

## Agir
1. Isoler le poste source depuis l'EDR si c'est un poste interne ; bloquer l'IP si elle vient du VPN.
2. Rechercher une connexion réussie depuis cette source (règles UC-03, UC-18).
3. Déverrouiller les comptes après avoir neutralisé la source, et faire changer les mots de passe faibles.
