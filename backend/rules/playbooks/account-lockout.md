# Compte verrouillé

## Vérifier
1. **D'où viennent les échecs ?** Le poste indiqué dans l'alerte (champ « Poste » des événements de verrouillage)
   est celui qui a envoyé les mauvais mots de passe au contrôleur de domaine.
2. **Cause banale ?** Mot de passe changé récemment et resté mémorisé sur : un téléphone (messagerie), un lecteur
   réseau, une session Windows restée ouverte sur un autre poste, une tâche planifiée ou un service (compte de
   service), un partage d'imprimante ou de scanner.
3. **Attaque ?** Échecs venant d'un poste que l'utilisateur n'utilise pas, d'une adresse VPN, ou plusieurs comptes
   verrouillés depuis la même source (règles UC-14 et UC-21).

## Agir
1. Cause banale : corriger le mot de passe mémorisé sur l'appareil, puis déverrouiller le compte.
2. Compte de service : mettre à jour le mot de passe partout où il est utilisé **avant** de déverrouiller, sinon
   il se reverrouille aussitôt.
3. Attaque : ne pas déverrouiller tout de suite ; isoler le poste source depuis l'EDR, faire changer le mot de
   passe, vérifier qu'aucune connexion n'a réussi depuis cette source.
