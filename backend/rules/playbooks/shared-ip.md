# Même adresse IP en alerte sur plusieurs outils

## Vérifier
1. La liste des alertes ci-dessus : quels outils, dans quel ordre (site web attaqué puis VPN, échecs Microsoft 365
   puis pare-feu…), quels comptes visés ?
2. Le panneau « Vu par OGO » : l'adresse a-t-elle aussi attaqué les sites web (requêtes bloquées, bannies) ?
3. Recherche : `source.ip=<ip>` sur 7 jours : une connexion **réussie** depuis cette adresse ? Pays et opérateur
   (hébergeur, VPN commercial, Tor) ?

## Agir
1. Bloquer l'adresse sur le pare-feu (bouton « Bloquer sur le pare-feu » de cette alerte), 7 jours au moins.
2. Connexion réussie depuis l'adresse : traiter le compte comme compromis (mot de passe, sessions, double
   authentification), voir la fiche « Connexion réussie après des échecs ».
3. Adresse légitime (prestataire, opérateur partagé) : exception sur la règle UC-61 limitée à cette adresse.
