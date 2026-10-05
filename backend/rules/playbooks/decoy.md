# Leurre touché

Un élément qu'aucun usage légitime ne touche (compte leurre, dossier piège, machine leurre, faux mot de passe) a été
utilisé. **Sauf manipulation par la DSI elle-même, c'est un attaquant ou un logiciel malveillant qui explore le
réseau.** Il n'y a pas de faux positif possible : traiter immédiatement.

1. **Identifier l'origine** : adresse IP source et machine de l'événement (fiche de l'alerte, événements liés).
2. **Isoler cette machine** (EDR) et réinitialiser les comptes qui y sont connectés.
3. **Chercher ce qui a précédé** (page Recherche) : `ip=<adresse source>` sur 7 jours ; découverte de l'annuaire
   (PingCastle, BloodHound), lecture de partages, tentatives de connexion.
4. **Ouvrir un incident** et prévenir la direction.
5. Si le leurre a été touché par la DSI (test, inventaire) : le noter dans l'alerte, puis la clôturer.
