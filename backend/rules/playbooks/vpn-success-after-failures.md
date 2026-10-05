# Connexion réussie après des échecs répétés

Cas le plus grave des attaques VPN : le mot de passe a peut-être été trouvé.

## Vérifier (immédiatement)
1. Appeler l'utilisateur : est-ce lui qui s'est connecté, à cette heure, depuis ce pays ?
2. Vérifier l'adresse IP source (pays, opérateur) dans la page Événements.

## Agir si ce n'est pas l'utilisateur
1. Couper la session VPN en cours sur le XGS (Monitor & analyze > Live users).
2. Désactiver le compte dans l'AD, réinitialiser son mot de passe.
3. Bloquer l'IP source sur le XGS.
4. Rechercher l'activité de ce compte et de cette IP dans l'EDR et les journaux AD.
5. Déclarer un incident : prévenir la direction, envisager un prestataire de réponse à incident (PRIS)
   et le signalement au CERT-FR.
