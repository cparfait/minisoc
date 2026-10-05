# Ajout à un groupe à privilèges

## Vérifier
1. L'auteur du changement (indiqué dans l'alerte) l'a-t-il fait volontairement ? L'appeler.
2. Le compte ajouté est-il connu, nominatif, et a-t-il réellement besoin de ce droit ?

## Agir si l'ajout n'est pas légitime
1. Retirer immédiatement le compte du groupe.
2. Désactiver le compte ajouté et le compte auteur, réinitialiser leurs mots de passe.
3. Rechercher l'activité de ces comptes (page Événements, EDR) : connexions, créations de comptes, GPO modifiées.
4. Traiter comme un incident majeur : un attaquant avec des droits d'administration du domaine contrôle tout le SI.
