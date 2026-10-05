# Hôte ou compte critique pour Vectra

## Vérifier
1. Ouvrir l'entité dans la console Vectra (lien « Ouvrir dans Vectra ») : quelles détections ont fait monter les
   scores, depuis quand, vers quelles destinations ?
2. Croiser avec l'EDR (HarfangLab, Bitdefender) sur le même poste : processus suspect, alerte récente ?
3. Pour un compte : connexions récentes (page Comptes AD, Microsoft 365), postes utilisés, heures inhabituelles.

## Agir
1. Commande et contrôle ou exfiltration confirmés : isoler le poste depuis l'EDR, bloquer les destinations sur le
   pare-feu (page Blocages).
2. Compte suspect : réinitialiser le mot de passe, révoquer les sessions, vérifier les droits ajoutés.
3. Ouvrir un incident pour suivre l'enquête ; marquer la détection comme traitée (« triage ») dans Vectra.
