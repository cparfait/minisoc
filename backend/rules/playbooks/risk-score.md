# Risque cumulé élevé

Plusieurs détections s'accumulent sur la même machine ou le même compte. Séparément, elles pouvaient sembler
anodines ; ensemble, elles dessinent souvent une intrusion en cours.

1. **Ouvrir la fiche de la machine ou du compte** (lien dans l'alerte) : détections qui composent le score,
   tactiques MITRE couvertes, activité sur 30 jours.
2. **Lire les détections dans l'ordre chronologique** : y a-t-il une logique (connexion inhabituelle, puis script,
   puis persistance) ? Une suite cohérente est grave, même si chaque alerte n'est que « moyenne ».
3. **Vérifier le contexte** : propriétaire de la machine, intervention prévue (déploiement, maintenance, audit) ?
4. **Si le doute persiste** : isoler le poste (EDR), réinitialiser le mot de passe du compte, ouvrir un incident.
5. **Si c'est légitime** : qualifier les détections en faux positif, ou leur donner une fiche (hygiène,
   information) dans Alertes › Par détection : le score baisse d'autant.
