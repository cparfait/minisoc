# Chaîne d'attaque

En 24 heures, une même machine ou un même compte a enchaîné au moins trois étapes différentes d'une attaque
(tactiques MITRE ATT&CK), dont une étape avancée. Un incident a été ouvert automatiquement : c'est la situation la
plus grave que le Mini-SOC sait reconnaître.

1. **Ouvrir l'incident** et lire les étapes dans l'ordre (elles y sont rattachées).
2. **Contenir sans attendre** : isoler le poste (EDR) ; désactiver ou réinitialiser le compte ; bloquer les adresses
   externes en cause (pare-feu).
3. **Préserver les traces** : ne pas éteindre ni réinstaller la machine avant la collecte (mémoire, journaux).
4. **Mesurer l'étendue** (page Recherche) : `user.name=<compte> | count by host.name` et
   `host.name=<machine> | count by user.name` ; d'autres machines sont-elles touchées ?
5. **Alerter** : direction, puis CERT-FR / ANSSI selon la procédure de gestion de crise (et le délai de
   notification NIS2 si la collectivité est concernée).
