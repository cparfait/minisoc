# Source silencieuse

Une source qui se tait peut être une panne… ou un attaquant qui a coupé la journalisation.

## Vérifier
1. L'équipement ou la console est-il joignable ?
2. Syslog : la configuration d'envoi vers le Mini-SOC est-elle toujours active ?
3. API : le jeton a-t-il expiré ou été révoqué ? (journaux du conteneur `worker`)

## Agir
1. Rétablir l'envoi des journaux.
2. Si la coupure est inexpliquée : vérifier le journal d'administration de l'équipement.
