# OGO Security (WAF) — à venir

Objectif : recevoir les attaques web bloquées, les bots et les IP bannies sur les sites protégés par OGO (UC-17).

## Pour finaliser ce connecteur
1. Vérifier avec OGO les possibilités d'export de votre offre : **syslog** (idéalement CEF) ou **API**.
2. Si le syslog est disponible : envoyer vers **{{MINISOC_HOST}}**, port **514/TCP** ; les messages CEF sont
   déjà analysés (règle NATIVE) en attendant un analyseur dédié.
3. Si seule une API existe : fournir sa documentation et un exemple de réponse.
