# Bitdefender GravityZone : réception des événements (Event Push)

GravityZone (cloud) **pousse** ses événements vers le Mini-SOC en HTTPS dès qu'ils se produisent : malware,
rançongiciel, HyperDetect, incidents EDR, attaques réseau, modules désactivés.

## Prérequis
- Le Mini-SOC doit être **joignable depuis Internet**, mais **uniquement** sur le chemin
  `/api/ingest/bitdefender` : publier ce seul chemin via un reverse proxy en DMZ avec un certificat valide
  (Let's Encrypt ou certificat de la collectivité). Ne jamais exposer l'interface du Mini-SOC.
- Clé d'API GravityZone avec le droit **Event Push Service API**.

## Étapes
1. **Jeton de réception** : dans cette fenêtre (onglet Configuration), saisir un jeton long et aléatoire dans
   « Valeur attendue de l'en-tête Authorization » (par exemple 40 caractères générés par un gestionnaire de mots de
   passe), et dans « Plages d'IP autorisées à pousser » les plages d'adresses de Bitdefender (documentation
   Bitdefender « Event Push Service »). Enregistrer.
2. **Clé d'API** : GravityZone › *Mon compte* › **Clés API** › Ajouter : cocher **Event Push Service API**.
   Noter la clé et l'**URL d'accès** affichée (ex. `https://cloud.gravityzone.bitdefender.com/api`).
3. **Déclarer le Mini-SOC** (depuis un poste qui a `curl`) en remplaçant la clé, l'URL d'accès, l'adresse publique et
   le jeton :

```
curl -sS -u "CLE_API:" -H "Content-Type: application/json" \
  https://cloud.gravityzone.bitdefender.com/api/v1.0/jsonrpc/push -d '{
  "jsonrpc": "2.0", "id": "1", "method": "setPushEventSettings",
  "params": {
    "status": 1,
    "serviceType": "jsonRPC",
    "serviceSettings": {
      "url": "https://ADRESSE_PUBLIQUE/api/ingest/bitdefender",
      "requireValidSslCertificate": true,
      "authorization": "JETON_DE_RECEPTION"
    },
    "subscribeToEventTypes": {
      "av": true, "hd": true, "avc": true, "ransomware-mitigation": true, "new-incident": true,
      "network-monitor": true, "aph": true, "modules": true, "uc": true, "exchange-malware": true
    }
  }
}'
```

4. **Test** : même commande avec `"method": "sendTestPushEvent"` et `"params": {"eventType": "av"}`.

## Vérifier
- Mini-SOC › **Événements**, source Bitdefender : l'événement de test apparaît.
- Mini-SOC › **Intégrations** : la fiche passe à « En service ».

## Dépannage
- **Réponse 401** dans le journal du Mini-SOC : le jeton envoyé par GravityZone ne correspond pas à celui saisi ici.
- **Réponse 403** : l'adresse d'émission de Bitdefender n'est pas dans « Plages d'IP autorisées à pousser » (ou le
  reverse proxy ne transmet pas l'adresse d'origine).
- **Aucune requête** : vérifier le certificat (GravityZone refuse un certificat invalide), la publication du reverse
  proxy et `getPushEventSettings` (même commande, méthode `getPushEventSettings`, `"params": {}`).
