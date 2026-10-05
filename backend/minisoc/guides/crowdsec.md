# CrowdSec : décisions de bannissement (API locale)

Le Mini-SOC lit les décisions de votre CrowdSec comme un « bouncer » en lecture seule :
- les détections de vos serveurs deviennent des événements ;
- toutes les IP bannies (y compris la liste communautaire si vous l'activez) enrichissent chaque événement :
  une connexion **réussie** depuis une IP bannie déclenche la règle UC-18.

## Prérequis
- Un agent CrowdSec avec son API locale (LAPI), par défaut sur le port **8080**.
- Le Mini-SOC doit joindre cette API. Par défaut, la LAPI n'écoute que localement (`127.0.0.1`).

## Étapes
1. Sur le serveur CrowdSec, si le Mini-SOC est sur une autre machine, ouvrir la LAPI au réseau interne dans
   `/etc/crowdsec/config.yaml` :

```
api:
  server:
    listen_uri: 0.0.0.0:8080
```

   puis `sudo systemctl restart crowdsec`, et n'autoriser que l'adresse du Mini-SOC ({{MINISOC_HOST}}) sur le port
   8080 (pare-feu du serveur).
2. Créer la clé du Mini-SOC :

```
sudo cscli bouncers add minisoc
```

   Copier la clé affichée (elle ne sera plus visible).
3. Dans cette fenêtre (onglet Configuration) :
   - **API locale (LAPI)** : `http://ADRESSE_DU_SERVEUR_CROWDSEC:8080` ;
   - **Clé de bouncer** : la clé copiée ;
   - **Inclure la liste communautaire** : cochée pour enrichir aussi avec les IP bannies par la communauté
     CrowdSec.
4. **Enregistrer**, puis **Tester**.

## Vérifier
- Sur le serveur CrowdSec : `sudo cscli bouncers list` montre « minisoc » avec une date de dernière requête.
- Mini-SOC › **Intégrations** : la fiche passe à « En service » ; les IP bannies apparaissent avec le badge « banni »
  dans les événements.

## Dépannage
- **HTTP 403** : clé erronée ou bouncer supprimé (`cscli bouncers list`).
- **Connexion refusée** : la LAPI n'écoute que sur 127.0.0.1, ou le pare-feu du serveur bloque le 8080.
