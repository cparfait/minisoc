# IOC trouvé dans les journaux

Un indicateur publié comme malveillant (CERT-FR, éditeur, liste externe ou saisie de la DSI) apparaît dans vos
journaux. Une correspondance ancienne compte autant qu'une récente : l'attaquant peut être installé depuis.

## Qualifier

1. **Quel indicateur, quelle source ?** Lire la fiche de l'IOC (page IOC) : bulletin d'origine, date, contexte.
2. **Quel sens ?** Une IP malveillante en **source** d'un flux bloqué par le pare-feu (scan entrant) est du bruit
   habituel. En **destination** d'un flux sortant accepté, ou dans une connexion VPN réussie, c'est grave.
3. **Quelles machines, quels comptes ?** Ouvrir les événements liés : première et dernière apparition, volume.
4. **Rechercher plus large** (page Recherche) : `ip=<adresse> | count by host.name, event.action` ou
   `"<domaine>" | timeline`.

## Si la correspondance est réelle

- Isoler le poste concerné (EDR) et collecter les éléments avant toute remise en état.
- Bloquer l'indicateur sur le pare-feu (Mini-SOC : Blocages) et dans l'EDR.
- Réinitialiser les mots de passe des comptes vus sur la machine.
- Ouvrir un incident et prévenir le CERT-FR (cert-fr.cossi@ssi.gouv.fr) si la compromission est confirmée.

## Si c'est du bruit

Qualifier en faux positif ; si l'IOC est trop générique (hébergeur partagé, CDN), le retirer de la liste.
