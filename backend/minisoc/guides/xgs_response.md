# Blocage d'IP sur le Sophos XGS (réponse)

Depuis une alerte, un analyste peut **bloquer une ou plusieurs adresses IP** sur le pare-feu pour une durée choisie
(levée automatique ensuite). Le Mini-SOC ajoute les adresses à un groupe d'hôtes du XGS ; ce groupe est bloqué par
une règle de pare-feu et par une exception d'accès aux services du pare-feu (VPN).

> Désactivé par défaut. Commencez par l'essai **en lecture seule** (bouton « Lire les règles ») avec un compte
> d'API en lecture seule, interrupteur de blocage désactivé.

## Prérequis
- Le Mini-SOC doit joindre l'interface d'administration du XGS (port **4444** par défaut).
- Un compte administrateur du XGS pour créer le compte d'API et les objets.

## Étapes
1. **API** : *Sauvegarde et microprogramme › API* (Backup & firmware › API) : activer la **configuration de
   l'API** et n'ajouter comme **adresse IP autorisée** que celle du Mini-SOC.
2. **Compte d'API** : *Administration › Paramètres de l'appareil* / *Profils d'administration* : créer un profil
   donnant l'écriture sur les **Objets** (hôtes et groupes) et la lecture sur les **Règles** ; créer l'administrateur
   `minisoc-api` avec ce profil et un mot de passe long. (Pour l'essai : profil en lecture seule.)
3. **Groupe d'hôtes** : *Hôtes et services › Groupe d'hôtes IP* › Ajouter `MiniSOC-Blocages` (vide).
4. **Règle de pare-feu** en tête de liste : *Règles et stratégies › Règles de pare-feu* › Ajouter : réseaux source
   = `MiniSOC-Blocages`, toutes zones et destinations, action **Abandonner**, journalisation activée.
5. **Exception ACL de service local** (indispensable : le VPN est hébergé par le pare-feu lui-même, la règle de
   pare-feu ne le protège pas) : *Administration › Accès à l'appareil › Règle d'exception ACL de service local* ›
   Ajouter : zone source WAN, réseau source `MiniSOC-Blocages`, services **VPN SSL, portail VPN, IPsec, portail
   utilisateur**, action **Abandonner**.
6. Dans cette fenêtre (onglet Configuration) : « Adresse de l'API » `https://ADRESSE_DU_XGS:4444`, compte et mot
   de passe d'API, certificat (décocher « Vérifier le certificat du pare-feu » si le XGS a son certificat
   auto-signé d'origine), groupe d'hôtes, durée par défaut, et les **Adresses jamais bloquables** (vos IP
   publiques, celles des prestataires).
7. **Tester**, puis **Lire les règles** (lecture seule) ; activer l'interrupteur de blocage seulement ensuite.

## Vérifier
- Bloquer une adresse de test (ex. une IP de documentation `203.0.113.10`) depuis la page **Blocages** : elle
  apparaît dans le groupe `MiniSOC-Blocages` du XGS, puis disparaît à l'échéance.

## Dépannage
- **« Authentification échouée »** : compte d'API, mot de passe, ou IP du Mini-SOC absente des IP autorisées de
  l'API.
- **Le VPN reste accessible à une IP bloquée** : l'exception ACL de service local (étape 5) manque.
