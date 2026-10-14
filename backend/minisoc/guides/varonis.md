# Varonis : alertes des modèles de menace

## Varonis SaaS (lecture par l'API)

Le Mini-SOC **interroge** l'API de votre instance (`https://<tenant>.varonis.io`) chaque minute, en HTTPS sortant :
il n'est jamais joignable depuis Internet, et le relais Varonis interne n'est pas sollicité.

Ce qui est remonté :
- les **alertes** des modèles de menace : accès anormaux aux données, Active Directory (force brute,
  kerberoasting, groupes à privilèges…), rançongiciel (règle UC-06, critique) ; compte, machine, données touchées,
  tactique MITRE (chaînes d'attaque et score de risque) ; lien direct vers l'alerte dans Varonis ;
- le **délai** entre l'activité et l'alerte, indiqué dans chaque alerte (« alerte reçue 42 min après
  l'activité ») : en SaaS, les événements sont collectés par lots puis analysés dans le cloud, et certains modèles
  comportementaux ne concluent qu'après une période d'observation ;
- la **clôture** : une alerte fermée dans Varonis est clôturée dans le Mini-SOC avec une trace (motif « Benign » ou
  « Authorized activity » : faux positif). L'état « en investigation » est aussi affiché.

Le Mini-SOC ne fait que des recherches : il ne change aucun statut et n'ajoute aucune note dans Varonis.

### Étapes
1. Console Varonis › **Configuration › API Keys** › **New API Key** : rôle **Threat Detection Integrator**.
   Copier la clé (affichée une seule fois).
2. Dans cette fenêtre (onglet Configuration) : adresse de l'instance (`https://<tenant>.varonis.io`) et clé.
   **Enregistrer**, puis **Tester** : le test lit les alertes arrivées ces dernières 24 heures.
3. Au premier relevé, les alertes arrivées depuis 7 jours sont reprises.

### Vérifier
- Mini-SOC › **Événements**, source Varonis : les alertes apparaissent avec le délai mesuré.
- Mini-SOC › **Alertes** : règle NATIVE (sévérité moyenne et plus) ou UC-06 pour un rançongiciel.

## Varonis installé sur site (syslog CEF)

1. Console Varonis › **DatAlert › Configuration › Méthodes d'alerte** › **Syslog** : serveur **{{MINISOC_HOST}}**,
   port **514**, **TCP**, format **CEF**.
2. Sur les règles d'alerte à transmettre (sévérité moyenne et plus, toutes les règles « rançongiciel »), cocher la
   méthode **Syslog**.

## Dépannage
- **« clé d'API Varonis refusée »** : clé révoquée, ou rôle « Threat Detection Integrator » absent.
- **« résultats de recherche non prêts »** : Varonis calcule encore la recherche ; nouvel essai à la minute suivante.
- **Syslog : événements « Syslog générique »** : le format choisi n'est pas CEF.
