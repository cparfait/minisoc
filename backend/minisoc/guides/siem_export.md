# Export vers un SIEM ou un SOC externe

Le Mini-SOC transfère ses **alertes** (créées ou dont la sévérité augmente) et, si vous le choisissez, **tous les
événements normalisés** vers un collecteur syslog : SOC mutualisé, CSIRT régional, prestataire de supervision,
Microsoft Sentinel (via un agent syslog), Splunk, Wazuh, Elastic…

> Désactivé par défaut. Les données quittent alors la collectivité : vérifiez le cadre (convention avec le
> destinataire, registre des traitements RGPD) **avant** d'exporter tous les événements, qui contiennent des noms
> de comptes et des adresses IP.

## Prérequis
- L'adresse et le port du collecteur du destinataire, et son mode de transport (**TLS** de préférence).
- Le flux sortant autorisé sur le pare-feu (VM Mini-SOC → collecteur, port choisi).
- En TLS : le collecteur doit présenter un certificat reconnu (ou décocher la vérification pour un essai).

## Étapes
1. Demander au destinataire : adresse, port, transport (TLS, TCP ou UDP) et format attendu :
   - **JSON** : champs au format ECS (Elastic Common Schema), lisibles par la plupart des SIEM récents ;
   - **CEF** : format historique d'ArcSight, accepté par presque tous les SIEM.
2. Autoriser le flux sortant sur le Sophos XGS (règle : source = IP du Mini-SOC, destination = collecteur).
3. Dans cette fenêtre (onglet Configuration) : adresse, port, transport, format, contenu (alertes seulement ou
   alertes et événements), sévérité minimale des alertes, nom d'émetteur.
4. **Tester** : un message de test part immédiatement ; le faire confirmer par le destinataire.
5. Activer l'intégration.

## Fonctionnement
- Messages syslog RFC 5424 (facilité *local4*), avec le comptage d'octets RFC 6587 en TCP et TLS.
- Une file d'attente bornée (20 000 messages) découple l'export du traitement : une cible lente ou injoignable ne
  ralentit jamais la détection. En cas de coupure prolongée, les messages en surplus sont **perdus et comptés**.
- Chaque alerte exportée contient son lien vers le Mini-SOC, son statut, son entité et sa priorité.

## Vérifier
- Le destinataire voit les messages de test, puis les nouvelles alertes.
- En cas d'échec, la cause (refus de connexion, certificat, délai) s'affiche au test.
