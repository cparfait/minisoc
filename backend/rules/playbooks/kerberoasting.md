# Kerberoasting

Un compte authentifié demande des tickets de service chiffrés en RC4 pour plusieurs comptes de service, afin de
casser leur mot de passe hors ligne. Aucune élévation n'est visible à ce stade : c'est la préparation.

## Vérifier
1. Quel poste (adresse IP des événements) et quel compte ont fait les demandes ? Un poste utilisateur est très
   suspect ; un serveur applicatif ancien qui ne parle que RC4 peut être légitime (le confirmer et l'exclure).
2. L'EDR signale-t-il un outil d'attaque (Rubeus, Impacket, PowerView) sur ce poste ?

## Agir
1. Isoler le poste depuis l'EDR, désactiver le compte demandeur s'il est compromis.
2. Changer en priorité le mot de passe des comptes de service visés (mots de passe longs, 25 caractères et plus),
   en commençant par ceux qui ont des droits élevés.
3. À terme : comptes de service gérés (gMSA), AES imposé sur les comptes de service, suppression des SPN inutiles.
