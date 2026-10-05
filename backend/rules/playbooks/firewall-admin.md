# Accès à l'administration du pare-feu depuis l'extérieur

## Vérifier
1. La console d'administration (WebAdmin, SSH) est-elle exposée sur l'interface WAN ?
   (Administration > Device access)
2. La connexion a-t-elle réussi ? Si oui, traiter comme une compromission.

## Agir
1. Retirer l'accès d'administration depuis la zone WAN ; ne l'autoriser que depuis le LAN
   d'administration ou le VPN.
2. Si connexion réussie : changer tous les mots de passe administrateurs, vérifier les changements
   de configuration récents (journal Admin), activer le MFA administrateur.
