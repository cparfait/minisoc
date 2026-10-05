# Compte administrateur ou compte de service

## Vérifier
1. **Qui ?** Contacter le titulaire du compte administrateur (ou le responsable de l'application pour un compte de
   service) : l'action est-elle de son fait, à cette heure, depuis ce poste ?
2. **D'où ?** Le poste ou l'adresse IP est-il un poste d'administration habituel ? Un compte de service ne doit
   jamais ouvrir de session au clavier ou en bureau à distance.
3. **Quoi d'autre ?** Page Comptes AD : connexions et échecs récents du compte, autres alertes sur le même poste.

## Agir
1. Doute sérieux : désactiver le compte (ou changer son mot de passe deux fois de suite pour un compte de service,
   après avoir prévenu le responsable de l'application), isoler le poste source depuis l'EDR.
2. Rechercher ce que le compte a fait depuis : ouvertures de session, ajouts à des groupes (UC-12), services
   installés, journaux effacés (UC-13).
3. Bonnes pratiques à terme : comptes d'administration distincts des comptes bureautiques, comptes de service
   gérés (gMSA) à mot de passe automatique, interdiction d'ouverture de session interactive par GPO.
