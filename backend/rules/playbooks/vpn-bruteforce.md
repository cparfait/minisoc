# Échecs de connexion VPN répétés

Commencer par la **qualification automatique** en haut de l'alerte : elle distingue une attaque d'un
utilisateur légitime en difficulté.

## Si « Erreur d'utilisateur probable »
Cas typiques : mot de passe expiré, ancien mot de passe enregistré sur le téléphone ou le client VPN,
compte verrouillé, fautes de frappe.
1. Contacter l'utilisateur ; lui faire mettre à jour le mot de passe enregistré sur tous ses appareils.
2. Déverrouiller ou réinitialiser le compte si nécessaire.
3. Clôturer l'alerte en « Faux positif » avec un commentaire. Si le cas se répète (ex. compte de service),
   créer une exception justifiée avec une date d'expiration.

## Si « Attaque probable » ou « À vérifier »
1. Les comptes visés existent-ils ? Si oui, l'attaquant connaît des identifiants valides.
2. Chercher une connexion réussie pour ces comptes ou ces IP (règles UC-03a / UC-03b, page Événements).
3. Activer sur le Sophos XGS la protection contre la force brute des connexions utilisateurs
   (blocage après N échecs pendant M minutes).
4. Restreindre l'accès VPN aux pays nécessaires (règle de pare-feu avec objets géographiques).
5. Imposer le MFA (OTP) sur le VPN SSL et le portail utilisateur.
6. Si l'attaque vient de peu d'IP : les bloquer sur le XGS.
7. Désactiver le portail utilisateur sur l'interface WAN s'il n'est pas indispensable.

## Adresse source « 127.0.0.1 »
Sur les versions récentes de SFOS, le portail VPN est servi par un relais interne du pare-feu : ses journaux
d'authentification indiquent 127.0.0.1 au lieu de l'adresse de l'attaquant. Conséquences :
- la règle UC-51 (nombre de comptes différents en échec) prend le relais de UC-01 ;
- le blocage automatique « par adresse IP » du XGS est inefficace sur ce portail (il bloquerait 127.0.0.1) ;
- mesures efficaces : retirer le portail VPN de la zone WAN (Administration › Accès à l'appareil) s'il n'est pas
  indispensable, sinon le limiter aux pays utiles, et imposer le MFA ; vérifier les comptes AD visés.

## Prévenir
- Responsable informatique si un compte a été compromis.
