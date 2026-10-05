# Compte Microsoft 365 / Entra ID suspect

## Vérifier
1. **Appeler l'utilisateur** (pas par courriel : sa messagerie est peut-être lue) : est-il en déplacement à
   l'étranger, utilise-t-il un VPN personnel, a-t-il validé une demande MFA sans l'avoir demandée ?
2. Centre d'administration Entra › Utilisateurs › le compte › **Journaux de connexion** (7 jours sans licence P1) :
   pays, applications, appareils, autres connexions réussies.
3. Outlook web › Paramètres › Courrier › **Règles** et **Transfert** : règle inconnue (déplacement vers « Archive »
   ou « RSS », transfert vers une adresse externe) ?

## Agir (compte compromis)
1. **Révoquer les sessions** (Entra › utilisateur › Révoquer les sessions) et **changer le mot de passe**.
2. Vérifier les méthodes MFA enregistrées et supprimer un téléphone ou une application inconnus.
3. Supprimer les règles de transfert et les applications consenties suspectes (Entra › Applications d'entreprise).
4. Prévenir les correspondants si des courriels frauduleux ont pu partir (fraude au RIB) ; rechercher les messages
   envoyés depuis le compte pendant la période.
5. Déclarer l'incident (CNIL sous 72 h si des données personnelles ont été exposées).
