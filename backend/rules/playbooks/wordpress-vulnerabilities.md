# Composant WordPress vulnérable

## Vérifier
1. Page **Vulnérabilités**, cadre « Sites WordPress » : le site, le composant, la version installée, la version
   qui corrige et la faille (lien CVE quand elle en a une).
2. Le composant est-il **actif** ? Une extension désactivée reste attaquable si ses fichiers sont appelés
   directement : la supprimer plutôt que la laisser désactivée.
3. Chercher des traces d'exploitation : alertes OGO (WAF) sur le site, comptes administrateurs WordPress récents
   ou inconnus (Utilisateurs), fichiers PHP récents dans `wp-content/uploads`.

## Agir
1. **Sauvegarde** du site (fichiers et base) ou instantané chez l'hébergeur.
2. Tableau de bord WordPress › **Mises à jour** : mettre à jour le composant (ou WordPress lui-même), puis vérifier
   l'affichage du site. Extension payante : version à télécharger chez son éditeur.
3. Pas encore de correctif : désactiver et supprimer l'extension si elle n'est pas indispensable, sinon règle de
   protection sur le WAF (OGO) et suivi dans un incident.
4. Intégrations › WordPress › **Analyser maintenant** : l'inventaire suivant confirme la correction.

Une faille de type XSS « authentifiée » (réservée aux contributeurs connectés) pèse moins qu'une faille
exploitable sans compte (injection SQL, téléversement de fichier, élévation de privilèges) : la description
WPScan l'indique.
