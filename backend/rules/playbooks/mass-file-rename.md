# Renommages de fichiers en masse / rançongiciel sur un partage

**Agir vite** : chaque minute, des centaines de fichiers supplémentaires peuvent être chiffrés.

## Vérifier (2 minutes maximum)
1. Ouvrir un des fichiers cités dans les événements : nouvelle extension inconnue, contenu illisible, fichier
   « LISEZ-MOI » ou « README » apparu dans les dossiers ? → rançongiciel.
2. Appeler l'utilisateur : déplace-t-il ou archive-t-il volontairement un dossier ?

## Agir
1. **Isoler le poste de l'utilisateur** depuis l'EDR (HarfangLab ou Bitdefender) ; à défaut, le débrancher du
   réseau.
2. **Désactiver le compte** de l'utilisateur dans l'AD et fermer ses sessions sur le serveur de fichiers
   (Gestion de l'ordinateur › Dossiers partagés › Sessions).
3. Si plusieurs postes sont concernés : couper l'accès aux partages (arrêt du service Serveur sur le serveur de
   fichiers) le temps d'identifier la source.
4. Ne pas éteindre le serveur ; prévenir le CERT-FR / l'ANSSI et votre assureur ; restaurer depuis les
   sauvegardes (clichés instantanés, sauvegardes hors ligne) une fois la source neutralisée.
