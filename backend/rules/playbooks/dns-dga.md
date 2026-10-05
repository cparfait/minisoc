# Domaine généré par algorithme (DGA)

Certains logiciels malveillants calculent chaque jour des noms de domaine imprononçables pour retrouver leur serveur
de commande. Un poste vient d'en demander un.

1. **Le domaine a-t-il répondu ?** Des échecs (NXDOMAIN) répétés sur des noms semblables : le logiciel cherche son
   serveur. Un succès : il l'a peut-être trouvé.
2. **D'autres postes demandent-ils des noms semblables ?** Page Recherche : `threat.name=dga_suspect | count by
   source.ip`.
3. **Faux positif fréquent** : services cloud et CDN aux noms techniques ; les ajouter aux domaines de confiance.
4. **Si suspect** : analyse du poste par l'EDR, isolement si confirmé, domaine ajouté aux IOC.
