# Vulnérabilités critiques non corrigées

## Vérifier
1. Ouvrir l'appareil dans NinjaOne : correctifs Windows et mises à jour de logiciels en attente ou en échec.
2. L'appareil est-il un serveur ou exposé à Internet (site web, VPN, accès distant) ? Priorité absolue.
3. Page Veille : une des vulnérabilités concernées est-elle dans le catalogue des vulnérabilités activement
   exploitées (CISA KEV) ou dans une alerte récente du CERT-FR ?

## Agir
1. Approuver et déployer les correctifs depuis NinjaOne ; redémarrer si nécessaire.
2. Correctifs en échec : analyser le journal de l'agent NinjaOne sur le poste.
3. Correction impossible à court terme sur un serveur exposé : mesure de contournement (filtrage sur le pare-feu,
   désactivation du service vulnérable) et suivi dans un incident.
