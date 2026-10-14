# Vulnérabilités signalées par Cyberwatch

## Vérifier
1. Ouvrir l'actif dans Cyberwatch (bouton de la console) : liste des CVE, correctifs disponibles, priorisation.
2. Faille du catalogue KEV : elle est exploitée activement. Le service vulnérable est-il exposé à Internet ou
   joignable depuis les postes ? Le classement « Machines à corriger en premier » donne le contexte (alertes
   ouvertes, criticité, exposition).
3. Chercher des traces d'exploitation : alertes EDR ou IPS sur la machine, page Recherche (`host.name:<machine>`).

## Agir
1. Appliquer le correctif indiqué par Cyberwatch (ou par NinjaOne pour les mises à jour Windows) ; redémarrer si
   Cyberwatch signale un redémarrage requis.
2. Correction impossible à court terme : mesure de contournement (filtrage sur le pare-feu, désactivation du
   service, retrait d'Internet) et suivi dans un incident.
3. Risque accepté en connaissance de cause : ignorer la CVE dans Cyberwatch avec un commentaire.
4. Système en fin de support : planifier la mise à niveau ; en attendant, isoler la machine du reste du réseau.

Le Mini-SOC ne modifie rien dans Cyberwatch. Il clôture son alerte au relevé suivant (30 minutes au plus) dès que
les CVE signalées ne sont plus présentes (corrigées ou ignorées dans Cyberwatch) ou que le système a été mis à
niveau, en gardant la trace dans l'historique.
