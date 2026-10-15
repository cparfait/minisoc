# Machine sans antivirus ou sans EDR

## Vérifier
1. La raison est dans le titre : absente de la console, « découverte » sans agent, ou agent muet depuis N jours.
2. La machine est-elle bien en service ? Dernier contact dans NinjaOne, sessions récentes (Recherche, champ
   host.name). Une machine retirée du parc mais encore déclarée dans NinjaOne doit y être supprimée.
3. Le nom est-il le même dans les consoles ? Une machine renommée apparaît sous l'ancien nom dans une console et
   sous le nouveau dans l'autre : vérifier dans GravityZone et HarfangLab par l'adresse IP.
4. Agent HarfangLab muet : service arrêté, désinstallé, bloqué par un autre produit, ou poste hors réseau longtemps.

## Agir
1. Déployer l'agent manquant (GravityZone : tâche d'installation à distance ou paquet ; HarfangLab : politique de
   déploiement) ou le réparer.
2. Agent désinstallé sans demande de la DSI sur un poste en activité : traiter comme suspect (alertes récentes de
   l'autre outil, sessions ouvertes), isoler le poste si un doute persiste.
3. Machine volontairement non équipée (appliance, système non pris en charge) : déclarer une exception sur la règle
   (champ host.name), avec la raison.

L'alerte se clôt d'elle-même au passage suivant (chaque heure) quand la machine est de nouveau protégée.
