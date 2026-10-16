# Attaque web en cours (OGO)

## Vérifier
1. Tableau de bord OGO (lien « Ouvrir dans OGO ») › site concerné : volume bloqué, catégories d'attaques
   (injection, scan, robots), pays et adresses d'origine, pages visées.
2. Le site répond-il normalement ? Temps de réponse et erreurs 5xx du serveur d'origine (journal OGO, supervision).
3. Les adresses à l'origine apparaissent-elles ailleurs (Recherche : `source.ip=<ip>`) : VPN, Microsoft 365,
   pare-feu ? Une même adresse qui attaque le site et tente des connexions signe une campagne ciblée.

## Agir
1. Attaque bloquée, site disponible : rien à faire de plus que surveiller ; clôturer en « attaque » pour la
   statistique.
2. Déni de service qui dégrade le site : contacter le support OGO (limitation de débit, géoblocage temporaire).
3. Page visée vulnérable (formulaire, extranet, ancienne application) : prévenir l'éditeur ou le prestataire,
   appliquer le correctif ; en attendant, règle de blocage du chemin dans OGO.
4. Adresse également vue sur le VPN ou Microsoft 365 : la bloquer sur le pare-feu (page Blocages).
