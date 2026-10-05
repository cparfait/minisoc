# Leurres (« honeytokens ») : la détection sans faux positif

Un leurre est un élément **qu'aucun usage légitime ne touche** : compte jamais utilisé, dossier piège, machine sans
rôle, faux mot de passe laissé en évidence. Toute activité qui le concerne est donc le fait d'un attaquant (ou d'un
logiciel malveillant) en train d'explorer le réseau. Le Mini-SOC crée alors une alerte **critique** (UC-45),
notifiée immédiatement.

C'est la mesure au meilleur rapport efficacité / coût : une heure de mise en place, aucun bruit.

> Toutes les commandes ci-dessous se lancent **par un administrateur de l'AD**, sur un contrôleur de domaine ou un
> poste d'administration (module ActiveDirectory). Adaptez les noms (`mairie.local`, OU) à votre annuaire.
> Puis renseignez les leurres dans **Paramètres › Détection** du Mini-SOC.

## 1. Compte leurre « administrateur » (le plus utile)

Les attaquants listent les comptes de l'annuaire dès leur arrivée et essaient en priorité ceux qui semblent
puissants ou dont la description contient un mot de passe.

```powershell
# Mot de passe réel long et aléatoire (jamais utilisé, jamais noté)
$secret = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | ForEach-Object { [char]$_ })
New-ADUser -Name "adm-sauvegarde" -SamAccountName "adm-sauvegarde" `
  -Path "OU=Comptes de service,DC=mairie,DC=local" `
  -AccountPassword (ConvertTo-SecureString $secret -AsPlainText -Force) -Enabled $true `
  -Description "Compte sauvegarde Veeam - mdp : Sauvegarde2024!"   # faux mot de passe : l'appât
# Appât pour le « kerberoasting » : un SPN (nom de service) rend le compte visible des outils d'attaque
Set-ADUser "adm-sauvegarde" -ServicePrincipalNames @{Add = "MSSQLSvc/srv-sauvegarde.mairie.local:1433"}
```

- Le faux mot de passe de la description (`Sauvegarde2024!`) ne fonctionne pas : toute tentative est un échec de
  connexion (événement 4625 / 4771) **sur un compte leurre**, donc une alerte.
- Toute demande de ticket Kerberos pour ce SPN (événement 4769) révèle un « kerberoasting ».
- Ne l'ajoutez à **aucun groupe** ; vérifiez qu'il n'a aucun droit.

Dans le Mini-SOC : **Leurres : comptes jamais utilisés** = `adm-sauvegarde`, et **Leurres : chaînes secrètes** =
`Sauvegarde2024!` (son apparition dans un journal prouve qu'elle a été trouvée).

## 2. Dossier piège sur le serveur de fichiers

```powershell
New-Item -ItemType Directory "D:\Partages\Commun\Paie_2026"
# Quelques fichiers attirants mais sans contenu réel
"Fichier de démonstration" | Out-File "D:\Partages\Commun\Paie_2026\Salaires_2026.xlsx"
"Fichier de démonstration" | Out-File "D:\Partages\Commun\Paie_2026\Mots de passe.txt"
```

Puis, sur le dossier `Paie_2026` : *Propriétés › Sécurité › Avancé › Audit* › Ajouter `Tout le monde`, type
**Succès**, accès **Lecture**, appliqué à ce dossier, sous-dossiers et fichiers. (L'audit « Système de fichiers »
doit être activé par GPO sur le serveur, comme pour la détection des rançongiciels.)

Dans le Mini-SOC : **Leurres : dossiers ou fichiers pièges** = `Paie_2026`.

> Prévenez les personnes qui ont accès au partage commun qu'un dossier « de test » existe et ne doit pas être
> ouvert — ou placez-le là où personne n'a de raison d'aller.

## 3. Machine leurre (facultatif)

Une adresse IP libre ou une ancienne machine sans rôle (ex. `PC-LEURRE`, `10.0.0.99`) : toute connexion vers elle
(pare-feu interne, journaux Windows) révèle un balayage du réseau.

Dans le Mini-SOC : **Leurres : machines sans usage** = `PC-LEURRE, 10.0.0.99`.

## 4. Vérifier

1. Depuis un poste de test, tenter une connexion avec `adm-sauvegarde` et un mauvais mot de passe (`runas
   /user:MAIRIE\adm-sauvegarde cmd`, puis annuler).
2. Une alerte **« Leurre touché : compte leurre : adm-sauvegarde »** doit apparaître en moins d'une minute (journaux
   Windows raccordés).
3. La clôturer en indiquant « test de la DSI ».

## À ne pas faire

- Ne jamais utiliser un leurre pour un usage réel, même ponctuel.
- Ne pas désactiver le compte leurre : les tentatives sur un compte désactivé sont moins visibles.
- Ne pas communiquer la liste des leurres en dehors de la DSI.
