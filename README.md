# Admin Ubuntu

Interface web auto-hébergée pour gérer un serveur Ubuntu. Elle utilise les comptes Linux pour l’authentification, affiche les ressources en temps réel, gère les paquets APT et les comptes locaux, et présente les volumes montés.

## Installation rapide sur Ubuntu

Depuis le dossier du projet, une seule commande :

```sh
bash install.sh
```

Le script demandera le mot de passe `sudo`, installera les dépendances manquantes, configurera le service et affichera l’adresse à ouvrir. Les opérations d’administration sont réservées aux comptes Linux du groupe `sudo`.

À la première ouverture, confirmez l’exception du navigateur pour le certificat auto-signé. HTTPS chiffre bien la connexion, mais ce certificat temporaire ne prouve pas l’identité du serveur. Pour un certificat reconnu par le navigateur, placez les certificats de votre domaine ici : `/etc/admin-ubuntu/tls.crt` et `/etc/admin-ubuntu/tls.key`, puis lancez :

```sh
sudo systemctl restart admin-ubuntu
```

Le service écoute sur toutes les interfaces réseau. Si UFW est actif, le script affiche la commande pour autoriser votre réseau sur le port 8443. Pour vérifier l’état du service ou consulter les erreurs d’installation :

```sh
sudo systemctl status admin-ubuntu
sudo journalctl -u admin-ubuntu -f
```

## Fonctions

- Authentification par PAM avec le compte Linux et cookie de session HTTPOnly, Secure et SameSite Strict.
- Tableau de bord CPU, mémoire, swap, stockage, réseau, charge et durée de fonctionnement, actualisé toutes les deux secondes.
- Recherche des paquets installés, installation et suppression avec APT.
- Consultation des comptes humains, création, suppression et attribution facultative du groupe sudo.
- Mesure de l’occupation des volumes montés.
- HTTPS direct avec certificat TLS configurable.

Le terminal utilise le broker PTY dédié : le shell tourne sous l’UID du compte Linux connecté, et le compte de service web reste non-root. Les touches sont envoyées immédiatement, les raccourcis courants du shell sont transmis, et le PTY suit la taille du panneau. Le rendu reste textuel : les applications plein écran comme `vim` ou `htop` ne sont pas encore prises en charge. Ne lancez pas l’application comme root.

Le helper privilégié est `deploy/admin-ubuntu-helper`. Il n’accepte pas de commande shell : seules les opérations nommées dans le code sont exécutées. Le compte de service peut appeler ce helper via sudo sans mot de passe ; gardez les fichiers de l’application et du helper modifiables uniquement par root.

## Développement local

Pour travailler sur l’interface sans privilèges système, créez un environnement virtuel et lancez Uvicorn sur la boucle locale. L’authentification ne sera disponible qu’après configuration de `ADMIN_UBUNTU_SECRET` et l’installation de `python-pam`; les actions d’administration nécessitent également le helper root configuré par le script d’installation.
# cockpit-ca-pu
