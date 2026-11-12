# Admin Ubuntu

Interface web Dockerisée pour administrer un hôte Ubuntu : ressources en direct, paquets APT, comptes Linux et terminal.

## Installation

Sur l’hôte Ubuntu, placez le projet dans un dossier, puis lancez :

```sh
bash install.sh
```

Le script demande `sudo`, installe Docker Engine et Compose si nécessaire, construit l’image, crée le certificat TLS et démarre l’application. Il affiche ensuite l’adresse à ouvrir : `https://adresse-du-serveur:8443`. Le certificat initial est auto-signé ; acceptez l’avertissement du navigateur pour le premier accès. Pour un certificat reconnu, remplacez `/etc/admin-ubuntu/tls.crt` et `/etc/admin-ubuntu/tls.key`, puis relancez `bash install.sh`.

## Architecture

- L’interface FastAPI s’exécute dans le conteneur `admin-ubuntu-web`, sous un UID non-root, avec un système de fichiers en lecture seule et sans capacité Linux ajoutée.
- Un petit agent systemd sur l’hôte gère PAM, les mesures système, APT, les comptes et les PTY. Le conteneur ne voit que son socket Unix `/run/admin-ubuntu/agent.sock`.
- Le conteneur n’utilise pas `/var/run/docker.sock` et ne monte pas la racine de l’hôte.
- Les fonctions d’administration restent réservées aux comptes Linux du groupe `sudo`. Le compte `root` ne peut pas se connecter à l’interface.

## Mise à jour

Depuis le dossier du projet :

```sh
git pull origin main
bash install.sh
```

Le script reconstruit et recrée le conteneur, puis redémarre l’agent hôte.

## Diagnostic

```sh
sudo docker compose --project-name admin-ubuntu --env-file /etc/admin-ubuntu/app.env -f /opt/admin-ubuntu/compose.yaml ps
sudo docker compose --project-name admin-ubuntu --env-file /etc/admin-ubuntu/app.env -f /opt/admin-ubuntu/compose.yaml logs -f
sudo systemctl status admin-ubuntu-agent
sudo journalctl -u admin-ubuntu-agent -f
```

Le service web publie le port 8443 sur les interfaces réseau. Si UFW est actif, autorisez ce port uniquement depuis votre réseau de confiance. Pour vérifier le service Docker : `sudo systemctl status docker`.

## Terminal

Le terminal transmet les touches en direct et redimensionne le PTY. Le rendu reste textuel ; les applications plein écran comme `vim` ou `htop` ne sont pas prises en charge.
