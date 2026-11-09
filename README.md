# Admin Ubuntu

Interface web auto-hébergée pour administrer un serveur Ubuntu. Le projet démarre par un tableau de bord système et une API locale ; les fonctions qui exécutent des commandes administrateur doivent rester limitées et auditées.

## Démarrage du prototype

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8080
```

Ouvrir `http://127.0.0.1:8080`. Le serveur écoute uniquement sur la boucle locale par défaut. Pour un accès distant, placez-le derrière un proxy HTTPS avec authentification et pare-feu correctement configurés.

## État

Le tableau de bord et les mesures système sont fonctionnels. L’authentification Linux, le terminal interactif, la gestion des comptes et les opérations de paquets nécessitent une configuration PAM et des règles sudo dédiées avant exposition réseau ; aucune commande privilégiée n’est activée par défaut.
# cockpit-ca-pu
