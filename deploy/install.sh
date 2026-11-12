#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Ce script demande les droits administrateur. Une demande de mot de passe sudo va apparaître."
  exec sudo sh "$0" "$@"
fi

BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP=/opt/admin-ubuntu
CONF=/etc/admin-ubuntu
SERVICE_USER=adminubuntu
STEP=0

step() { STEP=$((STEP + 1)); echo "[$STEP/7] $1"; }
fail() { echo "Installation interrompue à l’étape $STEP. Consultez le message précédent puis relancez : bash install.sh" >&2; exit 1; }
trap 'fail' HUP INT TERM

if [ ! -f /etc/os-release ] || ! . /etc/os-release || [ "${ID:-}" != ubuntu ]; then
  echo "Cette installation est prévue pour Ubuntu." >&2
  exit 1
fi

step "Vérification des dépendances Docker"
if ! command -v apt-get >/dev/null 2>&1; then echo "apt-get est introuvable." >&2; exit 1; fi
NEED_PACKAGES=""
command -v python3 >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES python3"
command -v openssl >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES openssl"
command -v sudo >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES sudo"
command -v visudo >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES sudo"
if command -v python3 >/dev/null 2>&1; then
  VENV_PROBE=$(mktemp -d)
  if ! python3 -m venv "$VENV_PROBE/probe" >/dev/null 2>&1; then NEED_PACKAGES="$NEED_PACKAGES python3-venv"; fi
  rm -rf "$VENV_PROBE"
else
  NEED_PACKAGES="$NEED_PACKAGES python3-venv"
fi
if ! command -v docker >/dev/null 2>&1; then
  NEED_PACKAGES="$NEED_PACKAGES docker.io docker-compose-v2"
elif ! docker compose version >/dev/null 2>&1; then
  NEED_PACKAGES="$NEED_PACKAGES docker-compose-v2"
fi
if [ -n "$NEED_PACKAGES" ]; then
  echo "Installation des composants nécessaires :$NEED_PACKAGES"
  apt-get update
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y $NEED_PACKAGES
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 est requis. Installez le paquet Ubuntu docker-compose-v2 puis relancez." >&2
  exit 1
fi

for file in app.py requirements.txt Dockerfile compose.yaml .dockerignore static/index.html static/app.js static/style.css deploy/admin-ubuntu-helper deploy/host-agent.py deploy/host-agent.service deploy/host-requirements.txt; do
  [ -f "$BASE/$file" ] || { echo "Fichier manquant : $BASE/$file" >&2; exit 1; }
done

step "Préparation du compte et des dossiers"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g "$SERVICE_USER" -m 0750 "$APP" "$CONF"

step "Copie des fichiers et dépendances de l’agent hôte"
cp "$BASE/app.py" "$BASE/requirements.txt" "$BASE/Dockerfile" "$BASE/compose.yaml" "$BASE/.dockerignore" "$APP/"
cp -R "$BASE/static" "$BASE/deploy" "$APP/"
chown -R root:"$SERVICE_USER" "$APP"
find "$APP" -type d -exec chmod 0750 {} \;
find "$APP" -path "$APP/.venv" -prune -o -type f -exec chmod 0640 {} \;
if [ ! -x "$APP/.venv/bin/pip" ]; then
  echo "Création/réparation de l’environnement Python de l’agent…"
  python3 -m venv --clear "$APP/.venv"
fi
"$APP/.venv/bin/pip" install --disable-pip-version-check -r "$APP/deploy/host-requirements.txt"

step "Configuration de l’agent Ubuntu sur l’hôte"
install -o root -g root -m 0755 "$APP/deploy/admin-ubuntu-helper" /usr/local/sbin/admin-ubuntu-helper
install -o root -g root -m 0644 "$APP/deploy/host-agent.service" /etc/systemd/system/admin-ubuntu-agent.service
if [ -f /etc/systemd/system/admin-ubuntu.service ]; then
  systemctl disable --now admin-ubuntu.service >/dev/null 2>&1 || true
fi
# The previous design granted the web user passwordless sudo. The Docker web
# container now talks only to the allowlisted host-agent socket.
rm -f /etc/sudoers.d/admin-ubuntu

step "Création du secret et du certificat HTTPS"
if [ ! -s "$CONF/app.env" ]; then
  printf 'ADMIN_UBUNTU_SECRET=%s\n' "$(openssl rand -hex 32)" > "$CONF/app.env"
fi
APP_UID=$(id -u "$SERVICE_USER")
APP_GID=$(id -g "$SERVICE_USER")
if grep -q '^ADMIN_UID=' "$CONF/app.env"; then sed -i "s/^ADMIN_UID=.*/ADMIN_UID=$APP_UID/" "$CONF/app.env"; else printf 'ADMIN_UID=%s\n' "$APP_UID" >> "$CONF/app.env"; fi
if grep -q '^ADMIN_GID=' "$CONF/app.env"; then sed -i "s/^ADMIN_GID=.*/ADMIN_GID=$APP_GID/" "$CONF/app.env"; else printf 'ADMIN_GID=%s\n' "$APP_GID" >> "$CONF/app.env"; fi
if grep -q '^ADMIN_UBUNTU_BIND=' "$CONF/app.env"; then :; else printf 'ADMIN_UBUNTU_BIND=0.0.0.0\n' >> "$CONF/app.env"; fi
chown root:root "$CONF/app.env"
chmod 0600 "$CONF/app.env"
if [ ! -s "$CONF/tls.crt" ] || [ ! -s "$CONF/tls.key" ]; then
  HOST=$(hostname -f 2>/dev/null || hostname)
  SAN="DNS:$HOST,DNS:localhost,IP:127.0.0.1"
  for ADDRESS in $(hostname -I 2>/dev/null || true); do SAN="$SAN,IP:$ADDRESS"; done
  openssl req -x509 -nodes -newkey rsa:3072 -days 365 -keyout "$CONF/tls.key" -out "$CONF/tls.crt" \
    -subj "/CN=$HOST" -addext "subjectAltName=$SAN"
  chmod 0640 "$CONF/tls.key"
  chmod 0644 "$CONF/tls.crt"
fi
chown root:"$SERVICE_USER" "$CONF/tls.key" "$CONF/tls.crt"
chmod 0640 "$CONF/tls.key"
chmod 0644 "$CONF/tls.crt"

step "Démarrage de Docker et de l’agent hôte"
systemctl enable --now docker
systemctl daemon-reload
systemctl enable admin-ubuntu-agent.service
if ! systemctl restart admin-ubuntu-agent.service; then
  systemctl --no-pager --full status admin-ubuntu-agent.service || true
  journalctl -u admin-ubuntu-agent.service -n 30 --no-pager || true
  fail
fi
i=0
while [ ! -S /run/admin-ubuntu/agent.sock ] && [ "$i" -lt 20 ]; do
  sleep 1
  i=$((i + 1))
done
if [ ! -S /run/admin-ubuntu/agent.sock ]; then
  systemctl --no-pager --full status admin-ubuntu-agent.service || true
  journalctl -u admin-ubuntu-agent.service -n 30 --no-pager || true
  fail
fi

step "Construction et démarrage de l’application Docker"
if ! docker compose --project-name admin-ubuntu --env-file "$CONF/app.env" -f "$APP/compose.yaml" up -d --build --force-recreate; then
  docker compose --project-name admin-ubuntu --env-file "$CONF/app.env" -f "$APP/compose.yaml" logs --tail 40 || true
  fail
fi

echo ""
echo "Installation Docker terminée."
HOST=$(hostname -f 2>/dev/null || hostname)
ADDRESSES=$(hostname -I 2>/dev/null || true)
echo "Depuis ce serveur : https://localhost:8443"
echo "Depuis un autre appareil : https://$HOST:8443 ou https://<IP-du-serveur>:8443"
[ -z "$ADDRESSES" ] || echo "Adresses IP détectées : $ADDRESSES"
echo "Confirmez l’exception du certificat auto-signé dans le navigateur."
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  echo "UFW est actif. N’ouvrez le port 8443 qu’à votre réseau de confiance : sudo ufw allow from ADRESSE_DU_RESEAU to any port 8443 proto tcp"
fi
echo "Journaux web : sudo docker compose --project-name admin-ubuntu --env-file $CONF/app.env -f $APP/compose.yaml logs -f"
echo "Journaux agent hôte : sudo journalctl -u admin-ubuntu-agent -f"
