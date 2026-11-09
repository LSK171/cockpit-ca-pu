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

step() { STEP=$((STEP + 1)); echo "[$STEP/6] $1"; }
fail() { echo "\nInstallation interrompue à l’étape $STEP. Corrigez le problème ci-dessus puis relancez : bash install.sh" >&2; exit 1; }
trap 'fail' HUP INT TERM

if [ ! -f /etc/os-release ] || ! . /etc/os-release || [ "${ID:-}" != ubuntu ]; then
  echo "Cette installation est prévue pour Ubuntu." >&2
  exit 1
fi

step "Vérification des dépendances"
if ! command -v apt-get >/dev/null 2>&1; then echo "apt-get est introuvable." >&2; exit 1; fi
NEED_PACKAGES=""
command -v python3 >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES python3"
command -v openssl >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES openssl"
command -v sudo >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES sudo"
command -v visudo >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES sudo"
python3 -m venv --help >/dev/null 2>&1 || NEED_PACKAGES="$NEED_PACKAGES python3-venv"
if [ -n "$NEED_PACKAGES" ]; then
  echo "Installation des composants Ubuntu nécessaires :$NEED_PACKAGES"
  apt-get update
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y $NEED_PACKAGES
fi
for file in app.py requirements.txt static/index.html static/app.js static/style.css deploy/admin-ubuntu-helper deploy/admin-ubuntu.service; do
  [ -f "$BASE/$file" ] || { echo "Fichier manquant : $BASE/$file" >&2; exit 1; }
done

step "Création du compte de service"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/admin-ubuntu --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o root -g "$SERVICE_USER" -m 0750 "$APP" "$CONF"

step "Installation de l’application"
cp -R "$BASE/app.py" "$BASE/requirements.txt" "$BASE/static" "$APP/"
chown -R root:"$SERVICE_USER" "$APP"
find "$APP" -type d -exec chmod 0750 {} \;
find "$APP" -path "$APP/.venv" -prune -o -type f -exec chmod 0640 {} \;
if [ ! -x "$APP/.venv/bin/pip" ]; then
  echo "Réparation de l’environnement Python…"
  python3 -m venv --clear "$APP/.venv"
fi
"$APP/.venv/bin/pip" install --disable-pip-version-check -r "$APP/requirements.txt"

step "Configuration des opérations système"
install -o root -g root -m 0755 "$BASE/deploy/admin-ubuntu-helper" /usr/local/sbin/admin-ubuntu-helper
SUDOERS_TMP=$(mktemp)
printf '%s\n' 'adminubuntu ALL=(root) NOPASSWD: /usr/local/sbin/admin-ubuntu-helper' > "$SUDOERS_TMP"
chmod 0440 "$SUDOERS_TMP"
visudo -cf "$SUDOERS_TMP"
install -o root -g root -m 0440 "$SUDOERS_TMP" /etc/sudoers.d/admin-ubuntu
rm -f "$SUDOERS_TMP"

step "Création du certificat HTTPS"
if [ ! -s "$CONF/app.env" ]; then
  SECRET=$(openssl rand -hex 32)
  printf 'ADMIN_UBUNTU_SECRET=%s\n' "$SECRET" > "$CONF/app.env"
  chown root:"$SERVICE_USER" "$CONF/app.env"
  chmod 0640 "$CONF/app.env"
fi
if [ ! -s "$CONF/tls.crt" ] || [ ! -s "$CONF/tls.key" ]; then
  HOST=$(hostname -f 2>/dev/null || hostname)
  SAN="DNS:$HOST,DNS:localhost,IP:127.0.0.1"
  for ADDRESS in $(hostname -I 2>/dev/null || true); do SAN="$SAN,IP:$ADDRESS"; done
  openssl req -x509 -nodes -newkey rsa:3072 -days 365 -keyout "$CONF/tls.key" -out "$CONF/tls.crt" \
    -subj "/CN=$HOST" -addext "subjectAltName=$SAN"
  chown root:"$SERVICE_USER" "$CONF/tls.key" "$CONF/tls.crt"
  chmod 0640 "$CONF/tls.key"
  chmod 0644 "$CONF/tls.crt"
fi

step "Activation du service"
install -o root -g root -m 0644 "$BASE/deploy/admin-ubuntu.service" /etc/systemd/system/admin-ubuntu.service
systemctl daemon-reload
systemctl enable admin-ubuntu.service
if ! systemctl restart admin-ubuntu.service; then
  systemctl --no-pager --full status admin-ubuntu.service || true
  journalctl -u admin-ubuntu.service -n 30 --no-pager || true
  fail
fi

echo ""
echo "Installation terminée."
HOST=$(hostname -f 2>/dev/null || hostname)
ADDRESSES=$(hostname -I 2>/dev/null || true)
echo "Depuis ce serveur : https://localhost:8443"
echo "Depuis un autre appareil, ouvrez https://$HOST:8443 ou https://<IP-du-serveur>:8443"
[ -z "$ADDRESSES" ] || echo "Adresses IP détectées : $ADDRESSES"
echo "Le navigateur signalera le certificat auto-signé : confirmez l’exception pour continuer."
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
  echo "Le pare-feu UFW est actif. Pour permettre l’accès depuis votre réseau, lancez : sudo ufw allow from ADRESSE_DU_RESEAU to any port 8443 proto tcp"
fi
echo "Comptes Linux du groupe sudo : accès aux fonctions d’administration."
echo "Pour l’état du service : sudo systemctl status admin-ubuntu"
