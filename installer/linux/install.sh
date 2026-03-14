#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Lithium"
APP_ID="lithium.messenger"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_BIN_DIR="${SCRIPT_DIR}/bin"

APP_DIR="${HOME}/.local/opt/Lithium"
BIN_DIR="${APP_DIR}/bin"
APPLICATIONS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_DIR="${HOME}/Desktop"

resolve_lithiumd_data_dir() {
    if [[ -n "${XDG_DATA_HOME:-}" ]]; then
        printf '%s\n' "${XDG_DATA_HOME}/lithiumd"
    elif [[ -n "${HOME:-}" ]]; then
        printf '%s\n' "${HOME}/.local/share/lithiumd"
    else
        printf '%s\n' "./lithiumd-data"
    fi
}

DATA_DIR="$(resolve_lithiumd_data_dir)"

if [[ ! -f "${SRC_BIN_DIR}/lithiumg" ]]; then
    echo "Missing ${SRC_BIN_DIR}/lithiumg"
    exit 1
fi

if [[ ! -f "${SRC_BIN_DIR}/lithiumd" ]]; then
    echo "Missing ${SRC_BIN_DIR}/lithiumd"
    exit 1
fi

mkdir -p "${BIN_DIR}"
mkdir -p "${APPLICATIONS_DIR}"
mkdir -p "${DATA_DIR}"

install -m 755 "${SRC_BIN_DIR}/lithiumg" "${BIN_DIR}/lithiumg"
install -m 755 "${SRC_BIN_DIR}/lithiumd" "${BIN_DIR}/lithiumd"

DESKTOP_FILE="${APPLICATIONS_DIR}/${APP_ID}.desktop"
cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Lithium
Exec=${BIN_DIR}/lithiumg
Terminal=false
Categories=Network;Utility;
StartupNotify=true
EOF

chmod 644 "${DESKTOP_FILE}"

if [[ -d "${DESKTOP_DIR}" ]]; then
    cp "${DESKTOP_FILE}" "${DESKTOP_DIR}/Lithium.desktop"
    chmod +x "${DESKTOP_DIR}/Lithium.desktop" || true
    if command -v gio >/dev/null 2>&1; then
        gio set "${DESKTOP_DIR}/Lithium.desktop" metadata::trusted true >/dev/null 2>&1 || true
    fi
fi

cat > "${APP_DIR}/uninstall.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${HOME}/.local/opt/Lithium"
APPLICATIONS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_FILE="${APPLICATIONS_DIR}/xyz.gilbertz.lithium.desktop"
DESKTOP_SHORTCUT="${HOME}/Desktop/Lithium.desktop"

resolve_lithiumd_data_dir() {
    if [[ -n "${XDG_DATA_HOME:-}" ]]; then
        printf '%s\n' "${XDG_DATA_HOME}/lithiumd"
    elif [[ -n "${HOME:-}" ]]; then
        printf '%s\n' "${HOME}/.local/share/lithiumd"
    else
        printf '%s\n' "./lithiumd-data"
    fi
}

DATA_DIR="$(resolve_lithiumd_data_dir)"

echo "Uninstalling Lithium..."
rm -f "${DESKTOP_FILE}"
rm -f "${DESKTOP_SHORTCUT}"
rm -rf "${APP_DIR}"

echo
echo "Do you also want to clear user data?"
echo "This removes any possibility to ever login to the account."
echo
echo "This WILL delete keys, account state, configuration, and local data stored in:"
echo "  ${DATA_DIR}"
printf "Type 'yes' to clear user data, anything else to keep it: "
read -r REPLY

if [[ "${REPLY}" == "yes" ]]; then
    rm -rf "${DATA_DIR}"
    echo "User data removed."
else
    echo "User data kept."
fi

echo "Done."
EOF

chmod +x "${APP_DIR}/uninstall.sh"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${APPLICATIONS_DIR}" >/dev/null 2>&1 || true
fi

echo
echo "Installed ${APP_NAME}"
echo "Binaries: ${BIN_DIR}"
echo "Menu entry: ${DESKTOP_FILE}"
if [[ -d "${DESKTOP_DIR}" ]]; then
    echo "Desktop shortcut: ${DESKTOP_DIR}/Lithium.desktop"
fi
echo "User data dir: ${DATA_DIR}"
echo "Uninstaller: ${APP_DIR}/uninstall.sh"