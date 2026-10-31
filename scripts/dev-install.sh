#!/usr/bin/env bash
# Build local de Mugshot (fork perso) : build autonome signé avec le certificat local
# persistant, paquet non notarisé, installation et publication GitHub.
#
# Usage :
#   scripts/dev-install.sh               construit le paquet et l'installe (sudo installer)
#   scripts/dev-install.sh build         construit le paquet seulement
#   scripts/dev-install.sh release X.Y.Z construit puis publie build/Mugshot-X.Y.Z.pkg
#                                        sur la release vX.Y.Z du dépôt `origin`
#
# Les mises à jour automatiques (Sparkle) sont coupées : elles remplaceraient ce build
# par la version officielle et réinitialiseraient les autorisations macOS.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
MODE="${1:-install}"
APP="$HERE/dist/Mugshot.app"

if [ "$MODE" = "release" ]; then
  VERSION="${2:?usage: dev-install.sh release X.Y.Z}"
  export MARKETING_VERSION="$VERSION"
fi
# Sparkle compare ce nombre ; il reste monotone sans dépendre de la version affichée.
export BUILD_VERSION="${BUILD_VERSION:-$(date +%y%m%d%H%M)}"
export MUGSHOT_UPDATE_CHECKS="${MUGSHOT_UPDATE_CHECKS:-false}"

bash scripts/build-standalone.sh
VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
PKG="build/Mugshot-$VERSION.pkg"
mkdir -p build
ALLOW_UNSIGNED_PKG=1 bash scripts/build-pkg.sh "$APP" "$PKG"
codesign --verify --deep --strict "$APP"
python3 tests/test_signing_identity.py

case "$MODE" in
  build) echo "Paquet prêt : $PKG" ;;
  install)
    osascript -e 'tell application "Mugshot" to quit' 2>/dev/null || true
    sudo installer -pkg "$PKG" -target /
    open -a Mugshot
    ;;
  release)
    gh release create "v$VERSION" "$PKG" --repo "$(git remote get-url origin)" \
      --title "Mugshot $VERSION (perso)" \
      --notes "Build local non notarisé, mises à jour automatiques désactivées. Sur un autre Mac : retirer la quarantaine (\`xattr -d com.apple.quarantine Mugshot-$VERSION.pkg\`) puis \`sudo installer -pkg Mugshot-$VERSION.pkg -target /\`."
    ;;
  *) echo "mode inconnu : $MODE" >&2; exit 1 ;;
esac
