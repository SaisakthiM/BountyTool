#!/usr/bin/env bash
#
# Install the external scanners BountyTool drives.
#
#   ./scripts/install-deps.sh              # core + recommended (the useful set)
#   ./scripts/install-deps.sh core         # bare minimum: nuclei, subfinder, httpx
#   ./scripts/install-deps.sh heavy        # everything, including nmap/sqlmap
#   ./scripts/install-deps.sh --dry-run    # print the commands, run nothing
#
# Arch has no official package for the ProjectDiscovery suite, so repo packages
# and AUR packages are installed by different tools. `bountytool doctor
# --install` does the same thing from inside the binary; this script exists for
# the bootstrap case where the binary is not built yet.

set -euo pipefail

GROUP="${1:-recommended}"
DRY_RUN=0

for arg in "$@"; do
  case "$arg" in
    --dry-run | -n) DRY_RUN=1 ;;
    --help | -h)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
  esac
done
if [[ "$GROUP" == --* ]]; then
  GROUP="recommended"
fi

if ! command -v pacman >/dev/null 2>&1; then
  echo "error: this script targets Arch Linux (pacman not found)" >&2
  exit 1
fi

run() {
  if ((DRY_RUN)); then
    echo "would run: $*"
  else
    echo "+ $*"
    "$@"
  fi
}

# Prefer the binary's own registry so the lists can never drift apart.
if command -v bountytool >/dev/null 2>&1; then
  echo "==> using the package list from \`bountytool doctor\`"
  if ((DRY_RUN)); then
    bountytool doctor --install --group "$GROUP" --dry-run
  else
    bountytool doctor --install --group "$GROUP"
  fi
  exit $?
fi

echo "==> bountytool is not installed; using the built-in package list"

REPO_PACKAGES=(gobuster sqlmap nmap findomain)
AUR_CORE=(nuclei subfinder httpx)
AUR_RECOMMENDED=(katana-bin ffuf-bin dalfox naabu interactsh-client seclists)

case "$GROUP" in
  core) AUR_PACKAGES=("${AUR_CORE[@]}") ;;
  recommended) AUR_PACKAGES=("${AUR_CORE[@]}" "${AUR_RECOMMENDED[@]}") ;;
  heavy | all) AUR_PACKAGES=("${AUR_CORE[@]}" "${AUR_RECOMMENDED[@]}") ;;
  *)
    echo "error: unknown group '$GROUP' (use core, recommended or heavy)" >&2
    exit 1
    ;;
esac

run sudo pacman -S --needed --noconfirm "${REPO_PACKAGES[@]}"

if ! command -v yay >/dev/null 2>&1; then
  echo
  echo "warning: yay is not installed and the ProjectDiscovery tools live in the AUR." >&2
  echo "         install an AUR helper first, or build them from source:" >&2
  echo "         https://github.com/projectdiscovery/nuclei" >&2
  exit 1
fi

run yay -S --needed --noconfirm "${AUR_PACKAGES[@]}"

if ((!DRY_RUN)); then
  echo "==> fetching nuclei templates (first run downloads them)"
  nuclei -update-templates -silent || true
fi

echo
echo "done. verify with: bountytool doctor"
