#!/usr/bin/env bash
# Exportiert die UniFi-Konfiguration in ein (privates!) Git-Repo und committet Änderungen.
#
# Alle Pfade sind Defaults und per Umgebungsvariable überschreibbar:
#   SNAPSHOT_REPO     Arbeitskopie des Snapshot-Repos     (/var/lib/unifi-snapshot/repo)
#   SNAPSHOT_SUBDIR   Unterordner für den Export im Repo  (state)
#   UNIFI_ENV_FILE    Datei mit UNIFI_HOST, UNIFI_API_KEY (/etc/unifi-snapshot/env)
#   UNIFI_SNAPSHOT    Aufruf des Exporters                (unifi-snapshot)
#   SNAPSHOT_PUSH     pull vor und push nach dem Commit   (true)
#   SNAPSHOT_LOCK     Lock-Datei für flock, leer = ohne   (leer)
#
# Alles steht in main(), damit bash das Skript komplett einliest, bevor
# "git pull" es möglicherweise während der Ausführung ersetzt.
set -euo pipefail

main() {
  local repo_dir subdir env_file exporter push lock changed details

  repo_dir="${SNAPSHOT_REPO:-/var/lib/unifi-snapshot/repo}"
  subdir="${SNAPSHOT_SUBDIR:-state}"
  env_file="${UNIFI_ENV_FILE:-/etc/unifi-snapshot/env}"
  exporter="${UNIFI_SNAPSHOT:-unifi-snapshot}"
  push="${SNAPSHOT_PUSH:-true}"
  lock="${SNAPSHOT_LOCK:-}"

  if [ -n "$lock" ]; then
    exec 9>"$lock"
    flock 9
  fi

  if [ -f "$env_file" ]; then
    set -a; . "$env_file"; set +a
  fi

  cd "$repo_dir"

  if [ "$push" = "true" ]; then
    git pull --ff-only --quiet
  fi

  # Bewusst ohne Anführungszeichen, damit z. B. "python3 -m unifi_snapshot" möglich ist
  $exporter export --out "$subdir"

  git add -A -- "$subdir"
  if git diff --cached --quiet; then
    echo "Keine Änderungen."
    return 0
  fi

  changed=$(git diff --cached --name-only | wc -l | tr -d ' ')
  # sed statt head: head beendet die Pipe vorzeitig, git bekommt SIGPIPE und
  # pipefail bricht das Skript dann stillschweigend ab
  details=$(git diff --cached --name-status -- "$subdir" | sed -n '1,40p')

  git -c user.name="${GIT_AUTHOR_NAME:-unifi-snapshot}" \
      -c user.email="${GIT_AUTHOR_EMAIL:-unifi-snapshot@localhost}" \
      commit --quiet -m "snapshot: ${changed} Datei(en) geändert" -m "$details"

  if [ "$push" = "true" ]; then
    git push --quiet
  fi
  echo "Snapshot committet (${changed} Datei(en))."
}

main "$@"
exit $?
