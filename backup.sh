#!/usr/bin/env bash
# Dumps the database and uploaded files to backup/<timestamp>/ and prunes old ones.
# Backups hold every document: keep them off public repos and copy them off this machine.
set -euo pipefail
cd "$(dirname "$0")"

KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
DIR="backup/$(date +%Y-%m-%d_%H%M%S)"
mkdir -p "$DIR"

docker compose exec -T postgres pg_dump -U outline outline | gzip > "$DIR/outline_db.sql.gz"
docker compose exec -T outline tar -C /var/lib/outline/data -cf - . | gzip > "$DIR/outline_files.tar.gz"

find backup -mindepth 1 -maxdepth 1 -type d -mtime +"$KEEP_DAYS" -exec rm -rf {} +
echo "Backup written to $DIR"
