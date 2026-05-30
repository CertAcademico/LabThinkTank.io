#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

COMPOSE="${COMPOSE:-docker compose}"

usage() {
  cat <<'EOF'
CTI-Lab starter

Usage:
  ./start.sh              Build/update and start backend, frontend and Cloudflare tunnel
  ./start.sh --no-build   Start services without rebuilding local images
  ./start.sh --restart    Restart running services
  ./start.sh --status     Show container status
  ./start.sh --logs       Follow logs for backend, frontend and cloudflared

Environment:
  CLOUDFLARE_TUNNEL_TOKEN must be present in .env for the named tunnel.
  VITE_API_URL defaults to http://localhost:8000 if not set.
EOF
}

require_docker() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running or is not reachable." >&2
    exit 1
  fi
}

show_status() {
  $COMPOSE ps backend frontend cloudflared
}

update_tunnel() {
  echo "Updating Cloudflare tunnel image..."
  $COMPOSE pull cloudflared
}

start_services() {
  local build_flag="${1:-build}"

  update_tunnel

  if [[ "$build_flag" == "build" ]]; then
    echo "Building and starting backend/frontend..."
    $COMPOSE up -d --build backend frontend
  else
    echo "Starting backend/frontend without build..."
    $COMPOSE up -d backend frontend
  fi

  echo "Refreshing Cloudflare tunnel..."
  $COMPOSE up -d --force-recreate cloudflared

  echo
  show_status
}

restart_services() {
  echo "Restarting backend/frontend/cloudflared..."
  $COMPOSE restart backend frontend cloudflared
  echo
  show_status
}

main() {
  require_docker

  case "${1:-}" in
    -h|--help)
      usage
      ;;
    --status)
      show_status
      ;;
    --logs)
      $COMPOSE logs -f backend frontend cloudflared
      ;;
    --no-build)
      start_services "no-build"
      ;;
    --restart)
      restart_services
      ;;
    "")
      start_services "build"
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
}

main "$@"
