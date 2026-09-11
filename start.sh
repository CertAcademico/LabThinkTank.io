#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

COMPOSE="${COMPOSE:-docker compose}"

# Servicio de tunnel activo en docker-compose.yml.
# Named tunnel (por defecto): URL estable, usa CLOUDFLARE_TUNNEL_TOKEN del .env.
# Quick Tunnel: exporta TUNNEL_SVC=cloudflared-quick y descomenta ese servicio.
TUNNEL_SVC="${TUNNEL_SVC:-cloudflared}"

usage() {
  cat <<'EOF'
CTI-Lab starter

Usage:
  ./start.sh              Build/update and start backend, frontend and the Cloudflare tunnel
  ./start.sh --no-build   Start services without rebuilding local images
  ./start.sh --restart    Restart running services
  ./start.sh --status     Show container status
  ./start.sh --url        Print the current public tunnel URL
  ./start.sh --logs       Follow logs for backend, frontend and the tunnel

Environment:
  TUNNEL_SVC              Tunnel compose service (default: cloudflared = named).
                          Set to cloudflared-quick for a throwaway Quick Tunnel.
  VITE_API_URL            Defaults to /api (same-origin through nginx).
  CLOUDFLARE_TUNNEL_TOKEN Required for the named tunnel (from Zero Trust dashboard).
EOF
}

require_docker() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker is not running or is not reachable." >&2
    exit 1
  fi
}

show_status() {
  $COMPOSE ps backend frontend "$TUNNEL_SVC"
}

update_tunnel() {
  echo "Updating Cloudflare tunnel image..."
  $COMPOSE pull "$TUNNEL_SVC"
}

# Muestra la URL pública del lab.
#  - Quick Tunnel: la extrae de los logs y la persiste en .env (TUNNEL_URL).
#  - Named tunnel: el hostname lo define el dashboard; usa TUNNEL_URL del .env.
show_tunnel_url() {
  if [[ "$TUNNEL_SVC" != "cloudflared-quick" ]]; then
    local named=""
    [[ -f .env ]] && named="$(grep -E '^TUNNEL_URL=' .env | cut -d= -f2- || true)"
    echo
    echo "──────────────────────────────────────────────────────────────"
    if [[ -n "$named" ]]; then
      echo "  URL pública del lab:  $named"
    else
      echo "  Named tunnel activo. El hostname se configura en Zero Trust →"
      echo "  Networks → Tunnels → (tu túnel) → Public Hostname → http://frontend:80"
      echo "  Ponlo en TUNNEL_URL del .env para verlo aquí."
    fi
    echo "──────────────────────────────────────────────────────────────"
    return 0
  fi

  local url="" tries=0
  while [[ -z "$url" && $tries -lt 30 ]]; do
    url="$($COMPOSE logs "$TUNNEL_SVC" 2>/dev/null \
            | grep -Eo 'https://[a-z0-9.-]+\.trycloudflare\.com' | tail -1 || true)"
    [[ -n "$url" ]] && break
    tries=$((tries + 1))
    sleep 2
  done

  if [[ -z "$url" ]]; then
    echo "No pude leer la URL del tunnel todavía. Prueba: $COMPOSE logs $TUNNEL_SVC" >&2
    return 1
  fi

  echo
  echo "──────────────────────────────────────────────────────────────"
  echo "  URL pública del lab:  $url"
  echo "──────────────────────────────────────────────────────────────"

  # Persistir en .env para referencia (no afecta al build, VITE_API_URL=/api).
  if [[ -f .env ]]; then
    if grep -q '^TUNNEL_URL=' .env; then
      local tmp; tmp="$(mktemp)"
      sed "s#^TUNNEL_URL=.*#TUNNEL_URL=$url#" .env >"$tmp" && mv "$tmp" .env
    else
      printf '\nTUNNEL_URL=%s\n' "$url" >>.env
    fi
  fi
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
  $COMPOSE up -d --force-recreate "$TUNNEL_SVC"

  echo
  show_status
  show_tunnel_url || true
}

restart_services() {
  echo "Restarting backend/frontend/$TUNNEL_SVC..."
  $COMPOSE restart backend frontend "$TUNNEL_SVC"
  echo
  show_status
  show_tunnel_url || true
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
    --url)
      show_tunnel_url
      ;;
    --logs)
      $COMPOSE logs -f backend frontend "$TUNNEL_SVC"
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
