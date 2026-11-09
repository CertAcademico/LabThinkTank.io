#!/usr/bin/env bash
# Uso: API=https://tu-backend TOKEN=<jwt admin> ./scripts/setup_day2.sh
# Día 2: colores, dificultad/puntos nivelados, 3 retos al azar por grupo,
# aviso de las 8 pm (hoy) y apertura automática del Día 3 el miércoles.
set -euo pipefail
: "${API:?define API}"; : "${TOKEN:?define TOKEN}"
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
PHASE2=${PHASE2:-2}; PHASE3=${PHASE3:-3}

curl -sf "${H[@]}" -X PATCH "$API/admin/ctf-phases/$PHASE2" -d '{"status":"active"}'; echo
curl -sf "${H[@]}" -X POST  "$API/admin/ctf-phases/$PHASE2/balance" -d '{"points":150}'; echo
curl -sf "${H[@]}" -X POST  "$API/admin/ctf-phases/$PHASE2/assign-random" -d '{"per_team":3}'; echo
curl -sf "${H[@]}" -X POST  "$API/admin/announcements" -d '{
  "title": "Día 2 habilitado — retos por equipo",
  "body": "Abran su perfil: cada grupo tiene 3 retos asignados al azar (Red, Blue, White o Purple). Tienen hasta el miércoles 11 de noviembre para resolverlos; ese día se habilita el Día 3. Revisen el Scoreboard para ver el puntaje de su equipo.",
  "publish_at": "2026-11-09T20:00:00-05:00",
  "expires_at": "2026-11-11T08:00:00-05:00"}'; echo
curl -sf "${H[@]}" -X PATCH "$API/admin/ctf-phases/$PHASE3" -d '{"opens_at":"2026-11-11T08:00:00-05:00"}'; echo
