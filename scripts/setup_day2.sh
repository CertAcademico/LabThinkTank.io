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

# Grupos 5 y 6 abiertos para estudiantes aún no registrados (eligen grupo al registrarse)
for N in 5 6; do
  ID=$(curl -s "${H[@]}" "$API/admin/teams" | python3 -c "import sys,json;print(next((t['id'] for t in json.load(sys.stdin) if t['name']=='Grupo $N'),''))")
  if [ -z "$ID" ]; then
    ID=$(curl -sf "${H[@]}" -X POST "$API/admin/teams" -d "{\"name\":\"Grupo $N\",\"open_signup\":true}" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")
  else
    curl -sf "${H[@]}" -X PATCH "$API/admin/teams/$ID/open-signup" -d '{"open":true}' >/dev/null
  fi
  echo "Grupo $N -> team_id $ID (registro abierto)"
done
# Asigna retos a los grupos nuevos (los que ya tenían, se conservan)
curl -sf "${H[@]}" -X POST "$API/admin/ctf-phases/$PHASE2/assign-random" -d '{"per_team":3}'; echo
