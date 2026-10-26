# ---------------------------------------------------------------------------
# LF27 · servicio de salas (relay) — imagen lista para cualquier host con Docker
#   docker build -f server/Dockerfile -t lf27-salas .
#   docker run -p 8099:8099 -e PUBLIC_URL=wss://salas.tudominio.com lf27-salas
# El contenedor NO lleva TLS: pon delante un proxy con certificado (Fly, Render,
# Railway, Caddy, nginx, Cloudflare…) y publica en WSS.
# ---------------------------------------------------------------------------
FROM node:20-alpine
WORKDIR /app
# sin dependencias externas: solo el runtime de Node
COPY server/relay.js server/package.json ./
ENV NODE_ENV=production PORT=8099 HOST=0.0.0.0
EXPOSE 8099
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8099)+'/salud').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "relay.js"]
