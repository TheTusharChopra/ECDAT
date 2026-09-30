# Stage 1: Build Next.js frontend
FROM node:22-bookworm-slim AS builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN mkdir -p public
ENV NEXT_PUBLIC_ECDAT_API_URL="/api/backend"
RUN npm run build

# Stage 2: Final unified runtime
FROM node:22-bookworm-slim AS runner

# Install Python 3 and curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy backend source & datasets
COPY backend/ ./backend/
COPY datasets/ ./datasets/

# Copy frontend source, build output & dependencies
COPY frontend/package*.json ./frontend/
COPY frontend/next.config.ts ./frontend/
COPY --from=builder /app/frontend/.next ./frontend/.next
COPY --from=builder /app/frontend/public ./frontend/public
COPY --from=builder /app/frontend/node_modules ./frontend/node_modules

# Copy startup orchestration script
COPY scripts/start-production.sh ./start.sh
RUN chmod +x ./start.sh

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV NEXT_PUBLIC_ECDAT_API_URL="/api/backend"
ENV ECDAT_BACKEND_INTERNAL_URL="http://127.0.0.1:8787"

EXPOSE 3000

CMD ["./start.sh"]
