# =============================================================================
# Stage 1: Build React Dashboard
# =============================================================================
FROM node:20-alpine AS frontend-builder
WORKDIR /app/dashboard

COPY dashboard/package*.json ./
RUN npm install

COPY dashboard/ ./
RUN npm run build

# =============================================================================
# Stage 2: Python Backend Runtime
# =============================================================================
FROM python:3.11-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Install Python backend dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy source code
COPY backend ./backend
COPY main.py start.sh ./
COPY extension ./extension

# Copy compiled frontend from Stage 1
COPY --from=frontend-builder /app/dashboard/dist ./dashboard/dist

RUN chmod +x start.sh

EXPOSE 8000

CMD ["bash", "start.sh"]
