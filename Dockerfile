# Multi-stage Dockerfile for building and packaging the secure-client-pki-tool

# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Stage 2: Runtime (lightweight)
FROM node:20-alpine

WORKDIR /app

# Install a simple HTTP server to serve the built application
RUN npm install -g serve

# Copy built artifacts from builder stage
COPY --from=builder /app/dist ./dist

# Expose port for serving
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

# Serve the application
CMD ["serve", "-s", "dist", "-l", "3000"]
