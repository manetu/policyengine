# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy source files
COPY . .

# Build the static site
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built static files to nginx
COPY --from=builder /app/build /usr/share/nginx/html/policyengine

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
