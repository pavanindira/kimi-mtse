# Stage 1: Build the React SPA
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --silent

COPY . .

# VITE_API_URL is the path prefix for API calls.
# In production nginx proxies /api → FastAPI, so /api is correct.
ARG  VITE_API_URL=/api
ENV  VITE_API_URL=$VITE_API_URL

RUN npm run build


# Stage 2: Serve with nginx
FROM nginx:1.27-alpine

# Remove the default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy the built SPA
COPY --from=builder /app/dist /usr/share/nginx/html

# nginx config: serve SPA and proxy /api to the API service
COPY nginx-spa.conf /etc/nginx/conf.d/mste.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
