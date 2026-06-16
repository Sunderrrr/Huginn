# Build the SPA, then serve the static assets with nginx.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
# The hub base URL is baked in at build time.
# Empty default = same-origin (relative /api calls), which the prod reverse
# proxy expects; override only if the hub lives on a different origin.
ARG VITE_HUB_URL=""
ENV VITE_HUB_URL=$VITE_HUB_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
