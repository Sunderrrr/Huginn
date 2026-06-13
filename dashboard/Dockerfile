# Build the SPA, then serve the static assets with nginx.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
# The hub base URL is baked in at build time.
ARG VITE_HUB_URL=http://localhost:8000
ENV VITE_HUB_URL=$VITE_HUB_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
