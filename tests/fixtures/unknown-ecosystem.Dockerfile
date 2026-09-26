# No recognisable build step. docker-trim must refuse to invent a builder stage
# and fall back to safe cleanups only.
FROM debian:bookworm

RUN apt-get update && apt-get install -y nginx curl

COPY site/ /var/www/html/

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
