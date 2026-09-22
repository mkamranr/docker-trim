# A typical bloated Node service: full node image, dev dependencies,
# build toolchain left in, npm cache shipped, running as root.
FROM node:18

WORKDIR /app

RUN apt-get update && apt-get install -y curl wget git build-essential python3

COPY . .

RUN npm install
RUN npm run build

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "dist/server.js"]
