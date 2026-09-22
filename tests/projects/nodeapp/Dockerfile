FROM node:18

WORKDIR /app

RUN apt-get update && apt-get install -y curl wget git build-essential

COPY . .

RUN npm install
RUN npm run build

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/server.js"]
