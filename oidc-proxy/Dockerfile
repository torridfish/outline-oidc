FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js .
USER node
EXPOSE 9000
CMD ["node", "server.js"]
