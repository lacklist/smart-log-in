FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --ignore-scripts && npm cache clean --force
COPY index.js ./
USER node
EXPOSE 8787
CMD ["node", "index.js"]
