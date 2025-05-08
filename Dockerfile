FROM node:18-alpine

WORKDIR /app

# Copy package files first to leverage Docker cache
COPY package*.json ./

# Install dependencies
RUN npm install || exit 1

# Copy the rest of the application
COPY . .

# Verify the application can start
RUN node -e "try { require('./index.js') } catch(e) { console.error(e); process.exit(1) }"

EXPOSE 3000

CMD ["npm", "start"] 