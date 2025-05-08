FROM node:18-alpine

WORKDIR /app

# Copy package files first to leverage Docker cache
COPY package*.json ./

# Install dependencies
RUN npm install || exit 1

# Copy the rest of the application
COPY . .

# Verify the application can be built without starting it
RUN node -e "const app = require('./index.js'); console.log('Application verified successfully');"

EXPOSE 3000

# Use a non-blocking command as the default
CMD ["echo", "Application is ready to start"] 