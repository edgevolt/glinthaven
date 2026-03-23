# Use a lightweight Node image
FROM node:18-alpine

# Set the working directory
WORKDIR /app

# Copy dependency definitions
COPY package*.json ./

# Install all dependencies (including devDependencies needed for Vite build)
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the Vite frontend into the dist/ directory
RUN npm run build

# Expose the port the Express server runs on
EXPOSE 3000

# Start the Express server
CMD ["npm", "start"]
