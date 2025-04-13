# Use Node LTS
FROM node:20

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json from the root directory
COPY ../package*.json ./

# Install app dependencies
RUN npm install

# Now copy the rest of the app source from the server directory
COPY ./server /app

# Start the server
CMD [ "node", "server.js" ]
