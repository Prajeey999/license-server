#!/bin/bash
# Navigate to the license-server folder
cd license-server

# Install dependencies if using Node.js
if [ -f package.json ]; then
  npm install
fi

# Start the app
if [ -f package.json ]; then
  npm start
else
  echo "No start script found. Please ensure your project has a start script."
  exit 1
fi
