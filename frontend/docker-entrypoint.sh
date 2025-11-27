#!/bin/sh
# Docker entrypoint script to generate config.js from environment variables
# This ensures Cognito configuration is properly injected at container startup

set -e

# Generate config.js with actual Cognito values from environment variables
cat > /usr/share/nginx/html/config.js << EOF
window.COGNITO_USER_POOL_ID = "${COGNITO_USER_POOL_ID}";
window.COGNITO_CLIENT_ID = "${COGNITO_CLIENT_ID}";
window.COGNITO_REGION = "${COGNITO_REGION}";
EOF

echo "Generated config.js with Cognito configuration"

# Start nginx
exec nginx -g 'daemon off;'
