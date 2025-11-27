#!/bin/sh
# Docker entrypoint script to generate config.js from environment variables
# This ensures Cognito configuration is properly injected at container startup

set -e

# Function to validate input - only allow alphanumeric, hyphens, and underscores
# This prevents XSS attacks from malicious environment variable values
validate_input() {
    local value="$1"
    local name="$2"
    
    # Empty values are allowed (will result in empty string in JS)
    if [ -z "$value" ]; then
        return 0
    fi
    
    # Check that value only contains safe characters (alphanumeric, hyphen, underscore)
    if ! echo "$value" | grep -qE '^[a-zA-Z0-9_-]+$'; then
        echo "Error: $name contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed."
        exit 1
    fi
}

# Validate all Cognito configuration values
validate_input "$COGNITO_USER_POOL_ID" "COGNITO_USER_POOL_ID"
validate_input "$COGNITO_CLIENT_ID" "COGNITO_CLIENT_ID"
validate_input "$COGNITO_REGION" "COGNITO_REGION"

# Generate config.js with actual Cognito values from environment variables
cat > /usr/share/nginx/html/config.js << EOF
window.COGNITO_USER_POOL_ID = "${COGNITO_USER_POOL_ID}";
window.COGNITO_CLIENT_ID = "${COGNITO_CLIENT_ID}";
window.COGNITO_REGION = "${COGNITO_REGION}";
EOF

echo "Generated config.js with Cognito configuration"

# Start nginx
exec nginx -g 'daemon off;'
