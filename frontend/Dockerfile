FROM nginx:alpine

# Create nginx user and set up directories with proper permissions
RUN mkdir -p /var/cache/nginx/client_temp \
    /var/cache/nginx/proxy_temp \
    /var/cache/nginx/fastcgi_temp \
    /var/cache/nginx/uwsgi_temp \
    /var/cache/nginx/scgi_temp \
    /var/run \
    /tmp \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /var/run \
    && chown -R nginx:nginx /tmp \
    && chmod -R 755 /var/cache/nginx \
    && chmod -R 755 /var/run \
    && chmod -R 777 /tmp

# Copy HTML file
COPY index.html /usr/share/nginx/html/

# Copy nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Set permissions and ensure nginx owns the HTML directory
RUN chmod +x /docker-entrypoint.sh \
    && chown -R nginx:nginx /usr/share/nginx/html

# Set default environment variables for Cognito
ENV COGNITO_USER_POOL_ID="" \
    COGNITO_CLIENT_ID="" \
    COGNITO_REGION="eu-central-1"

EXPOSE 8080

# Run as nginx user
USER nginx

# Use entrypoint script to generate config.js from environment variables
ENTRYPOINT ["/docker-entrypoint.sh"]