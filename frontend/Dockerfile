FROM nginx:alpine

# Create nginx user and set up directories with proper permissions
RUN mkdir -p /var/cache/nginx/client_temp \
    /var/cache/nginx/proxy_temp \
    /var/cache/nginx/fastcgi_temp \
    /var/cache/nginx/uwsgi_temp \
    /var/cache/nginx/scgi_temp \
    /var/cache/nginx/config \
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

# Copy nginx config template
COPY nginx.conf /etc/nginx/nginx.conf.template

# Ensure nginx owns the HTML directory
RUN chown -R nginx:nginx /usr/share/nginx/html \
    && chown nginx:nginx /etc/nginx/nginx.conf.template

# Set default environment variables for Cognito
ENV COGNITO_USER_POOL_ID="" \
    COGNITO_CLIENT_ID="" \
    COGNITO_REGION="eu-central-1"

EXPOSE 8080

# Run as nginx user
USER nginx

# Use envsubst to replace environment variables in nginx config, then start nginx
# Using /var/cache/nginx/config which is owned by nginx for security
CMD ["/bin/sh", "-c", "envsubst '$COGNITO_USER_POOL_ID $COGNITO_CLIENT_ID $COGNITO_REGION' < /etc/nginx/nginx.conf.template > /var/cache/nginx/config/nginx.conf && nginx -c /var/cache/nginx/config/nginx.conf -g 'daemon off;'"]