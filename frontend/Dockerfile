FROM nginx:alpine

# Create nginx user and set up directories with proper permissions
RUN mkdir -p /var/cache/nginx/client_temp \
    /var/cache/nginx/proxy_temp \
    /var/cache/nginx/fastcgi_temp \
    /var/cache/nginx/uwsgi_temp \
    /var/cache/nginx/scgi_temp \
    /var/run \
    && chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /var/run \
    && chmod -R 755 /var/cache/nginx \
    && chmod -R 755 /var/run

# Copy HTML file
COPY index.html /usr/share/nginx/html/

# Copy nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Ensure nginx owns the HTML directory
RUN chown -R nginx:nginx /usr/share/nginx/html

EXPOSE 8080

# Run as nginx user
USER nginx

CMD ["nginx", "-g", "daemon off;"]