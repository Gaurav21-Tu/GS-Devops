#!/bin/sh
# Generate config.js from environment variables at runtime
cat > /usr/share/nginx/html/config.js <<EOF
window.ENV = {
  REACT_APP_BASE_URL: '${REACT_APP_BASE_URL}'
};
EOF

# Start nginx
exec nginx -g 'daemon off;'
