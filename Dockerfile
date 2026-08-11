FROM php:8.2-apache

# Install dependencies including LDAP
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    sshpass \
    openssh-client \
    qrencode \
    cron \
    logrotate \
    libldap2-dev \
    docker.io \
    && docker-php-ext-configure ldap --with-libdir=lib/x86_64-linux-gnu/ \
    && docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd ldap \
    && a2enmod rewrite \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Copy project files
COPY . /var/www/html

# Install PHP dependencies
RUN git config --global --add safe.directory /var/www/html \
  && composer config --global audit.block-insecure false \
  && composer install --no-dev --optimize-autoloader --no-security-blocking

# Configure Apache
COPY apache.conf /etc/apache2/sites-available/000-default.conf

# Don't advertise exact Apache/PHP versions: it hands an attacker a ready-made
# list of version-specific exploits to try. The zz- prefix matters: Debian's
# stock security.conf sets ServerTokens OS and conf-enabled loads alphabetically,
# so anything sorting earlier is simply overridden.
RUN printf '%s\n' 'ServerTokens Prod' 'ServerSignature Off' > /etc/apache2/conf-available/zz-security-tokens.conf \
    && a2enconf zz-security-tokens \
    && printf '%s\n' 'expose_php = Off' > /usr/local/etc/php/conf.d/zz-hide-version.ini

# Set permissions and create writable directories
RUN mkdir -p /var/www/html/backups /var/www/html/logs /var/www/html/storage/ssh \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html/public \
    && chmod 775 /var/www/html/backups /var/www/html/logs

# Setup cron jobs.
# NB: the www-data jobs redirect into /var/log/cron.log. If that file is not
# group-writable the shell REDIRECT fails before the command runs, so every
# www-data job dies silently — hence the explicit chown/chmod below.
RUN echo "0 * * * * www-data cd /var/www/html && /usr/local/bin/php bin/check_expired_clients.php >> /var/log/cron.log 2>&1" > /etc/cron.d/amnezia-cron \
    && echo "0 * * * * www-data cd /var/www/html && /usr/local/bin/php bin/check_traffic_limits.php >> /var/log/cron.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && echo "*/3 * * * * root /bin/bash /var/www/html/bin/monitor_metrics.sh >> /var/log/metrics_monitor.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && echo "0 * * * * www-data cd /var/www/html && /usr/local/bin/php bin/backup_cron.php >> /var/log/cron.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && echo "17 5 * * * www-data cd /var/www/html && /usr/local/bin/php bin/update_audit_cron.php >> /var/log/cron.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && printf '%s\n' \
       '/var/log/cron.log /var/log/metrics_collector.log /var/log/metrics_collector_errors.log /var/log/metrics_monitor.log /var/log/logrotate.log {' \
       '    daily' '    rotate 7' '    maxsize 20M' '    compress' '    delaycompress' '    missingok' '    notifempty' '    copytruncate' '}' \
       '/var/www/html/logs/*.log {' \
       '    su www-data www-data' '    weekly' '    rotate 4' '    maxsize 10M' '    compress' '    missingok' '    notifempty' '    copytruncate' '}' \
       > /etc/logrotate.d/amnezia \
    && echo "30 2 * * * root /usr/sbin/logrotate /etc/logrotate.d/amnezia >> /var/log/logrotate.log 2>&1" >> /etc/cron.d/amnezia-cron \
    && chmod 0644 /etc/cron.d/amnezia-cron \
    && crontab /etc/cron.d/amnezia-cron \
    && touch /var/log/cron.log \
    && chown root:www-data /var/log/cron.log \
    && chmod 664 /var/log/cron.log \
    && touch /var/log/metrics_monitor.log \
    && touch /var/log/metrics_collector.log \
    && touch /var/log/ldap_sync.log

# Make monitor script executable
RUN chmod +x /var/www/html/bin/monitor_metrics.sh

# Create startup script
RUN echo '#!/bin/bash\n\
service cron start\n\
# Ensure writable directories exist with correct ownership\n\
mkdir -p /var/www/html/backups /var/www/html/logs /var/www/html/storage/ssh\nchown -R www-data:www-data /var/www/html/storage\nchmod 700 /var/www/html/storage/ssh\n# Keep the cron log writable by www-data (see note above).\ntouch /var/log/cron.log\nchown root:www-data /var/log/cron.log 2>/dev/null || true\nchmod 664 /var/log/cron.log 2>/dev/null || true\n\
chown -R www-data:www-data /var/www/html/backups /var/www/html/logs\n\
chmod 775 /var/www/html/backups /var/www/html/logs\n\
if [ -f /var/www/html/.env ]; then\n\
  chgrp www-data /var/www/html/.env || true\n\
  chmod 640 /var/www/html/.env || true\n\
fi\n\
# Ensure www-data can talk to host docker socket if mounted\n\
if [ -S /var/run/docker.sock ]; then\n\
  SOCK_GID=$(stat -c %g /var/run/docker.sock)\n\
  if ! getent group docker >/dev/null; then\n\
    groupadd -g "$SOCK_GID" docker || true\n\
  fi\n\
  usermod -aG docker www-data || true\n\
fi\n\
# Start metrics collector on container startup\n\
/bin/bash /var/www/html/bin/monitor_metrics.sh\n\
apache2-foreground' > /start.sh \
    && chmod +x /start.sh

# Expose port 80
EXPOSE 80

CMD ["/start.sh"]
