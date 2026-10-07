FROM php:8.3-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libonig-dev \
        libpng-dev \
        libzip-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" gd mbstring pdo_mysql mysqli zip \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod rewrite headers expires deflate

RUN printf '%s\n' \
    'upload_max_filesize=20M' \
    'post_max_size=22M' \
    'memory_limit=256M' \
    'max_execution_time=60' \
    'max_input_time=60' \
    'display_errors=Off' \
    'log_errors=On' \
    'session.cookie_httponly=1' \
    'session.cookie_samesite=Lax' \
    'session.use_strict_mode=1' \
    > /usr/local/etc/php/conf.d/cloudfen.ini

WORKDIR /var/www/html
COPY --chown=www-data:www-data . /var/www/html/
COPY render-entrypoint.sh /usr/local/bin/render-entrypoint
RUN chmod 0755 /usr/local/bin/render-entrypoint

ENV PORT=10000
CMD ["/usr/local/bin/render-entrypoint"]
