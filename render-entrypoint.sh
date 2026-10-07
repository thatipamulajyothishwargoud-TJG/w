#!/bin/sh
set -eu

: "${PORT:=10000}"
: "${UPLOAD_BASE_PATH:=/var/data/cloudfen/uploads}"

sed -i "s/^Listen 80$/Listen ${PORT}/" /etc/apache2/ports.conf
sed -i "s/<VirtualHost \*:80>/<VirtualHost *:${PORT}>/" /etc/apache2/sites-available/000-default.conf

mkdir -p "$UPLOAD_BASE_PATH"
chown -R www-data:www-data "$(dirname "$UPLOAD_BASE_PATH")"

echo "Preparing CloudFen database and fictional demo records."
php /var/www/html/tools/render-bootstrap.php

exec apache2-foreground
