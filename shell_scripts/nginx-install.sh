#!/bin/bash

tar xvfz nginx-1.14.1.tar.gz
cd nginx-1.14.1
./configure --prefix=/usr/local/nginx  --without-http_rewrite_module --without-http_gzip_module
make
make install