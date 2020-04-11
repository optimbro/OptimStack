# OptimStack

 OptimStack is a Nginx installation script with extra module support for optimum security & performance. https://optimengine.com

# Optional modules/features

- ModSecurity v3
- LibreSSL from source (CHACHA20, ALPN for HTTP/2, X25519, P-521)
- OpenSSL from source (TLS 1.3, CHACHA20, ALPN for HTTP/2, X25519, P-521)
- ngx_pagespeed (Google performance module)
- ngx_brotli (Brotli compression algorithm)
- ngx_headers_more (Custom HTTP headers)
- ngx_http_geoip2_module with libmaxminddb and GeoLite2 databases
- ngx_cache_purge (Purge content from FastCGI, proxy, SCGI and uWSGI caches)
- ngx-fancyindex (Fancy indexes module)

# Installation: Debian 10 Standard Nginx Configuration/ Path

Just run this command in your shell to download and run the script, and then just follow the instruction on your screen:

```
cd /tmp; rm -rf optimstack.sh; wget https://raw.githubusercontent.com/OptimBro/optimstack/master/optimstack.sh --no-dns-cache; chmod +x optimstack.sh; bash optimstack.sh
```

### Installation: VirtualMin Compatible Nginx for Debian, Ubuntu

Just run this command in your shell to download and run the script, and then just follow the instruction on your screen:

```
cd /tmp; rm -rf optimstack-virtualmin.sh; wget https://raw.githubusercontent.com/OptimBro/optimstack/master/optimstack-virtualmin.sh --no-dns-cache; chmod +x optimstack-virtualmin.sh; bash optimstack-virtualmin.sh
```

# Installing WordPress (Optional)

You need to setup WP CLI first
```
cd /web; rm wp.sh; wget https://raw.githubusercontent.com/OptimBro/optimstack/master/wp.sh; chmod +x wp.sh; bash wp.sh
```
### Links
https://www.nginx.com/ 
https://github.com/angristan/nginx-autoinstall (Thanks for the script idea)
https://github.com/SpiderLabs/ModSecurity-nginx
