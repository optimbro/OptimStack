#!/bin/bash
tstart=$(date +%s)
if [[ "$EUID" -ne 0 ]]; then
	echo -e "Sorry, you need to run this as root"
	exit 1
fi

# Define versions
OPTIM_NGINX_VER=18.5
NGINX_MAINLINE_VER=1.17.8
NGINX_STABLE_VER=1.16.0
LIBRESSL_VER=2.9.0
OPENSSL_VER=1.1.1a
NPS_VER=1.13.35.2
HEADERMOD_VER=0.33
LIBMAXMINDDB_VER=1.3.2
GEOIP2_VER=3.2
HTTP_REDIS_VER=0.3.9
PCRE_NGINX_VER=8.43
ZLIB_NGINX_VER=1.2.11

# Define installation paramaters for headless install (fallback if unspecifed)
if [[ "$HEADLESS" == "y" ]]; then
	OPTION=${OPTION:-1}
	NGINX_VER=${NGINX_VER:-1}
	PAGESPEED=${PAGESPEED:-n}
	BROTLI=${BROTLI:-n}
	HEADERMOD=${HEADERMOD:-n}
	GEOIP=${GEOIP:-n}
	FANCYINDEX=${FANCYINDEX:-n}
	CACHEPURGE=${CACHEPURGE:-n}
	WEBDAV=${WEBDAV:-n}
	SSL=${SSL:-1}
	RM_CONF=${RM_CONF:-y}
	RM_LOGS=${RM_LOGS:-y}
fi

# Clean screen before launching menu
if [[ "$HEADLESS" == "n" ]]; then
	clear
fi

if [[ "$HEADLESS" != "y" ]]; then
	echo ""
echo '
   ________          __  .__          _________ __                 __    
\_____  \ _______/  |_|__| _____  /   _____//  |______    ____ |  | __
 /   |   \\____ \   __\  |/     \ \_____  \\   __\__  \ _/ ___\|  |/ /
/    |    \  |_> >  | |  |  Y Y  \/        \|  |  / __ \\  \___|    < 
\_______  /   __/|__| |__|__|_|  /_______  /|__| (____  /\___  >__|_ \
        \/|__|                 \/        \/           \/     \/     \/
        '
        echo ""
	echo ""
	echo "OptimStack v-${OPTIM_NGINX_VER}"
	echo "It is the most complete nginx installation script which supports most widely used nginx modules."
	echo "Choose your desired option from the menu"
	echo "Credits: Forked from https://github.com/angristan/nginx-autoinstall, thanks to the developer."
	echo "Credits: OptimBro (It's me), for extending and adding more features."
	echo "Credits: All present and future supporters like you"
	echo "Thank You"
	echo ""
	echo "What do you want to do?"
	echo "   1) Install or update Nginx"
	echo "   2) Uninstall Nginx"
	echo "   3) Update the script"
	echo "   4) Exit"
	echo ""
	while [[ $OPTION !=  "1" && $OPTION != "2" && $OPTION != "3" && $OPTION != "4" ]]; do
		read -p "Select an option [1-4]: " OPTION
	done
fi

case $OPTION in
	1)
		if [[ "$HEADLESS" != "y" ]]; then
			echo ""
			echo "This script will install Nginx with some optional modules."
			echo ""
			echo "Do you want to install Nginx stable or mainline?"
			echo "   1) Stable $NGINX_STABLE_VER"
			echo "   2) Mainline $NGINX_MAINLINE_VER"
			echo ""
			while [[ $NGINX_VER != "1" && $NGINX_VER != "2" ]]; do
				read -p "Select an option [1-2]: " NGINX_VER
			done
		fi
		case $NGINX_VER in
			1)
			NGINX_VER=$NGINX_STABLE_VER
			;;
			2)
			NGINX_VER=$NGINX_MAINLINE_VER
			;;
			*)
			echo "NGINX_VER unspecified, fallback to stable $NGINX_STABLE_VER"
			NGINX_VER=$NGINX_STABLE_VER
			;;
		esac
		if [[ "$HEADLESS" != "y" ]]; then
			echo ""
			echo "Please tell me which modules you want to install."
			echo "If you select none, Nginx will be installed with its default modules."
			echo ""
			echo "Modules to install :"
			while [[ $PAGESPEED != "y" && $PAGESPEED != "n" ]]; do
				read -p "       PageSpeed $NPS_VER [y/n]: " -e PAGESPEED
			done
			while [[ $BROTLI != "y" && $BROTLI != "n" ]]; do
				read -p "       Brotli [y/n]: " -e BROTLI
			done
			while [[ $HEADERMOD != "y" && $HEADERMOD != "n" ]]; do
				read -p "       Headers More $HEADERMOD_VER [y/n]: " -e HEADERMOD
			done
			while [[ $GEOIP != "y" && $GEOIP != "n" ]]; do
				read -p "       GeoIP [y/n]: " -e GEOIP
			done
			while [[ $FANCYINDEX != "y" && $FANCYINDEX != "n" ]]; do
				read -p "       Fancy index [y/n]: " -e FANCYINDEX
			done
			while [[ $CACHEPURGE != "y" && $CACHEPURGE != "n" ]]; do
				read -p "       ngx_cache_purge [y/n]: " -e CACHEPURGE
			done
			while [[ $WEBDAV != "y" && $WEBDAV != "n" ]]; do
				read -p "       nginx WebDAV [y/n]: " -e WEBDAV
			done
			while [[ $MODSEC != "y" && $MODSEC != "n" ]]; do
				read -p "       nginx ModSec [y/n]: " -e MODSEC
			done
			while [[ $SRCACHE != "y" && $SRCACHE != "n" ]]; do
				read -p "       nginx SRCache [y/n]: " -e SRCACHE
			done
			while [[ $REDIS2 != "y" && $REDIS2 != "n" ]]; do
				read -p "       nginx Redis2 [y/n]: " -e REDIS2
			done
			while [[ $NGX_DEVEL_KIT != "y" && $NGX_DEVEL_KIT != "n" ]]; do
				read -p "       nginx NGX_DEVEL_KIT [y/n]: " -e NGX_DEVEL_KIT
			done
			while [[ $SET_MISC != "y" && $SET_MISC != "n" ]]; do
				read -p "       nginx SET_MISC [y/n]: " -e SET_MISC
			done
			while [[ $HTTP_REDIS != "y" && $HTTP_REDIS != "n" ]]; do
				read -p "       nginx HTTP_Redis [y/n]: " -e HTTP_REDIS
			done
			while [[ $MEMC_NGINX != "y" && $MEMC_NGINX != "n" ]]; do
				read -p "       nginx MEMC [y/n]: " -e MEMC_NGINX
			done
			while [[ $ECHO_NGINX != "y" && $ECHO_NGINX != "n" ]]; do
				read -p "       nginx ECHO [y/n]: " -e ECHO_NGINX
			done
			while [[ $PCRE_NGINX != "y" && $PCRE_NGINX != "n" ]]; do
				read -p "       nginx PCRE [y/n]: " -e PCRE_NGINX
			done
			while [[ $ZLIB_NGINX != "y" && $ZLIB_NGINX != "n" ]]; do
				read -p "       nginx zlib [y/n]: " -e ZLIB_NGINX
			done
			while [[ $HTTP3 != "y" && $HTTP3 != "n" ]]; do
				read -p "       HTTP/3 (by Cloudflare, WILL INSTALL BoringSSL, Quiche, Rust and Go) [y/n]: " -e HTTP3
			done

		if [[ "$HTTP3" != 'y' ]]; then
				echo ""
				echo "Choose your OpenSSL implementation:"
				echo "   1) System's OpenSSL ($(openssl version | cut -c9-14))"
				echo "   2) OpenSSL $OPENSSL_VER from source"
				echo "   3) LibreSSL $LIBRESSL_VER from source "
				echo ""
				while [[ $SSL != "1" && $SSL != "2" && $SSL != "3" ]]; do
					read -p "Select an option [1-3]: " SSL
				done
			fi
		fi
		if [[ "$HTTP3" != 'y' ]]; then
			case $SSL in
				1)
				;;
				2)
					OPENSSL=y
				;;
				3)
					LIBRESSL=y
				;;
				*)
					echo "SSL unspecified, fallback to system's OpenSSL ($(openssl version | cut -c9-14))"
				;;
			esac
		fi


		if [[ "$HEADLESS" != "y" ]]; then
			echo ""
			read -n1 -r -p "Nginx is ready to be installed, press any key to continue..."
			echo ""
		fi

				# Cleanup
		# The directory should be deleted at the end of the script, but in case it fails
		rm -r /usr/local/src/nginx/ >> /dev/null 2>&1
		mkdir -p /usr/local/src/nginx/modules

		# Dependencies
		echo "Updating system"
		apt-get -o Acquire::ForceIPv4=true update
		echo "System updated"
		sleep 1
		echo "Installing Dependencies..."
		apt-get -o Acquire::ForceIPv4=true install -y build-essential ca-certificates wget curl libpcre3 libpcre3-dev autoconf unzip automake libtool tar git libssl-dev zlib1g-dev uuid-dev lsb-release libxml2-dev libxslt1-dev
        	apt-get -o Acquire::ForceIPv4=true install -y apt-utils autoconf automake build-essential git libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre++-dev libtool libxml2-dev libyajl-dev pkgconf wget zlib1g-dev git
		apt-get -o Acquire::ForceIPv4=true install -y libtool autoconf build-essential libpcre3-dev zlib1g-dev libssl-dev libxml2-dev libgeoip-dev liblmdb-dev libyajl-dev libcurl4-openssl-dev libpcre++-dev pkgconf libxslt1-dev libgd-dev
		echo "Dependencies Installed"
		sleep 3
		# PageSpeed
		if [[ "$PAGESPEED" = 'y' ]]; then
		echo "Configuring PageSpeed"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			wget https://github.com/pagespeed/ngx_pagespeed/archive/v${NPS_VER}-stable.zip
			unzip v${NPS_VER}-stable.zip
			cd incubator-pagespeed-ngx-${NPS_VER}-stable || exit 1
			psol_url=https://dl.google.com/dl/page-speed/psol/${NPS_VER}.tar.gz
			[ -e scripts/format_binary_url.sh ] && psol_url=$(scripts/format_binary_url.sh PSOL_BINARY_URL)
			wget "${psol_url}"
			tar -xzvf "$(basename "${psol_url}")"
		fi

		#Brotli
		if [[ "$BROTLI" = 'y' ]]; then
		echo "Configuring Brotli Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			git clone https://github.com/eustas/ngx_brotli
			cd ngx_brotli || exit 1
			git checkout v0.1.2
			git submodule update --init
		fi

		# More Headers
		if [[ "$HEADERMOD" = 'y' ]]; then
		echo "Configuring Headers More Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			wget https://github.com/openresty/headers-more-nginx-module/archive/v${HEADERMOD_VER}.tar.gz
			tar xaf v${HEADERMOD_VER}.tar.gz
		fi

		# GeoIP
		if [[ "$GEOIP" = 'y' ]]; then
		echo "Configuring GeoIP Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			# install libmaxminddb
			wget https://github.com/maxmind/libmaxminddb/releases/download/${LIBMAXMINDDB_VER}/libmaxminddb-${LIBMAXMINDDB_VER}.tar.gz
			tar xaf libmaxminddb-${LIBMAXMINDDB_VER}.tar.gz
			cd libmaxminddb-${LIBMAXMINDDB_VER}/
			./configure
			make
			make install
			ldconfig

			cd ../
			wget https://github.com/leev/ngx_http_geoip2_module/archive/${GEOIP2_VER}.tar.gz
			tar xaf ${GEOIP2_VER}.tar.gz

			mkdir geoip-db
			cd geoip-db || exit 1
			wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
			wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz
			tar -xf GeoLite2-City.tar.gz
			tar -xf GeoLite2-Country.tar.gz
			mkdir /opt/geoip
			cd GeoLite2-City_*/
			mv GeoLite2-City.mmdb /opt/geoip/
			cd ../
			cd GeoLite2-Country_*/
			mv GeoLite2-Country.mmdb /opt/geoip/
		fi

		# Cache Purge
		if [[ "$CACHEPURGE" = 'y' ]]; then
		echo "Configuring Cache Purge Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			git clone https://github.com/torden/ngx_cache_purge
		fi

		# LibreSSL
		if [[ "$LIBRESSL" = 'y' ]]; then
		echo "Configuring LibreSSL"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			mkdir libressl-${LIBRESSL_VER}
			cd libressl-${LIBRESSL_VER} || exit 1
			wget -qO- http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VER}.tar.gz | tar xz --strip 1

			./configure \
				LDFLAGS=-lrt \
				CFLAGS=-fstack-protector-strong \
				--prefix=/usr/local/src/nginx/modules/libressl-${LIBRESSL_VER}/.openssl/ \
				--enable-shared=no

			make install-strip -j "$(nproc)"
		fi

		# OpenSSL
		if [[ "$OPENSSL" = 'y' ]]; then
		echo "Configuring OpenSSL"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			wget https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz
			tar xaf openssl-${OPENSSL_VER}.tar.gz
			cd openssl-${OPENSSL_VER}

			./config
		fi

		#Modsec

		if [[ "$MODSEC" = 'y' ]]; then
		echo "Configuring ModSecurity"
		sleep 3
			if [[ ! -d /usr/local/src/nginx/modules/ModSecurity ]]; then
			cd /usr/local/src/nginx/modules || exit 1
			git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
			cd ModSecurity
			git submodule init
			git submodule update
			./build.sh
			./configure
			make
			make install
			mkdir /etc/nginx/modsec
			wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
			mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf

			fi
		fi

		# SRCACHE
		if [[ "$SRCACHE" = 'y' ]]; then
		echo "Configuring SRCache Module "
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			git clone https://github.com/openresty/srcache-nginx-module
		fi

		# REDIS2
		if [[ "$REDIS2" = 'y' ]]; then
		echo "Configuring Redis2 Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			git clone https://github.com/openresty/redis2-nginx-module
		fi

		# SET_MISC
		if [[ "$SET_MISC" = 'y' ]]; then
		echo "Configuring Set_Misc Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			git clone https://github.com/openresty/set-misc-nginx-module
		fi

		# HTTP_REDIS
		if [[ "$HTTP_REDIS" = 'y' ]]; then
		echo "Configuring HTTP Redis Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			wget https://people.freebsd.org/~osa/ngx_http_redis-${HTTP_REDIS_VER}.tar.gz
			tar xaf ngx_http_redis-${HTTP_REDIS_VER}.tar.gz
			cd ngx_http_redis-${HTTP_REDIS_VER}
		fi

		if [[ "$PCRE_NGINX" = 'y' ]]; then
		echo "Configuring PCRE_NGINX Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			wget https://ftp.pcre.org/pub/pcre/pcre-${PCRE_NGINX_VER}.tar.gz
			tar xaf pcre-${PCRE_NGINX_VER}.tar.gz
			cd pcre-${PCRE_NGINX_VER}
		fi

		if [[ "$ZLIB_NGINX" = 'y' ]]; then
		echo "Configuring ZLIB_NGINX Module"
		sleep 3
			cd /usr/local/src/nginx/modules || exit 1
			wget http://zlib.net/zlib-${ZLIB_NGINX_VER}.tar.gz
			tar xaf zlib-${ZLIB_NGINX_VER}.tar.gz
			cd zlib-${ZLIB_NGINX_VER}
		fi

		# Download and extract of Nginx source code
		echo "Downloading NGINX..."
		sleep 3
		cd /usr/local/src/nginx/ || exit 1
		wget -qO- http://nginx.org/download/nginx-${NGINX_VER}.tar.gz | tar zxf -
		cd nginx-${NGINX_VER}

		# As the default nginx.conf does not work, we download a clean and working conf from my GitHub.
		# We do it only if it does not already exist, so that it is not overriten if Nginx is being updated
		if [[ ! -e /etc/nginx/nginx.conf ]]; then
			mkdir -p /etc/nginx
			cd /etc/nginx || exit 1
			wget https://raw.githubusercontent.com/OptimBro/Advanced-Nginx-Install-Script/master/conf/nginx.conf
		fi
		echo "Configuring NGINX"
		sleep 3
		cd /usr/local/src/nginx/nginx-${NGINX_VER} || exit 1

		NGINX_OPTIONS="
		--build=OptimEngine-${OPTIM_NGINX_VER} \
		--prefix=/etc/nginx \
		--sbin-path=/usr/sbin/nginx \
		--conf-path=/etc/nginx/nginx.conf \
		--error-log-path=/var/log/nginx/error.log \
		--http-log-path=/var/log/nginx/access.log \
		--pid-path=/var/run/nginx.pid \
		--lock-path=/var/run/nginx.lock \
		--http-client-body-temp-path=/var/cache/nginx/client_temp \
		--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
		--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
		--user=www-data \
		--group=www-data"

		NGINX_MODULES="--with-threads \
		--with-file-aio \
		--with-http_ssl_module \
		--with-http_v2_module \
		--with-http_mp4_module \
		--with-http_auth_request_module \
		--with-http_slice_module \
		--with-http_stub_status_module \
		--with-http_realip_module \
		--with-pcre-jit \
		--with-debug \
		--with-http_degradation_module \
		--with-http_addition_module \
		--with-http_dav_module \
		--with-http_flv_module \
		--with-http_gunzip_module \
		--with-http_gzip_static_module \
		--with-http_sub_module \
		--with-http_secure_link_module \
		--with-stream_realip_module \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
		--with-select_module \
		--with-poll_module"

		# Optional modules

		if [[ "$NGX_DEVEL_KIT" = 'y' ]]; then
			git clone --quiet https://github.com/simplresty/ngx_devel_kit.git /usr/local/src/nginx/modules/ngx_devel_kit
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo --add-module=/usr/local/src/nginx/modules/ngx_devel_kit)
		fi

		if [[ "$LIBRESSL" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--with-openssl=/usr/local/src/nginx/modules/libressl-${LIBRESSL_VER}")
		fi

		if [[ "$PAGESPEED" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/incubator-pagespeed-ngx-${NPS_VER}-stable")
		fi

		if [[ "$BROTLI" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/ngx_brotli")
		fi

		if [[ "$HEADERMOD" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/headers-more-nginx-module-${HEADERMOD_VER}")
		fi

		if [[ "$GEOIP" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/ngx_http_geoip2_module-${GEOIP2_VER}")
		fi

		if [[ "$OPENSSL" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--with-openssl=/usr/local/src/nginx/modules/openssl-${OPENSSL_VER}")
		fi

		if [[ "$CACHEPURGE" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/ngx_cache_purge")
		fi

		if [[ "$FANCYINDEX" = 'y' ]]; then
			git clone --quiet https://github.com/aperezdc/ngx-fancyindex.git /usr/local/src/nginx/modules/fancyindex
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/fancyindex")
		fi

		if [[ "$WEBDAV" = 'y' ]]; then
			git clone --quiet https://github.com/arut/nginx-dav-ext-module.git /usr/local/src/nginx/modules/nginx-dav-ext-module
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--with-http_dav_module --add-module=/usr/local/src/nginx/modules/nginx-dav-ext-module")
		fi

		if [[ "$MODSEC" = 'y' ]]; then
			git clone --quiet --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/nginx/modules/nginx-modsec-connect
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/nginx-modsec-connect")
		fi

		if [[ "$SRCACHE" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/srcache-nginx-module")
		fi

		if [[ "$REDIS2" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/redis2-nginx-module")
		fi

		if [[ "$SET_MISC" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/set-misc-nginx-module")
		fi

		if [[ "$HTTP_REDIS" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/ngx_http_redis-${HTTP_REDIS_VER}")
		fi
		if [[ "$MEMC_NGINX" = 'y' ]]; then
			git clone --quiet https://github.com/openresty/memc-nginx-module.git /usr/local/src/nginx/modules/memc-nginx-module
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/memc-nginx-module")
		fi
		if [[ "$ECHO_NGINX" = 'y' ]]; then
			git clone --quiet https://github.com/openresty/echo-nginx-module.git /usr/local/src/nginx/modules/echo-nginx-module
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--add-module=/usr/local/src/nginx/modules/echo-nginx-module")
		fi
		if [[ "$PCRE_NGINX" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--with-pcre=/usr/local/src/nginx/modules/pcre-${PCRE_NGINX_VER}")
		fi
		if [[ "$ZLIB_NGINX" = 'y' ]]; then
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo "--with-zlib=/usr/local/src/nginx/modules/zlib-${ZLIB_NGINX_VER}")
		fi

		# HTTP3
		if [[ "$HTTP3" = 'y' ]]; then
			cd /usr/local/src/nginx/modules || exit 1
			git clone --recursive https://github.com/cloudflare/quiche
			# Dependencies for BoringSSL and Quiche
			apt-get install -y golang
			# Rust is not packaged so that's the only way...
			curl -sSf https://sh.rustup.rs | sh -s -- -y
			source $HOME/.cargo/env

			cd /usr/local/src/nginx/nginx-${NGINX_VER} || exit 1
			# Apply actual patch
			patch -p01 < /usr/local/src/nginx/modules/quiche/extras/nginx/nginx-1.16.patch

			NGINX_OPTIONS=$(echo "$NGINX_OPTIONS"; echo --with-openssl=/usr/local/src/nginx/modules/quiche/deps/boringssl --with-quiche=/usr/local/src/nginx/modules/quiche)
			NGINX_MODULES=$(echo "$NGINX_MODULES"; echo --with-http_v3_module)
		fi

		echo "Compiling NGINX"
		sleep 3

		./configure $NGINX_OPTIONS --with-cc-opt='-g -O2 -fPIC -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' --with-ld-opt='-Wl,-Bsymbolic-functions -fPIC -pie -Wl,-z,relro -Wl,-z,now' --with-pcre-opt='-g -Ofast -fPIC -m64 -march=native -fstack-protector-strong -D_FORTIFY_SOURCE=2' --with-zlib-opt='-g -Ofast -fPIC -m64 -march=native -fstack-protector-strong -D_FORTIFY_SOURCE=2' $NGINX_MODULES
		make -j "$(nproc)"
		make install

		sleep 5

		# remove debugging symbols
		strip -s /usr/sbin/nginx

		sleep 5

		echo "Installing NGINX"
		sleep 3
		# Nginx installation from source does not add an init script for systemd and logrotate
		# Using the official systemd script and logrotate conf from nginx.org
		if [[ ! -e /lib/systemd/system/nginx.service ]]; then
			cd /lib/systemd/system/ || exit 1
			wget https://raw.githubusercontent.com/Angristan/nginx-autoinstall/master/conf/nginx.service
			# Enable nginx start at boot
			systemctl enable nginx
		fi
		sleep 5
		if [[ ! -e /etc/logrotate.d/nginx ]]; then
			cd /etc/logrotate.d/ || exit 1
			wget https://raw.githubusercontent.com/Angristan/nginx-autoinstall/master/conf/nginx-logrotate -O nginx
		fi
		sleep 5
		# Nginx's cache directory is not created by default
		if [[ ! -d /var/cache/nginx ]]; then
			mkdir -p /var/cache/nginx
		fi
		sleep 5
		# We add the sites-* folders as some use them.
		if [[ ! -d /etc/nginx/sites-available ]]; then
			mkdir -p /etc/nginx/sites-available
		fi
		if [[ ! -d /etc/nginx/sites-enabled ]]; then
			mkdir -p /etc/nginx/sites-enabled
		fi
		if [[ ! -d /etc/nginx/conf.d ]]; then
			mkdir -p /etc/nginx/conf.d
		fi
		echo "NGINX Installed"
		sleep 3

		# Restart Nginx
		echo "Restarting NGINX"
		sleep 3
		systemctl restart nginx

		# Block Nginx from being installed via APT
		if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]
		then
			cd /etc/apt/preferences.d/ || exit 1
			echo -e "Package: nginx*\\nPin: release *\\nPin-Priority: -1" > nginx-block
		fi

		# Removing temporary Nginx and modules files
		echo "Removing temporary Nginx and modules files"
		sleep 3
		rm -r /usr/local/src/nginx

		# We're done !
		echo "NGINX Installed Successfully"
		tend=$(date +%s)
		totalruntime=$((tend-tstart))
		echo "Total To Compile and Install Nginx: $totalruntime seconds!"
	exit
	;;
	2) # Uninstall Nginx
		if [[ "$HEADLESS" != "y" ]]; then
			while [[ $RM_CONF !=  "y" && $RM_CONF != "n" ]]; do
				read -p "       Remove configuration files ? [y/n]: " -e RM_CONF
			done
			while [[ $RM_LOGS !=  "y" && $RM_LOGS != "n" ]]; do
				read -p "       Remove logs files ? [y/n]: " -e RM_LOGS
			done
		fi
		# Stop Nginx
		systemctl stop nginx
		echo "Nginx Stopped"
		sleep 1
		systemctl daemon-reload
		echo "Units Reloaded"
		# Removing Nginx files and modules files
		echo "Removing Nginx files and modules"
		sleep 2
		rm -r /usr/local/src/nginx \
		/usr/sbin/nginx* \
		/etc/logrotate.d/nginx \
		/var/cache/nginx \
		/lib/systemd/system/nginx.service \
		/etc/systemd/system/multi-user.target.wants/nginx.service

		# Remove conf files
		echo "Removing other configuration files"
		sleep 2
		if [[ "$RM_CONF" = 'y' ]]; then
			rm -r /etc/nginx/
		fi

		# Remove logs
		echo "Removing logs cleaning up"
		sleep 2
		if [[ "$RM_LOGS" = 'y' ]]; then
			rm -r /var/log/nginx
		fi
		echo "Cleanup Complete"
		sleep 2
		# Remove Nginx APT block
		if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]
		then
			rm /etc/apt/preferences.d/nginx-block
		fi

		# We're done !
		echo "Nginx is now fully uninstalled."

		tend=$(date +%s)
		totalruntime=$((tend-tstart))
		echo "Total To Uninstall Nginx: $totalruntime seconds!"
		exit
	;;
	3) # # Update the script
		echo "Purging DNS Cache"
		sudo /etc/init.d/networking restart
		sleep 1
		rm -rf OptimStack.sh
		echo "Starting update..."
		sleep 1
		wget https://raw.githubusercontent.com/OptimBro/OptimStack/master/OptimStack.sh --no-dns-cache -O OptimStack.sh
		chmod +x OptimStack.sh
		echo ""
		echo "Updating script..."
		sleep 3
		./OptimStack.sh
		echo "Update complete"
				tend=$(date +%s)
		totalruntime=$((tend-tstart))
		echo "Total To Update The OptimNGINX(SCRIPT): $totalruntime seconds!"
		exit
	;;
	*) # Exit
		exit
	;;

esac
