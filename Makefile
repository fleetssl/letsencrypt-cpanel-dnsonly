ACMETOOL_VER?=0.0.61
VER?=0.0.1

.PHONY: clean package all

all: package

package: clean acmetool
	@rm -rf fpm; mkdir fpm;
	cp certificate-hook.sh pre-install.sh post-install.sh acmetool responses.yml fpm/
	chmod 0644 fpm/responses.yml
	chmod +x fpm/acmetool fpm/*.sh
	dos2unix fpm/*.sh fpm/responses.yml
	fpm -a amd64 -s dir -t rpm -n letsencrypt-cpanel-dnsonly -v $(VER)  -C ./fpm/ --before-install fpm/pre-install.sh --after-install fpm/post-install.sh --prefix /usr/local/letsencrypt-cpanel-dnsonly --rpm-os Linux --url https://dnsonly.letsencrypt-for-cpanel.com -d bind-utils --conflicts acmetool --conflicts acmetool-nocgo
	@rm -rf fpm

acmetool:
	rm -rf scratch; mkdir scratch; 
	wget -O scratch/acmetool.tar.gz https://github.com/hlandau/acme/releases/download/v$(ACMETOOL_VER)/acmetool-v$(ACMETOOL_VER)-linux_amd64.tar.gz
	tar -C scratch/ --strip-components=1 -zxf scratch/acmetool.tar.gz
	mv scratch/bin/acmetool .
	rm -rf scratch

clean:
	rm -rf *.rpm
