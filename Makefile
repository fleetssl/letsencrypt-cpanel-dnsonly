VER?=1.0.0

.PHONY: clean package all publish

all: package

package: clean fleetssl-dnsonly
	@rm -rf fpm; mkdir -p fpm/usr/local/bin; mkdir -p fpm/etc/cron.d/
	cp fleetssl-dnsonly fpm/usr/local/bin/
	cp cronjob fpm/etc/cron.d/fleetssl-dnsonly
	chmod +x fpm/usr/local/bin/fleetssl-dnsonly
	fpm -a amd64 -s dir -t rpm -n letsencrypt-cpanel-dnsonly -v $(VER)  -C ./fpm/ --before-install pre-install.sh --after-install post-install.sh --rpm-os Linux --url https://dnsonly.letsencrypt-for-cpanel.com -d python
	@rm -rf fpm

fleetssl-dnsonly:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o fleetssl-dnsonly fleetssl-dnsonly.go

publish:
	rsync -vhz --progress *.rpm root@fleetssl.com:/home/web/repo
	ssh web@fleetssl.com "createrepo --update /home/web/repo"
	ssh root@fleetssl.com "sh -c '/root/invalidate-cdn.sh'"

clean:
	rm -f fleetssl-dnsonly *.rpm
