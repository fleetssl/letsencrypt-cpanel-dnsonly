VER?=1.2.0

.PHONY: clean package all publish

all: package

package: clean fleetssl-dnsonly
	VER=$(VER) nfpm pkg --packager rpm --target .

fleetssl-dnsonly:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VER)" -o fleetssl-dnsonly fleetssl-dnsonly.go

publish:
	rsync -vhz --progress *.rpm web@fleetssl.com:/home/web/repo
	ssh web@fleetssl.com "createrepo --update /home/web/repo"
	ssh root@fleetssl.com "sh -c '/root/invalidate-cdn.sh'"

clean:
	rm -f fleetssl-dnsonly *.rpm fleetssl-dnsonly *.deb
