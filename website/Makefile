.PHONY: all deploy

all: deploy

deploy:
	aws --profile=fleetssl-site --region=ap-southeast-2 s3 cp index.html s3://dnsonly.letsencrypt-for-cpanel.com/index.html
	aws --profile=fleetssl-site --region=ap-southeast-2 cloudfront create-invalidation --distribution-id E2X1H7N04P4UVF --paths "/index.html" "/"
