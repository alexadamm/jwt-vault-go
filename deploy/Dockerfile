FROM vault:1.13.3

RUN apk add --no-cache curl jq netcat-openbsd

# Copy initialization script
COPY ./init-vault.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-vault.sh

# set environment variables
ENV VAULT_ADDR='http://127.0.0.1:8200'
ENV VAULT_DEV_ROOT_TOKEN_ID='dev-root-token'

# start vault and run init script
CMD ["sh", "-c", "vault server -dev -dev-listen-address=0.0.0.0:8200 & sleep 2 && /usr/local/bin/init-vault.sh && tail -f /dev/null"]
