export OPENDJ_JAVA_ARGS=-Xmx256m

dsconfig \
  --verbose \
  --no-prompt \
  --trustAll \
  --port "$ADMIN_CONNECTOR_PORT" \
  --bindDN "$ROOT_USER_DN" \
  --bindPassword "$ROOT_USER_PASSWORD" \
  --batchFilePath "/dev/stdin" <<DSCONFIG_EOF

set-password-policy-prop \
  --policy-name Default\ Password\ Policy \
  --set default-password-storage-scheme:Salted\ SHA-512 \
  --set force-change-on-reset:true

DSCONFIG_EOF