#!/bin/bash

set -e

SERVER_URL=http://wrenam.wrensecurity.local:8080
DEPLOYMENT_URI=/auth
BASE_DIR=/srv/wrenam

check_am() {
  status=$(curl -s $SERVER_URL$DEPLOYMENT_URI/isAlive.jsp)
  [ $? -eq 0 ] || return 1
  echo "$status"
}

init_am() {
  export CATALINA_PID="/tmp/catalina-setup.pid"

  echo "Starting Tomcat server..."
  catalina.sh start
  while ! $(check_am > /dev/null); do
    echo "Waiting Tomcat initialization..."
    sleep 2
  done

  echo "Initializing Wren:AM instance..."
  cd /opt/ssoconf
  java \
    -jar ./openam-configurator-tool.jar \
    --file "$BASE_DIR/setup/config.properties"
  while true; do
    $(check_am | grep "Server is ALIVE:" > /dev/null) && break
    echo "Waiting Wren:AM initialization..."
    sleep 2
  done

  echo "Configuring SSO Admin Tools..."
  cd /opt/ssoadm
  ./setup --path $BASE_DIR --acceptLicense

  echo "Configuring Wren:AM services..."
  cd "$BASE_DIR/setup"
  /opt/ssoadm${DEPLOYMENT_URI}/bin/ssoadm \
    do-batch \
    --adminid amadmin \
    --password-file <(echo -n "password") \
    --batchfile "config.batch"

  echo "Configuring Wren:AM keystore..."
  cp -f "$BASE_DIR/setup/auth/keystore.jceks" /srv/wrenam/auth/keystore.jceks
  cp -f "$BASE_DIR/setup/auth/.keypass" /srv/wrenam/auth/.keypass
  cp -f "$BASE_DIR/setup/auth/.storepass" /srv/wrenam/auth/.storepass

  echo "Restarting Tomcat server..."
  catalina.sh stop 15 -force
}

if [ ! -d "$BASE_DIR$DEPLOYMENT_URI" ]; then
  echo "First start..."
  init_am
fi

exec "$@"
