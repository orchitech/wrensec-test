# Setup for mTLS authentication

## Certification authority

CA certificate:

```sh
openssl req -x509 -sha256 -days 36500 -newkey rsa:4096 -nodes -subj "/O=Wren Security/CN=TEST CA" -keyout ca.key -out ca.crt
```

JKS truststore:

```sh
keytool -import -keystore truststore -storepass changeit  -storetype JKS -file ca.crt -alias test-ca
```


## Server certificate

Create certificate:

```sh
openssl req -newkey rsa:4096 -nodes -subj "/O=Wren Security/CN=*.wrensecurity.local" -keyout ssl-server.key -out ssl-server.csr

cat << EOF > ssl-server.cnf                                                                                                          
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
EOF

horal@Pavel--MacBook-Pro mtls % openssl x509 -req -CA ca.crt -CAkey ca.key -in ssl-server.csr -out ssl-server.crt -days 36500 -CAcreateserial -extfile ssl-server.cnf
```

P12 keystore:

```sh
openssl pkcs12 -export -in "ssl-server.crt" -inkey "ssl-server.key" -name "openidm-localhost" -out ssl-server.p12 -passout pass:changeit
```

JCEKS keystore:

```sh
keytool -importkeystore -srckeystore ssl-server.p12 -srcstoretype PKCS12 -srcstorepass changeit -destkeystore keystore.jceks -deststoretype JCEKS -deststorepass changeit
```


## User certificate

User certificate:

```sh
openssl req -newkey rsa:4096 -nodes -subj "/O=Wren Security/OU=Users/CN=${WRENIDM_USER}" -keyout "user-${WRENIDM_USER}.key" -out "user-${WRENIDM_USER}.csr"
```

```sh
openssl x509 -req -CA ca.crt -CAkey ca.key -in "user-${WRENIDM_USER}.csr" -out "user-${WRENIDM_USER}.crt" -days 36500 -CAcreateserial
```


P12 keystore:

```sh
openssl pkcs12 -export -in "user-${WRENIDM_USER}.crt" -inkey "user-${WRENIDM_USER}.key" -name "user-${WRENIDM_USER}" -out user-${WRENIDM_USER}.p12 -passout pass:changeit
```
