# Wren:IG System Tests

Repository containing Wren:IG system tests.

## Test Categories

* auth - _TODO_
  * auth-oauth2 - _TODO_
  * auth-oicd - _TODO_
  * auth-saml2 - SAML 2.0 Service Provider
* expression - Expression language features
* monitoring - _TODO_
* password-replay - _TODO_
* route - Route-related features
* scripting - Script-related features
* uma - _TODO_

## Running Tests

Before running any tests, make sure the following entries are in your hosts file:

```console
127.0.0.1 wrenig.wrensecurity.local
127.0.0.1 wrenam.wrensecurity.local
```

Tests can be run using the _Maven Surefire Plugin_:

```console
$ mvn test
```

You can restrict the execution of tests by specifying the name of the test class:

```console
$ mvn test -Dtest="RouteTest"
```

Tests are based on the latest Wren:IG docker image. This image name can be overriden
with `WRENIG_IMAGE` environment variable:

```console
$ WRENIG_IMAGE=wrenig-local mvn test
```
