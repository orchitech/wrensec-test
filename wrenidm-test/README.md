# Wren:IDM System Tests

Repository containing Wren:IDM system tests.


## Test Categories

* audit - _TODO_
* auth - _TODO_
* config - _TODO_
* crypto - _TODO_
* email - Email Service Features
* endpoint - Endpoint Features
* info - Info Service Features
* managed - _TODO_
* policy - _TODO_
* provisioner - Provisioner Features
* repo - _TODO_
* router - _TODO_
* scheduler - _TODO_
* scripting - _TODO_
* sync - Synchronization Features
* workflow - Workflow Features


## Running Tests

Before running any tests, make sure the following entries are in your hosts file:

```console
127.0.0.1 wrenidm.wrensecurity.local
127.0.0.1 smtp.wrensecurity.local
```

Tests can be run using the _Maven Surefire Plugin_:

```console
$ mvn test
```

You can restrict the execution of tests by specifying the name of the test class:

```console
$ mvn test -Dtest="RouteTest"
```

Tests are based on the latest Wren:IDM docker image. This image name can be overriden
with `WRENIDM_IMAGE` environment variable:

```console
$ WRENIDM_IMAGE=wrenidm-local mvn test
```

