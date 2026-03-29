.test# Test Federation

Setup for test federation is fairly simple. The test subject is a *local* Wren:AM deployment
shared by all tests that use hostname *wrenam.wrensecurity.test*. For the *remote* part there
is a different Wren:AM instance using the hostname *wrenam.wrensecurity.remote*.

Each deployment hosts a single IdP and single SP. Keystore material is shared between both
*local* and *remote* where there are two keypairs *test-local* and *test-remote*, each being
exclusively used by the respective federation side.
