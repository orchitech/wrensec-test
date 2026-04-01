# Wren:AM System Tests

Wren:AM system tests for ensuring release stability.


## Running

```bash
# Run all tests
mvn test -pl wrenam-test -am

# Use a different AM image
mvn test -pl wrenam-test -am -Dwrenam.image=wrenam:my-branch

# Run a single test class
mvn test -pl wrenam-test -am -Dtest=AuthDataStoreTest
```
