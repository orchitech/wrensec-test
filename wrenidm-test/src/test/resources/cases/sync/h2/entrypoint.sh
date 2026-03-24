#!/bin/bash

java -cp /h2/h2.jar org.h2.tools.RunScript -url "jdbc:h2:~/wrenidm" -user wrenidm -password wrenidm -script /h2/schema.sql

exec java -cp /h2/h2.jar org.h2.tools.Server -web -webAllowOthers -tcp -tcpAllowOthers
