To add to Keycloak:

./gradlew build

Take the generated app/build/libs/app-1.0.0.jar and add it to the Keycloak server's providers directory.

In your keycloak server

./bin/kc.sh build

./bin/kc.sh start-dev
