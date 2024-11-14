To add to Keycloak:

./gradlew build

Take the generated app/build/libs/app-1.0.0.jar and add it to the Keycloak server's providers directory.

In your keycloak server

./bin/kc.sh build

./bin/kc.sh start-dev

To include dependencies in the keycloak server, add download the jar from maven central and add it to the server's providers directory.

e.g:
mvn dependency:get -Dartifact=com.authsignal:authsignal-java:1.0.0 -Ddest=path/to/directory

This will be located in:

~/.m2/repository/com/authsignal/authsignal-java/1.0.0/

Copy the authsignal-java-1.0.0.jar file to the keycloak server's providers directory.
