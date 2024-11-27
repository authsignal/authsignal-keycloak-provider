# Authsignal Key Cloak Authenticator - Enable MFA and Passkeys for Keycloak
Authenticator for [Keycloak](https://github.com/keycloak/keycloak) that uses Authsignal's [Pre-built UI](https://docs.authsignal.com/scenarios/launching-the-prebuilt-ui) to challenge the user for MFA/Passworldess/Passkeys as part of a Keycloak login flow.

This has been tested against Keycloak 26+ (Quarkus) and Java 18+.

## How to use
### Install the authenticator extension
1. Build or download the pre-built "authsignal-v*.jar" JAR file.
2. Download the Authsignal (version 2.0+) Java SDK (dependency) JAR file from [maven](https://mvnrepository.com/artifact/com.authsignal/authsignal-java)
3. Copy the above two JAR files to your keycloak server `/providers/` directory


### Configure the authenticator
Please view our [official Keycloak configuration documentation](https://docs.authsignal.com/integrations/keycloak)


## Building on your computer
You should be able to build and package this project using Gradle. The gradle command will compile the source code and build the JAR files for you. 

`./gradlew build`

You will need to use the output JAR `app/build/libs/authsignal-v*.jar`  and copy it to your Keycloak server's `/providers` directory