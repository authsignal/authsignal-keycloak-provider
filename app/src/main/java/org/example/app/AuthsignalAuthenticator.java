package com.keycloak.providers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;

public class AuthsignalAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Authenticating with Authsignal");
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Handle MFA verification response here
        // Example: Check if the MFA code provided by the user is valid
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // Cleanup if needed
    }
}