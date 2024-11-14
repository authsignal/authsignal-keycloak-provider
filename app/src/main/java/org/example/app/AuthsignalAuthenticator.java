package com.keycloak.providers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;

import com.authsignal.model.TrackRequest;
import com.authsignal.model.TrackResponse;
import com.authsignal.AuthsignalClient;

import java.util.concurrent.CompletableFuture;

public class AuthsignalAuthenticator implements Authenticator {
    private String baseUrl = "https:// dev-signal.authsignal.com/v1";
    private String secret = "nn4OBTWLrdXpc3102b2Ntq+6xEytGsTBjakBqiErRrFJnj2GkPUQsQ==";

    AuthsignalClient authsignalClient = new AuthsignalClient(
            "nn4OBTWLrdXpc3102b2Ntq+6xEytGsTBjakBqiErRrFJnj2GkPUQsQ==", "https://dev-signal.authsignal.com/v1");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Authenticating with Authsignal");
        TrackRequest request = new TrackRequest();
        request.userId = "userId";
        request.action = "action";

        try {
            CompletableFuture<TrackResponse> response = authsignalClient.track(request);
            context.success();
        } catch (Exception e) {
            e.printStackTrace();
        }
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