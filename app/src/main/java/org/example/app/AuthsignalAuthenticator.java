package com.keycloak.providers;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.connections.httpclient.HttpClientProvider;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AbstractAuthenticationFlowContext;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;

import com.authsignal.model.TrackRequest;
import com.authsignal.model.TrackResponse;
import com.authsignal.AuthsignalClient;

import java.net.URI;
import java.net.http.HttpRequest;
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

        // Object email = context.getHttpRequest();

        try {
            CompletableFuture<TrackResponse> responseFuture = authsignalClient.track(request);

            TrackResponse response = responseFuture.get();

            String url = response.url;

            System.out.println("URL: " + url);

            Response responseRedirect = Response.status(Response.Status.FOUND)
                    .location(URI.create(url))
                    .build();

            context.challenge(responseRedirect);
            System.out.println("challenge set");

        } catch (Exception e) {
            e.printStackTrace();
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
        System.out.println("Success");
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        System.out.println("Action method called");
        // Handle MFA verification response here
        // Example: Check if the MFA code provided by the user is valid
    }

    @Override
    public boolean requiresUser() {
        System.out.println("requiresUser method called");
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        System.out.println("configuredFor method called");
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        System.out.println("setRequiredActions method called");
        // No required actions
    }

    @Override
    public void close() {
        System.out.println("close method called");
        // Cleanup if needed
    }
}