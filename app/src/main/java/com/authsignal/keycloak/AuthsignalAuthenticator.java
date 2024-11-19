package com.authsignal.keycloak;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.connections.httpclient.HttpClientProvider;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.AbstractAuthenticationFlowContext;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;

import com.authsignal.model.TrackRequest;
import com.authsignal.model.TrackResponse;
import com.authsignal.AuthsignalClient;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

public class AuthsignalAuthenticator implements Authenticator {
    private String baseUrl = "https:// dev-signal.authsignal.com/v1";
    private String secret = "nn4OBTWLrdXpc3102b2Ntq+6xEytGsTBjakBqiErRrFJnj2GkPUQsQ==";

    AuthsignalClient authsignalClient = new AuthsignalClient(
            "nn4OBTWLrdXpc3102b2Ntq+6xEytGsTBjakBqiErRrFJnj2GkPUQsQ==", "https://dev-signal.authsignal.com/v1");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Authenticating with Authsignal!!");

        String token = context.getHttpRequest().getUri().getQueryParameters().getFirst("token");

        if (token != null && !token.isEmpty()) {
            // do validation
            context.success();
        } else {
            System.out.println("userID: " + context.getUser().getId());

            MultivaluedMap<String, String> queryParams = context.getHttpRequest().getUri().getQueryParameters();

            String sessionCode = queryParams.getFirst("session_code");

            System.out.println("sessionCode: " + sessionCode);

            String redirectUrl = context.getHttpRequest().getUri().getBaseUri().toString().replaceAll("/+$", "") +
                    "/realms/" + URLEncoder.encode(context.getRealm().getName(), StandardCharsets.UTF_8) +
                    "/authsignal-authenticator/callback" +
                    "?kc_client_id="
                    + URLEncoder.encode(context.getAuthenticationSession().getClient().getClientId(),
                            StandardCharsets.UTF_8)
                    +
                    "&kc_execution=" + URLEncoder.encode(context.getExecution().getId(), StandardCharsets.UTF_8) +
                    "&kc_tab_id="
                    + URLEncoder.encode(context.getAuthenticationSession().getTabId(), StandardCharsets.UTF_8)
                    +
                    "&kc_session_code=" + URLEncoder.encode(sessionCode, StandardCharsets.UTF_8);

            TrackRequest request = new TrackRequest();
            request.action = "action";
            request.userId = context.getUser().getId();
            request.redirectUrl = redirectUrl;

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
            // context.success();
        }

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