package com.authsignal.keycloak;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/** Class for creating GetShimResource. */
public class GetShimResource {
  private final KeycloakSession session;

  public GetShimResource(KeycloakSession session) {
    this.session = session;
  }

  /** Handles the callback for the authentication process. */
  @GET
  @Path("/callback")
  @Produces(MediaType.TEXT_HTML)
  public Response get() {
    KeycloakContext context = session.getContext();
    String realm = "";

    try {
      realm = context.getRealm().getName();
    } catch (Exception exception) {
      // leave realm blank
    }

    UriInfo uriInfo = context.getUri();
    MultivaluedMap<String, String> queryParams = uriInfo.getQueryParameters();
    if (realm.equalsIgnoreCase("")
        || !queryParams.containsKey("kc_execution")
        || !queryParams.containsKey("kc_client_id")
        || !queryParams.containsKey("kc_tab_id")) {
      // these fields are required, throw a bad request error
      return Response.status(400).build();
    }

    String authenticationExecution = queryParams.getFirst("kc_execution");
    String clientId = queryParams.getFirst("kc_client_id");
    String tabId = queryParams.getFirst("kc_tab_id");
    String actionUrl =
        uriInfo.getBaseUri().toString() + "realms/" + realm + "/login-actions/authenticate";
    actionUrl = actionUrl + "?execution=" + authenticationExecution;
    actionUrl = actionUrl + "&client_id=" + clientId;
    actionUrl = actionUrl + "&tab_id=" + tabId;

    if (!queryParams.containsKey("kc_session_code") || !queryParams.containsKey("token")) {
      try {
        return Response.temporaryRedirect(new URI(actionUrl)).build();
      } catch (URISyntaxException exception) {
        return Response.serverError().build();
      }
    }

    String sessionCode = queryParams.getFirst("kc_session_code");
    String token = queryParams.getFirst("token");
    String kcActionUrl = queryParams.getFirst("kc_action_url");

    kcActionUrl = kcActionUrl + "&session_code=" + sessionCode;
    kcActionUrl = kcActionUrl + "&token=" + token;

    String redirect =
        "<html><body onload=\"document.forms[0].submit()\"><form id=\"form1\" action=\""
            + kcActionUrl
            + "\" method=\"post\"><input type=\"hidden\" name=\"actionExecution\" value=\""
            + authenticationExecution
            + "\"><noscript><input type=\"submit\" value=\"Continue\"></noscript></form>"
            + "</body></html>";
    return Response.ok(redirect).build();
  }

  /** AuthenticationSessionModel. */
  public AuthenticationSessionModel getAuthenticationSessionByIdAndClient(
      RealmModel realm, String authSessionId, ClientModel client, String tabId) {
    RootAuthenticationSessionModel rootAuthSession =
        session.authenticationSessions().getRootAuthenticationSession(realm, authSessionId);
    return rootAuthSession == null ? null : rootAuthSession.getAuthenticationSession(client, tabId);
  }
}
