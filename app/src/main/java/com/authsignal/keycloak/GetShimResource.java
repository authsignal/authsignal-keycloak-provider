package com.authsignal.keycloak;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import org.keycloak.common.util.HtmlUtils;
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

    if (!queryParams.containsKey("kc_session_code") || !queryParams.containsKey("token")) {
      URI actionUrl =
          UriBuilder.fromUri(uriInfo.getBaseUri())
              .path("realms/{realm}/login-actions/authenticate")
              .queryParam("execution", "{execution}")
              .queryParam("client_id", "{clientId}")
              .queryParam("tab_id", "{tabId}")
              .build(realm, authenticationExecution, clientId, tabId);
      return Response.temporaryRedirect(actionUrl).build();
    }

    String sessionCode = queryParams.getFirst("kc_session_code");
    String token = queryParams.getFirst("token");
    URI kcActionUrl = validateActionUrl(queryParams.getFirst("kc_action_url"), uriInfo, realm);
    if (kcActionUrl == null) {
      return Response.status(400).type(MediaType.TEXT_PLAIN).entity("Invalid kc_action_url").build();
    }

    String formAction =
        UriBuilder.fromUri(kcActionUrl)
            .replaceQueryParam("session_code", "{sessionCode}")
            .build(sessionCode)
            .toString();

    String redirect =
        "<html><body onload=\"document.forms[0].submit()\"><form id=\"form1\" action=\""
            + HtmlUtils.escapeAttribute(formAction)
            + "\" method=\"post\"><input type=\"hidden\" name=\"actionExecution\" value=\""
            + HtmlUtils.escapeAttribute(authenticationExecution)
            + "\"><input type=\"hidden\" name=\"token\" value=\""
            + HtmlUtils.escapeAttribute(token)
            + "\"><noscript><input type=\"submit\" value=\"Continue\"></noscript></form>"
            + "</body></html>";
    return Response.ok(redirect)
        .header("Cache-Control", "no-store")
        .header("Referrer-Policy", "no-referrer")
        .build();
  }

  private static URI validateActionUrl(String value, UriInfo uriInfo, String realm) {
    if (value == null) {
      return null;
    }
    URI uri;
    try {
      uri = new URI(value);
    } catch (URISyntaxException exception) {
      return null;
    }
    URI base = uriInfo.getBaseUri();
    if (!uri.isAbsolute()
        || uri.isOpaque()
        || uri.getRawUserInfo() != null
        || uri.getRawFragment() != null
        || uri.getHost() == null
        || !uri.getScheme().equalsIgnoreCase(base.getScheme())
        || !uri.getHost().equalsIgnoreCase(base.getHost())
        || effectivePort(uri) != effectivePort(base)) {
      return null;
    }
    String path = uri.getPath();
    String basePath = base.getPath() == null ? "" : base.getPath().replaceAll("/+$", "");
    if (path == null || !path.startsWith(basePath + "/realms/" + realm + "/login-actions/")) {
      return null;
    }
    for (String segment : path.split("/")) {
      if (segment.equals(".") || segment.equals("..")) {
        return null;
      }
    }
    return uri;
  }

  private static int effectivePort(URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }

  /** AuthenticationSessionModel. */
  public AuthenticationSessionModel getAuthenticationSessionByIdAndClient(
      RealmModel realm, String authSessionId, ClientModel client, String tabId) {
    RootAuthenticationSessionModel rootAuthSession =
        session.authenticationSessions().getRootAuthenticationSession(realm, authSessionId);
    return rootAuthSession == null ? null : rootAuthSession.getAuthenticationSession(client, tabId);
  }
}
