package com.authsignal.keycloak;

import com.authsignal.AuthsignalClient;
import com.authsignal.model.TrackAttributes;
import com.authsignal.model.TrackRequest;
import com.authsignal.model.TrackResponse;
import com.authsignal.model.UserActionState;
import com.authsignal.model.ValidateChallengeRequest;
import com.authsignal.model.ValidateChallengeResponse;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.credential.CredentialInput;

/** Authsignal Authenticator. */
public class AuthsignalAuthenticator implements Authenticator {
  private static final Logger logger = Logger.getLogger(AuthsignalAuthenticator.class.getName());

  public static final AuthsignalAuthenticator SINGLETON = new AuthsignalAuthenticator();

  private AuthsignalClient authsignalClient;

  private AuthsignalClient getAuthsignalClient(AuthenticationFlowContext context) {
    if (authsignalClient == null) {
      authsignalClient = new AuthsignalClient(secretKey(context), baseUrl(context));
    }
    return authsignalClient;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    boolean isPasskeyAutofill = false;
    
    if (config != null) {
        Object passkeyAutofillObj = config.getConfig().get(AuthsignalAuthenticatorFactory.PROP_PASSKEY_AUTOFILL);
        isPasskeyAutofill = passkeyAutofillObj != null && Boolean.parseBoolean(passkeyAutofillObj.toString());
    }

    if (isPasskeyAutofill) {
        Response challenge = context.form()
            .setAttribute("message", "Please enter your token")
            .createForm("login.ftl");
        context.challenge(challenge);
        return;
    } else {
        handleAuthenticationFlow(context);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    handleAuthenticationFlow(context);
  }

  private boolean handlePasswordAuthentication(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();
    String username = formParams.getFirst("username");
    String password = formParams.getFirst("password");

    // If user is already set (e.g., after SSO), skip password authentication
    UserModel user = context.getUser();
    if (user != null) {
        return true;
    }

    // If username is provided, try to authenticate with password
    if (username != null && !username.isEmpty()) {
        user = context.getSession().users().getUserByUsername(context.getRealm(), username);
        if (user == null) {
            user = context.getSession().users().getUserByEmail(context.getRealm(), username);
        }
        if (user == null) {
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, context.form()
                .setError("Invalid username or password")
                .createForm("login.ftl"));
            return false;
        }
        context.setUser(user);

        if (!validateCredentials(user, password)) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, context.form()
                .setError("Invalid username or password")
                .createForm("login.ftl"));
            return false;
        }
        return true;
    }

    // If neither user nor username is present, fail authentication (do NOT render login.ftl)
    context.failure(AuthenticationFlowError.INVALID_USER);
    return false;
  }

  private void handleAuthenticationFlow(AuthenticationFlowContext context) {
    AuthsignalClient client = getAuthsignalClient(context);

    MultivaluedMap<String, String> queryParams = context.getUriInfo().getQueryParameters();
    MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();

    String token = formParams.getFirst("token");
    
    if (token == null) {
        token = queryParams.getFirst("token");
    }

    if (token != null && !token.isEmpty()) {
        handleTokenValidation(context, client, token);
    } else {
        if (!handlePasswordAuthentication(context)) {
            // If password authentication fails, return early
            return;
        }
        handleAuthsignalTrack(context, client);
    }
  }

  private void handleTokenValidation(AuthenticationFlowContext context, AuthsignalClient authsignalClient, String token) {
    ValidateChallengeRequest request = new ValidateChallengeRequest();
    request.token = token;

    try {
        ValidateChallengeResponse response = authsignalClient.validateChallenge(request).get();

        if (response.state == UserActionState.CHALLENGE_SUCCEEDED || response.state == UserActionState.ALLOW) {
            String userId = response.userId;
            UserModel user = context.getSession().users().getUserById(context.getRealm(), userId);
            if (user == null) {
                context.failure(AuthenticationFlowError.INVALID_USER);
                return;
            }
            context.setUser(user);
            context.success();
        } else {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    } catch (Exception e) {
        e.printStackTrace();
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
    }
  }

  private boolean validateCredentials(UserModel user, String password) {
    CredentialInput credentialInput = UserCredentialModel.password(password);
    return user.credentialManager().isValid(credentialInput);
  }

  private void handleAuthsignalTrack(AuthenticationFlowContext context, AuthsignalClient authsignalClient) {
    String sessionCode = context.generateAccessCode();
    URI actionUri = context.getActionUrl(sessionCode);
    String redirectUrl = buildRedirectUrl(context, sessionCode, actionUri);

    TrackRequest request = createTrackRequest(context, redirectUrl);

    try {
        TrackResponse response = authsignalClient.track(request).get();
        handleTrackResponse(context, response);
    } catch (Exception e) {
        e.printStackTrace();
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
    }
  }

  private String buildRedirectUrl(AuthenticationFlowContext context, String sessionCode, URI actionUri) {
    return context.getHttpRequest().getUri().getBaseUri().toString().replaceAll("/+$", "")
        + "/realms/" + URLEncoder.encode(context.getRealm().getName(), StandardCharsets.UTF_8)
        + "/authsignal-authenticator/callback" + "?kc_client_id="
        + URLEncoder.encode(context.getAuthenticationSession().getClient().getClientId(), StandardCharsets.UTF_8)
        + "&kc_execution=" + URLEncoder.encode(context.getExecution().getId(), StandardCharsets.UTF_8)
        + "&kc_tab_id=" + URLEncoder.encode(context.getAuthenticationSession().getTabId(), StandardCharsets.UTF_8)
        + "&kc_session_code=" + URLEncoder.encode(sessionCode, StandardCharsets.UTF_8)
        + "&kc_action_url=" + URLEncoder.encode(actionUri.toString(), StandardCharsets.UTF_8);
  }

  private TrackRequest createTrackRequest(AuthenticationFlowContext context, String redirectUrl) {
    TrackRequest request = new TrackRequest();
    request.action = actionCode(context);
    request.attributes = new TrackAttributes();
    request.attributes.redirectUrl = redirectUrl;
    request.attributes.ipAddress = context.getConnection().getRemoteAddr();
    request.attributes.userAgent = context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");
    request.userId = context.getUser().getId();
    request.attributes.username = context.getUser().getUsername();
    
    // Add Keycloak groups and roles as custom attributes for use in Authsignal rules
    UserModel user = context.getUser();
    Map<String, Object> customData = new HashMap<>();
    
    // Extract user groups
    List<String> groups = user.getGroupsStream()
        .map(GroupModel::getName)
        .collect(Collectors.toList());
    if (!groups.isEmpty()) {
      customData.put("keycloakGroups", groups);
    }
    
    // Extract realm roles
    List<String> realmRoles = user.getRealmRoleMappingsStream()
        .map(RoleModel::getName)
        .collect(Collectors.toList());
    if (!realmRoles.isEmpty()) {
      customData.put("keycloakRoles", realmRoles);
    }
    
    // Extract client roles from all clients
    List<String> clientRoles = user.getRoleMappingsStream()
        .filter(role -> role.isClientRole())
        .map(RoleModel::getName)
        .collect(Collectors.toList());
    if (!clientRoles.isEmpty()) {
      customData.put("keycloakClientRoles", clientRoles);
    }
    
    if (!customData.isEmpty()) {
      request.attributes.custom = customData;
    }
    
    return request;
  }

  private void handleTrackResponse(AuthenticationFlowContext context, TrackResponse response) {
    String url = response.url;
    Response responseRedirect = Response.status(Response.Status.FOUND).location(URI.create(url)).build();
    boolean isEnrolled = response.isEnrolled;

    if (enrolByDefault(context) && !isEnrolled) {
        if (response.state == UserActionState.BLOCK) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }
        context.challenge(responseRedirect);
    } else {
        if (response.state == UserActionState.CHALLENGE_REQUIRED) {
            context.challenge(responseRedirect);
        } else if (response.state == UserActionState.BLOCK) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        } else if (response.state == UserActionState.ALLOW) {
            context.success();
        } else {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    }
  }

  @Override
  public boolean requiresUser() {
    return false;
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

  private String generateConfigErrorMessage(String prefix) {
    return prefix + " Add provider details in your Keycloak admin portal.";
  }

  private String secretKey(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null) {
      throw new IllegalStateException(
          generateConfigErrorMessage("Authsignal provider config is missing."));
    }
    Object secretKeyObj = config.getConfig().get(AuthsignalAuthenticatorFactory.PROP_SECRET_KEY);
    String tenantSecretKey = (secretKeyObj != null) ? secretKeyObj.toString() : null;

    if (tenantSecretKey == null || tenantSecretKey.isEmpty()) {
      throw new IllegalStateException(
          generateConfigErrorMessage("Authsignal Tenant Secret Key is not configured."));
    }
    return tenantSecretKey;
  }

  private String baseUrl(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null) {
      throw new IllegalStateException(
          generateConfigErrorMessage("Authsignal provider config is missing."));
    }
    Object apiUrlObj =
        config.getConfig().get(AuthsignalAuthenticatorFactory.PROP_API_HOST_BASE_URL);
    String apiUrl = (apiUrlObj != null) ? apiUrlObj.toString() : null;

    if (apiUrl == null || apiUrl.isEmpty()) {
      throw new IllegalStateException(
          generateConfigErrorMessage("Authsignal API URL is not configured."));
    }
    return apiUrl;
  }

  private String actionCode(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null) {
      return "sign-in";
    }

    Object actionCodeObj = config.getConfig().get(AuthsignalAuthenticatorFactory.PROP_ACTION_CODE);
    String actionCode = (actionCodeObj != null) ? actionCodeObj.toString() : null;

    if (actionCode == null) {
      return "sign-in";
    }
    return actionCode;
  }

  private Boolean enrolByDefault(AuthenticationFlowContext context) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null) {
      return true;
    }
    Boolean enrolByDefault = Boolean
        .valueOf(config.getConfig().get(AuthsignalAuthenticatorFactory.PROP_ENROL_BY_DEFAULT));
    return enrolByDefault;
  }
}