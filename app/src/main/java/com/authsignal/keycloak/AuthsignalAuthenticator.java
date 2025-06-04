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
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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
      logger.info("Initializing AuthsignalClient with baseUrl: " + baseUrl(context));
      authsignalClient = new AuthsignalClient(secretKey(context), baseUrl(context));
    }
    return authsignalClient;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    logger.info("Starting authentication flow");
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    boolean isPasskeyAutofill = false;
    
    if (config != null) {
        Object passkeyAutofillObj = config.getConfig().get(AuthsignalAuthenticatorFactory.PROP_PASSKEY_AUTOFILL);
        isPasskeyAutofill = passkeyAutofillObj != null && Boolean.parseBoolean(passkeyAutofillObj.toString());
        logger.info("Passkey autofill enabled: " + isPasskeyAutofill);
    }

    if (isPasskeyAutofill) {
        logger.info("Handling passkey autofill flow");
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
    logger.info("Processing authentication action");
    handleAuthenticationFlow(context);
  }

  private boolean handlePasswordAuthentication(AuthenticationFlowContext context) {
    logger.info("Starting password authentication");
    AuthsignalClient client = getAuthsignalClient(context);
    MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();
    String username = formParams.getFirst("username");
    logger.info("Attempting authentication for username: " + username);

    // If user is already set (e.g., after SSO), skip password authentication
    UserModel user = context.getUser();
    if (user != null) {
        logger.info("User already authenticated via SSO, skipping password authentication");
        context.setUser(user);
        return true;
    }

    // If there is no username and no user, skip password authentication (likely SSO)
    if ((username == null || username.isEmpty()) && user == null) {
        logger.info("No username provided and no user in context, skipping password authentication (likely SSO)");
        return true;
    }

    if (username != null && !username.isEmpty()) {
        user = context.getSession().users().getUserByUsername(context.getRealm(), username);
        if (user == null) {
            logger.info("User not found by username, trying email");
            user = context.getSession().users().getUserByEmail(context.getRealm(), username);
        }
    }

    if (user == null) {
        logger.warning("User not found for username: " + username);
        context.failureChallenge(AuthenticationFlowError.INVALID_USER, context.form()
            .setError("Invalid username or password")
            .createForm("login.ftl"));
        return false;
    }

    logger.info("User found, validating credentials");
    context.setUser(user);

    if (!validateCredentials(user, formParams.getFirst("password"))) {
        logger.warning("Invalid credentials for user: " + username);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, context.form()
            .setError("Invalid username or password")
            .createForm("login.ftl"));
        return false;
    }
    
    logger.info("Password authentication successful for user: " + username);
    return true;
  }

  private void handleAuthenticationFlow(AuthenticationFlowContext context) {
    logger.info("Handling authentication flow");
    AuthsignalClient client = getAuthsignalClient(context);

    logger.info("Authentication context details:");
    logger.info("Realm: " + context.getRealm().getName());
    logger.info("Flow: " + context.getFlowPath());
    logger.info("Context: " + context.toString());
    logger.info("Status: " + context.getStatus());
    logger.info("Client: " + (context.getConnection() != null ? context.getConnection().getRemoteAddr() : "unknown"));

    MultivaluedMap<String, String> queryParams = context.getUriInfo().getQueryParameters();
    MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();

    String token = formParams.getFirst("token");
    
    if (token == null) {
        token = queryParams.getFirst("token");
    }

    if (token != null && !token.isEmpty()) {
        logger.info("Processing token validation");
        handleTokenValidation(context, client, token);
    } else {
        logger.info("No token found, proceeding with password authentication");
        if (!handlePasswordAuthentication(context)) {
            logger.info("Password authentication failed, returning early");
            return;
        }
        logger.info("Password authentication successful, proceeding with Authsignal track");
        if (context.getUser() == null) {
            logger.warning("No user in context after authentication, cannot proceed with Authsignal track.");
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }
        handleAuthsignalTrack(context, client);
    }
  }

  private void handleTokenValidation(AuthenticationFlowContext context, AuthsignalClient authsignalClient, String token) {
    logger.info("Validating token");
    ValidateChallengeRequest request = new ValidateChallengeRequest();
    request.token = token;

    try {
        logger.info("Sending validate challenge request to Authsignal");
        ValidateChallengeResponse response = authsignalClient.validateChallenge(request).get();
        logger.info("Received validate challenge response with state: " + response.state);

        if (response.state == UserActionState.CHALLENGE_SUCCEEDED || response.state == UserActionState.ALLOW) {
            String userId = response.userId;
            logger.info("Challenge succeeded for user ID: " + userId);
            UserModel user = context.getSession().users().getUserById(context.getRealm(), userId);
            if (user == null) {
                logger.warning("User not found for ID: " + userId);
                context.failure(AuthenticationFlowError.INVALID_USER);
                return;
            }
            context.setUser(user);
            context.success();
            logger.info("Authentication successful for user: " + user.getUsername());
        } else {
            logger.warning("Challenge failed with state: " + response.state);
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
    } catch (Exception e) {
        logger.log(Level.SEVERE, "Error during token validation", e);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
    }
  }

  private boolean validateCredentials(UserModel user, String password) {
    logger.info("Validating credentials for user: " + user.getUsername());
    CredentialInput credentialInput = UserCredentialModel.password(password);
    boolean isValid = user.credentialManager().isValid(credentialInput);
    logger.info("Credential validation result: " + isValid);
    return isValid;
  }

  private void handleAuthsignalTrack(AuthenticationFlowContext context, AuthsignalClient authsignalClient) {
    logger.info("Starting Authsignal track");
    String sessionCode = context.generateAccessCode();
    URI actionUri = context.getActionUrl(sessionCode);
    String redirectUrl = buildRedirectUrl(context, sessionCode, actionUri);
    logger.info("Generated redirect URL: " + redirectUrl);

    TrackRequest request = createTrackRequest(context, redirectUrl);
    logger.info("Created track request for user: " + context.getUser().getUsername());

    try {
        logger.info("Sending track request to Authsignal");
        TrackResponse response = authsignalClient.track(request).get();
        logger.info("Received track response with state: " + response.state);
        handleTrackResponse(context, response);
    } catch (Exception e) {
        logger.log(Level.SEVERE, "Error during Authsignal track", e);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
    }
  }

  private String buildRedirectUrl(AuthenticationFlowContext context, String sessionCode, URI actionUri) {
    String redirectUrl = context.getHttpRequest().getUri().getBaseUri().toString().replaceAll("/+$", "")
        + "/realms/" + URLEncoder.encode(context.getRealm().getName(), StandardCharsets.UTF_8)
        + "/authsignal-authenticator/callback" + "?kc_client_id="
        + URLEncoder.encode(context.getAuthenticationSession().getClient().getClientId(), StandardCharsets.UTF_8)
        + "&kc_execution=" + URLEncoder.encode(context.getExecution().getId(), StandardCharsets.UTF_8)
        + "&kc_tab_id=" + URLEncoder.encode(context.getAuthenticationSession().getTabId(), StandardCharsets.UTF_8)
        + "&kc_session_code=" + URLEncoder.encode(sessionCode, StandardCharsets.UTF_8)
        + "&kc_action_url=" + URLEncoder.encode(actionUri.toString(), StandardCharsets.UTF_8);
    logger.info("Built redirect URL: " + redirectUrl);
    return redirectUrl;
  }

  private TrackRequest createTrackRequest(AuthenticationFlowContext context, String redirectUrl) {
    logger.info("Creating track request");
    TrackRequest request = new TrackRequest();
    request.action = actionCode(context);
    request.attributes = new TrackAttributes();
    request.attributes.redirectUrl = redirectUrl;
    request.attributes.ipAddress = context.getConnection().getRemoteAddr();
    request.attributes.userAgent = context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");
    request.userId = context.getUser().getId();
    request.attributes.username = context.getUser().getUsername();
    logger.info("Created track request for action: " + request.action + ", user: " + request.attributes.username);
    return request;
  }

  private void handleTrackResponse(AuthenticationFlowContext context, TrackResponse response) {
    logger.info("Handling track response with state: " + response.state);
    String url = response.url;
    Response responseRedirect = Response.status(Response.Status.FOUND).location(URI.create(url)).build();
    boolean isEnrolled = response.isEnrolled;
    logger.info("User enrolled status: " + isEnrolled);

    if (enrolByDefault(context) && !isEnrolled) {
        logger.info("Enrolling user by default");
        if (response.state == UserActionState.BLOCK) {
            logger.warning("User blocked during enrollment");
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            return;
        }
        context.challenge(responseRedirect);
    } else {
        if (response.state == UserActionState.CHALLENGE_REQUIRED) {
            logger.info("Challenge required, redirecting user");
            context.challenge(responseRedirect);
        } else if (response.state == UserActionState.BLOCK) {
            logger.warning("User blocked");
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
        } else if (response.state == UserActionState.ALLOW) {
            logger.info("User allowed, authentication successful");
            context.success();
        } else {
            logger.warning("Unexpected state: " + response.state);
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