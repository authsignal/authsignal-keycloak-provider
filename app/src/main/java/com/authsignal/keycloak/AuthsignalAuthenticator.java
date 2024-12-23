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
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** Authsignal Authenticator. */
public class AuthsignalAuthenticator implements Authenticator {
  private static final Logger logger = Logger.getLogger(AuthsignalAuthenticator.class.getName());

  public static final AuthsignalAuthenticator SINGLETON = new AuthsignalAuthenticator();

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    AuthsignalClient authsignalClient = new AuthsignalClient(secretKey(context), baseUrl(context));

    MultivaluedMap<String, String> queryParams = context.getUriInfo().getQueryParameters();
    MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();

    String token = queryParams.getFirst("token");
    if (token == null) {
      token = formParams.getFirst("token");
    }
    String userId = context.getUser().getId();
    if (userId == null) {
      userId = formParams.getFirst("userId");
    }

    if (token != null && !token.isEmpty()) {
      ValidateChallengeRequest request = new ValidateChallengeRequest();
      request.token = token;
      request.userId = userId;

      try {
        ValidateChallengeResponse response = authsignalClient.validateChallenge(request).get();
        if (response.state == UserActionState.CHALLENGE_SUCCEEDED) {
          context.success();
        } else {
          context.failure(AuthenticationFlowError.ACCESS_DENIED);
        }
      } catch (Exception e) {
        e.printStackTrace();
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
      }
    } else {
      String sessionCode = context.generateAccessCode();

      URI actionUri = context.getActionUrl(sessionCode);

      String redirectUrl =
          context.getHttpRequest().getUri().getBaseUri().toString().replaceAll("/+$", "")
              + "/realms/" + URLEncoder.encode(context.getRealm().getName(), StandardCharsets.UTF_8)
              + "/authsignal-authenticator/callback" + "?kc_client_id="
              + URLEncoder.encode(context.getAuthenticationSession().getClient().getClientId(),
                  StandardCharsets.UTF_8)
              + "&kc_execution="
              + URLEncoder.encode(context.getExecution().getId(), StandardCharsets.UTF_8)
              + "&kc_tab_id="
              + URLEncoder.encode(context.getAuthenticationSession().getTabId(),
                  StandardCharsets.UTF_8)
              + "&kc_session_code=" + URLEncoder.encode(sessionCode, StandardCharsets.UTF_8)
              + "&kc_action_url=" + URLEncoder.encode(actionUri.toString(), StandardCharsets.UTF_8);

      TrackRequest request = new TrackRequest();
      request.action = actionCode(context);

      request.attributes = new TrackAttributes();
      request.attributes.redirectUrl = redirectUrl;
      request.attributes.ipAddress = context.getConnection().getRemoteAddr();
      request.attributes.userAgent =
          context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");
      request.userId = context.getUser().getId();

      try {
        CompletableFuture<TrackResponse> responseFuture = authsignalClient.track(request);

        TrackResponse response = responseFuture.get();

        String url = response.url;

        Response responseRedirect =
            Response.status(Response.Status.FOUND).location(URI.create(url)).build();

        boolean isEnrolled = response.isEnrolled;

        // If the user is not enrolled (has no authenticators) and enrollment by default
        // is enabled,
        // display the challenge page to allow the user to enroll.
        if (enrolByDefault(context) && !isEnrolled) {
          if (response.state == UserActionState.BLOCK) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
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

      } catch (Exception e) {
        e.printStackTrace();
        context.failure(AuthenticationFlowError.INTERNAL_ERROR);
      }
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    logger.info("Action method called");
    // No-op
  }

  @Override
  public boolean requiresUser() {
    logger.info("requiresUser method called");
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    logger.info("configuredFor method called");
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    logger.info("setRequiredActions method called");
    // No required actions
  }

  @Override
  public void close() {
    logger.info("close method called");
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
