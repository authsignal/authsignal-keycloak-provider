package com.authsignal.keycloak;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory class for creating Authsignal authenticator instances. Implements AuthenticatorFactory to
 * provide configuration and lifecycle management for the Authsignal authentication mechanism in
 * Keycloak.
 */
public class AuthsignalAuthenticatorFactory implements AuthenticatorFactory {
  public static final String PROVIDER_ID = "authsignal-authenticator";

  public static final String PROP_SECRET_KEY = "authsignal.secretKey";
  public static final String PROP_TENANT_ID = "authsignal.tenantId";
  public static final String PROP_API_HOST_BASE_URL = "authsignal.baseUrl";
  public static final String PROP_ACTION_CODE = "authsignal.actionCode";
  public static final String PROP_ENROL_BY_DEFAULT = "authsignal.enrolByDefault";
  public static final String PROP_PASSKEY_AUTOFILL = "passkey-autofill";

  private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES =
      {AuthenticationExecutionModel.Requirement.REQUIRED,
          AuthenticationExecutionModel.Requirement.DISABLED};

  private static final Logger logger = Logger.getLogger(AuthsignalAuthenticator.class.getName());

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  private static final List<ProviderConfigProperty> configProperties =
      new ArrayList<ProviderConfigProperty>();

  static {
    ProviderConfigProperty secretKey = new ProviderConfigProperty();
    secretKey.setName(PROP_SECRET_KEY);
    secretKey.setLabel("Authsignal Tenant Secret Key");
    secretKey.setType(ProviderConfigProperty.PASSWORD);
    secretKey.setHelpText("Secret key from Authsignal admin portal");
    configProperties.add(secretKey);

    ProviderConfigProperty baseUrl = new ProviderConfigProperty();
    baseUrl.setName(PROP_API_HOST_BASE_URL);
    baseUrl.setLabel("Authsignal API URL");
    baseUrl.setType(ProviderConfigProperty.STRING_TYPE);
    baseUrl.setHelpText("API URL from Authsignal admin portal");
    configProperties.add(baseUrl);

    ProviderConfigProperty tenantId = new ProviderConfigProperty();
    tenantId.setName(PROP_TENANT_ID);
    tenantId.setLabel("Authsignal Tenant ID");
    tenantId.setType(ProviderConfigProperty.STRING_TYPE);
    tenantId.setHelpText("Tenant ID from Authsignal admin portal");
    configProperties.add(tenantId);

    ProviderConfigProperty actionCode = new ProviderConfigProperty();
    actionCode.setName(PROP_ACTION_CODE);
    actionCode.setLabel("Action code");
    actionCode.setType(ProviderConfigProperty.STRING_TYPE);
    actionCode.setHelpText("Optional: Set your own action code, defaults to sign-in");
    configProperties.add(actionCode);

    ProviderConfigProperty enrolByDefault = new ProviderConfigProperty();
    enrolByDefault.setName(PROP_ENROL_BY_DEFAULT);
    enrolByDefault.setLabel("Enroll by default");
    enrolByDefault.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    enrolByDefault.setDefaultValue(true);
    enrolByDefault.setHelpText("Optional: Auto enroll user if no authenticators "
        + "are available i.e. the user is not enrolled. Defaults to true.");
    configProperties.add(enrolByDefault);

    ProviderConfigProperty passkeyAutofill = new ProviderConfigProperty();
    passkeyAutofill.setName(PROP_PASSKEY_AUTOFILL);
    passkeyAutofill.setLabel("Enable Passkey Autofill");
    passkeyAutofill.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    passkeyAutofill.setDefaultValue(false);
    passkeyAutofill.setHelpText("Optional: Enable passkey autofill functionality. Defaults to false.");
    configProperties.add(passkeyAutofill);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return AuthsignalAuthenticator.SINGLETON;
  }

  @Override
  public String getDisplayType() {
    return "Authsignal Authenticator";
  }

  @Override
  public String getReferenceCategory() {
    return "MFA";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Drop-in MFA provided by Authsignal";
  }

  @Override
  public void init(Config.Scope scope) {}

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
