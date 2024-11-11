package com.keycloak.providers;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.Config;

import java.util.List;

public class AuthsignalAuthenticatorFactory implements AuthenticatorFactory {

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return List.of(AuthenticationExecutionModel.Requirement.REQUIRED)
                .toArray(new AuthenticationExecutionModel.Requirement[0]);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        System.out.println("Creating new AuthsignalAuthenticator instance");
        return new AuthsignalAuthenticator();
    }

    @Override
    public String getDisplayType() {
        return "Authsignal Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "getReferenceCategory";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "getHelpText";
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "authsignal-authenticator";
    }
}