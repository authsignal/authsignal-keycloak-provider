package com.authsignal.keycloak.getshim;

import com.authsignal.keycloak.AuthsignalAuthenticatorFactory;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class GetShimProviderFactory implements RealmResourceProviderFactory {

    @Override
    public String getId() {
        return AuthsignalAuthenticatorFactory.PROVIDER_ID;
    }

    @Override
    public int order() {
        return 0;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new GetShimProvider(keycloakSession);
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
}