package com.authsignal.keycloak;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory class for creating instances of GetShimResourceProvider.
 */
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
    return new GetShimResourceProvider(keycloakSession);
  }

  @Override
  public void init(Scope scope) {}

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {}

  @Override
  public void close() {}
}
