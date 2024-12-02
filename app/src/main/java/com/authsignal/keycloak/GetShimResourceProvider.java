package com.authsignal.keycloak;

import jakarta.ws.rs.ext.Provider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/** Class for creating instances of GetShimResourceProvider. */
@Provider
public class GetShimResourceProvider implements RealmResourceProvider {

  private KeycloakSession session;

  public GetShimResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return new GetShimResource(session);
  }

  @Override
  public void close() {}
}
