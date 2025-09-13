package dev.kannan.userservice.security;

import java.util.UUID;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * This component initializes and registers default OAuth2 clients into the database
 * when the Spring Boot application starts.
 *
 * It checks if a client with a specific clientId (e.g., "oidc-client") already exists,
 * and if not, creates and persists a RegisteredClient instance with predefined
 * authentication methods, grant types, scopes, and client settings.
 *
 * This allows the application to have default OAuth2 clients available for authorization
 * flows, replacing the in-memory client registration used in development/testing environments.
 *
 * Using CommandLineRunner ensures this setup happens exactly once per application startup.
 */


@Component
public class ClientSetupRunner implements CommandLineRunner {

    private final RegisteredClientRepository registeredClientRepository;

    public ClientSetupRunner(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        if (registeredClientRepository.findByClientId("oidc-client") == null) {
            RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("ADMIN")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

            registeredClientRepository.save(oidcClient);
            System.out.println("Default client registered");
        }
    }
}
