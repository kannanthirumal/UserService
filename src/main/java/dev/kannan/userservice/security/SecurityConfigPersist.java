package dev.kannan.userservice.security;

/*
    This configuration is based on the official Spring Authorization Server documentation:
    https://docs.spring.io/spring-authorization-server/reference/getting-started.html

    Purpose:
    - Makes this UserService act like a third-party OAuth2 Authorization Server (similar to Google or Facebook).
    - It issues tokens and handles authorization flows for registered clients.

    Result:
    - I will get a login page, provided I have configured it correctly.
    - When I hit -> http://localhost:8080/login
*/

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import dev.kannan.userservice.security.repositories.AuthorizationConsentRepository;
import dev.kannan.userservice.security.repositories.AuthorizationRepository;
import dev.kannan.userservice.security.repositories.ClientRepository;
import dev.kannan.userservice.security.repositories.JpaRegisteredClientRepository;
import dev.kannan.userservice.security.services.JpaOAuth2AuthorizationConsentService;
import dev.kannan.userservice.security.services.JpaOAuth2AuthorizationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfigPersist {

    /**
     * Configures the security filter chain for the Authorization Server endpoints.
     * These endpoints include /oauth2/token, /.well-known/openid-configuration, etc.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                // Apply the configurer to match only authorization server endpoints
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                // Enable OpenID Connect 1.0 support
                                .oidc(Customizer.withDefaults())
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .requestMatchers("/signup").permitAll() // (1) added from "SecurityCOnfiguration" file
                                // Require authentication for all endpoints
                                .anyRequest().authenticated()
                )
                .cors().disable() // (2) added from "SecurityCOnfiguration" file
                .csrf().disable() // (3) added from "SecurityCOnfiguration" file

                // Redirect unauthenticated users to /login for HTML requests
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    /**
     * Default security configuration for other endpoints (like the login page).
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Enables form-based login
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * Simple in-memory user for authentication.
     * Username: user, Password: password
     */

    /**
     * Notes on password encoding:
     *
     * - This uses `User.builder()` instead of `withDefaultPasswordEncoder()` because the password
     *   is already BCrypt-encoded.
     *
     * Why not use `withDefaultPasswordEncoder()`?
     * - That method is only intended for quick demos/testing.
     * - It uses a simple (and insecure) default encoder that does NOT work with pre-encoded passwords.
     * - If you use it with a BCrypt-hash like this one, Spring will re-encode it — causing login failures.
     *
     * Why this works:
     * - I'm providing a BCrypt-hashed password manually.
     * - I also have a `BCryptPasswordEncoder` bean configured elsewhere (e.g., in `ApplicationConfig`).
     * - So Spring Security will correctly match the hashed password during authentication.
     *
     * TL;DR:
     * Use `User.builder()` + pre-hashed password when using a real encoder like BCrypt.
     */

    @Bean
    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("$2a$12$6xV2V9vAGXiSY7im09eM3ejk5ANY6/qRP9k3LCVM6pII98ChBxW96")
//                .roles("USER")
//                .build();

        UserDetails userDetails = User.builder()
                .username("user")
                .password("$2a$12$6xV2V9vAGXiSY7im09eM3ejk5ANY6/qRP9k3LCVM6pII98ChBxW96")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * Registers a test OAuth2 client in memory.
     * This client will be used in tools like Postman to test authorization flows.
     *
     * Note:
     * - This is not persisted to a database.
     * - You can configure clients in application.properties/yaml as well, but that's disabled for now.
     */

    /*
        commenting out the below in-memory repository since I created a "registeredClientRepository" that can persist
    */
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("oidc-client")
//                .clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("https://oauth.pstmn.io/v1/callback")
//                .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .scope("ADMIN") //I added this custom scope for my login
//                .clientSettings(ClientSettings.builder()
//                        .requireAuthorizationConsent(true) // Shows consent screen
//                        .build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient);
//    }

    /**
     * Provides a JWK (JSON Web Key) source for signing JWT tokens.
     * This key pair is generated on startup and kept in memory.
     *
     * Provides a JWK (JSON Web Key) source that Spring uses to sign and verify JWT tokens.
     *
     * Role in JWT Lifecycle:
     * - Calls generateRsaKey() to create a key pair.
     * - Wraps the RSA key pair into a JWK (standard JSON format for keys).
     * - Makes the key(s) available to Spring Authorization Server for:
     *      - Signing JWTs using the private key.
     *      - Verifying JWTs using the public key.
     *      - Exposing the public key at the /.well-known/jwks.json endpoint so clients can validate tokens.
     *
     * This acts as the bridge between the raw cryptographic key and Spring Security’s JWT handling.
     */

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Generates an RSA key pair used to sign JWT tokens.
     * This is used internally by the JWKSource.
     *
     * Generates an RSA key pair (public and private keys) used for signing JWT tokens.
     *
     * Role in JWT Lifecycle:
     * - Called at application startup.
     * - Generates a new 2048-bit RSA key pair.
     * - The private key is used to digitally sign JWTs.
     * - The public key is used to verify the JWT signature (shared with clients).
     *
     * This method only handles key creation. It does NOT expose or manage the keys for use.
     * That is handled by the jwkSource() method.
     */
    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }

    /**
     * Configures the JWT decoder used to validate and parse incoming JWT tokens.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Basic settings for the Authorization Server.
     * Uses default endpoints (e.g. /oauth2/token, /.well-known/openid-configuration)
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


    // ==============================
    // OAuth2 DB Persistence Beans
    // ==============================
    @Bean
    @Primary
    public RegisteredClientRepository registeredClientRepository(ClientRepository clientRepository) {
        return new JpaRegisteredClientRepository(clientRepository);
    }

    @Bean
    @Primary
    public OAuth2AuthorizationService authorizationService(
            AuthorizationRepository authorizationRepository,
            RegisteredClientRepository registeredClientRepository) {
        return new JpaOAuth2AuthorizationService(authorizationRepository, registeredClientRepository);
    }

    @Bean
    @Primary
    public OAuth2AuthorizationConsentService authorizationConsentService(
            AuthorizationConsentRepository authorizationConsentRepository,
            RegisteredClientRepository registeredClientRepository) {
        return new JpaOAuth2AuthorizationConsentService(authorizationConsentRepository, registeredClientRepository);
    }

}

/*
    JWT Lifecycle Summary:

    1. generateRsaKey():
        - Creates a new RSA key pair at startup.
        - Only handles key generation (raw cryptography).

    2. jwkSource():
        - Wraps the key pair into a JWKSet.
        - Used by Spring Security to:
            - Sign JWTs with private key.
            - Verify JWTs with public key.
            - Serve public key via /.well-known/jwks.json.

    Together, these enable secure issuance and validation of JWT tokens in the OAuth2 flow.
*/

/*
 * ============================
 * Postman OAuth2 Setup Reference
 * ============================
 *
 * 1. Header Prefix: -> removed "Bearer" and left it empty
 *
 * --- Configure New Token ---
 * 2. Token Name: -> token-kannan-auth-service
 * 3. Grant Type: -> Authorization Code
 *
 * 4. Callback URL: -> https://oauth.pstmn.io/v1/callback
 *
 * 5. Auth URL: -> http://localhost:8080/oauth2/authorize
 *
 * 6. Access Token URL: -> http://localhost:8080/oauth2/access-token
 *
 * 7. Client ID: -> used the default id from spring oauth dependency ->  oidc-client
 *
 * 8. Client Secret: -> used the default id from spring oauth dependency -> secret
 *
 *
 * 9. Scope: -> ADMIN (I hardcoded "ADMIN" in the scope)
 *
 * ----------------------------
 * 💡 Notes:
 * - Ensure your `redirectUri` in the registered client matches the Postman callback URL.
 * - Client must be allowed to use `authorization_code` and `refresh_token` grant types.
 * - The `scope` (e.g., ADMIN) must be registered and allowed for the client.
 */
