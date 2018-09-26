package org.geoserver.security.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

import java.util.Arrays;

/**
 * Generic REST template for OAuth2 protocol.
 * <p>
 * The procedure will provide a new <b>Client ID</b>, <b>Client Secret</b> and <b>Auth Domain</b>
 * </p>
 * <p>
 * The user must specify the <b>Redirect URIs</b> pointing to the GeoServer instance<br/>
 * Example:
 * <ul>
 * <li>http://localhost:8080/geoserver</li>
 * <li>https://localhost:8080/geoserver/</li>
 * </ul>
 * </p>
 * <p>
 * The generic OAuth2 Filter endpoint can automatically redirect the users at first login <br/>
 * </p>
 */
@Configuration(value="genericOAuth2SecurityConfiguration")
@EnableOAuth2Client
public class GenericOAuth2SecurityConfiguration extends GeoServerOAuth2SecurityConfiguration {

    @Bean(name="genericOAuth2Resource")
    public OAuth2ProtectedResourceDetails geoServerOAuth2Resource() {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setId("generic-oauth2-client");

        details.setGrantType("authorization_code");
        details.setAuthenticationScheme(AuthenticationScheme.header);
        details.setClientAuthenticationScheme(AuthenticationScheme.form);

        return details;
    }

    /**
     * Must have "session" scope
     */
    @Bean(name="genericOauth2RestTemplate")
    @Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
    public OAuth2RestTemplate geoServerOauth2RestTemplate() {

        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(geoServerOAuth2Resource(),
                new DefaultOAuth2ClientContext(getAccessTokenRequest()));

        AuthorizationCodeAccessTokenProvider authorizationCodeAccessTokenProvider = new AuthorizationCodeAccessTokenProvider();
        authorizationCodeAccessTokenProvider.setStateMandatory(false);

        AccessTokenProvider accessTokenProviderChain = new AccessTokenProviderChain(
                Arrays.<AccessTokenProvider> asList(authorizationCodeAccessTokenProvider,
                        new ImplicitAccessTokenProvider(),
                        new ResourceOwnerPasswordAccessTokenProvider(),
                        new ClientCredentialsAccessTokenProvider()));

        oAuth2RestTemplate.setAccessTokenProvider(accessTokenProviderChain);

        return oAuth2RestTemplate;
    }
}
