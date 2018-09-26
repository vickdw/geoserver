/* (c) 2018 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.oauth2;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.geoserver.ows.URLMangler;
import org.geoserver.ows.URLMangler.URLType;
import org.geoserver.security.GeoServerSecurityManager;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

public class OAuth2AccessTokenURLManglerTest {

    private static final String testAccessToken = "testAccessToken";

    private URLMangler mangler;

    private OAuth2AccessToken token;

    @Before
    public void setUp() {
        GeoServerSecurityManager manager = mock(GeoServerSecurityManager.class);
        ApplicationContext context = mock(ApplicationContext.class);
        when(manager.getApplicationContext()).thenReturn(context);

        OAuth2RestTemplate template = mock(OAuth2RestTemplate.class);
        OAuth2ClientContext clientContext = mock(OAuth2ClientContext.class);
        when(template.getOAuth2ClientContext()).thenReturn(clientContext);

        Authentication auth = mock(Authentication.class);
        when(auth.isAuthenticated()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        GeoServerOAuth2SecurityConfiguration config = mock(GeoServerOAuth2SecurityConfiguration.class);
        mangler = new OAuth2AccessTokenURLMangler(manager, config, template);
        token = mock(OAuth2AccessToken.class);
        when(clientContext.getAccessToken()).thenReturn(token);
    }

    @Test
    public void testURLMangling() throws Exception {
        when(token.getTokenType()).thenReturn(OAuth2AccessToken.BEARER_TYPE);
        when(token.getValue()).thenReturn(testAccessToken);

        // layer preview-type links should not be mangled
        final Map<String, String> kvp = new HashMap<>();
        mangler.mangleURL(new StringBuilder("http://localhost:8080/geoserver/"), new StringBuilder("tiger/wms"), kvp, URLType.SERVICE);
        mangler.mangleURL(new StringBuilder("http://localhost:8080/geoserver/"), new StringBuilder("tiger/ows"), kvp, URLType.SERVICE);
        mangler.mangleURL(new StringBuilder("http://localhost:8080/geoserver/"), new StringBuilder("wms"), kvp, URLType.SERVICE);
        mangler.mangleURL(new StringBuilder("http://localhost:8080/geoserver/"), new StringBuilder("ows"), kvp, URLType.SERVICE);
        assertEquals(1, kvp.size());

        // all other links should be mangled
        assertUrlMangled("wfs", null, null);
        assertUrlMangled("wcs", null, null);
        assertUrlMangled("wfs", "request", "GetFeature");
        assertUrlMangled("ows", "service", "WMS");
        assertUrlMangled("/gwc/service/wms", null, null);
        assertUrlMangled("wms", "SERVICE", "WMS");
    }

    private void assertUrlMangled(String path, String key, String value) {
        final Map<String, String> kvp = new HashMap<>();
        if (key != null) {
            kvp.put(key, value);
        }
        mangler.mangleURL(new StringBuilder("http://localhost:8080/geoserver/"), new StringBuilder(path), kvp, URLType.SERVICE);
        assertEquals(key != null ? 2 : 1, kvp.size());
    }

}
