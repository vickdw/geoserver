package org.geoserver.security.oauth2;

import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.auth.AbstractAuthenticationProviderTest;
import org.geoserver.security.config.PreAuthenticatedUserNameFilterConfig;
import org.geoserver.security.config.SecurityFilterConfig;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.test.SystemTest;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.*;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Category(SystemTest.class)
public class OAuthAuthenticationFilterTest extends AbstractAuthenticationProviderTest {

    public final static String testFilterName = "oAuthTestFilter";

    public final static String testAccessToken = "testAccessToken";

    private RemoteTokenServices tokenServices;

    private GenericOAuth2AuthenticationProvider provider;

    private OAuth2Authentication mockAuth;

    private GeoServerOAuth2FilterConfig config;

    @Before
    public void revertFilters() throws Exception {
        GeoServerSecurityManager secMgr = getSecurityManager();
        if (secMgr.listFilters().contains(testFilterName)) {
            SecurityFilterConfig config = secMgr.loadFilterConfig(testFilterName);
            secMgr.removeFilter(config);
        }
    }

    private void initAuth(boolean redirect, boolean authenticated, String principal) throws Exception {
        config = new GeoServerOAuth2FilterConfig();
        config.setCliendId("client_id");
        config.setClientSecret("secret_id");
        config.setClassName(GeoServerOAuthAuthenticationFilter.class.getName());
        config.setName(testFilterName);
        config.setRoleSource(PreAuthenticatedUserNameFilterConfig.PreAuthenticatedUserNameRoleSource.RoleService);
        config.setEnableRedirectAuthenticationEntryPoint(redirect);
        getSecurityManager().saveFilter(config);

        mockAuth = mock(OAuth2Authentication.class);
        when(mockAuth.isAuthenticated()).thenReturn(authenticated);
        when(mockAuth.getPrincipal()).thenReturn(principal);
        tokenServices = mock(RemoteTokenServices.class);
        when(tokenServices.loadAuthentication(any(String.class))).thenReturn(mockAuth);

        provider = applicationContext.getBean(GenericOAuth2AuthenticationProvider.class);
        provider.tokenServices = tokenServices;

        prepareFilterChain(pattern,
                testFilterName);
        modifyChain(pattern, false, true, null);

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    @Test
    public void testMissingAccessToken() throws Exception {
        initAuth(false, false, null);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testMissingAccessTokenWithRedirect() throws Exception {
        initAuth(true, false, null);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_MOVED_TEMPORARILY,response.getStatus());
    }

    @Test
    public void testInvalidAccessTokenInHeader() throws Exception {
        initAuth(false, false, null);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        request.addHeader("Authorization",  "Bearer " + testAccessToken);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testInvalidAccessTokenWithRedirect() throws Exception {
        initAuth(true, false, null);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        request.addHeader("Authorization",  "Bearer " + testAccessToken);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testInvalidAccessTokenParameter() throws Exception {
        initAuth(false, false, null);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        request.setParameter(OAuth2AccessToken.ACCESS_TOKEN, testAccessToken);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testInvalidAccessTokenInCookie() throws Exception {
        initAuth(false, false, null);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(GeoServerOAuthAuthenticationFilter.SESSION_COOKIE_NAME, testAccessToken);
        request.setCookies(cookies);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testValidAccessTokenInHeader() throws Exception {
        initAuth(false, true, testUserName);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        request.addHeader("Authorization",  "Bearer " + testAccessToken);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNotNull(ctx);
        Authentication auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, auth.getPrincipal());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));
    }

    @Test
    public void testValidAccessTokenParameter() throws Exception {
        initAuth(false, true, testUserName);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        request.setParameter(OAuth2AccessToken.ACCESS_TOKEN, testAccessToken);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNotNull(ctx);
        Authentication auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, auth.getPrincipal());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));
    }

    @Test
    public void testValidAccessTokenInCookie() throws Exception {
        initAuth(false, true, testUserName);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(GeoServerOAuthAuthenticationFilter.SESSION_COOKIE_NAME, testAccessToken);
        request.setCookies(cookies);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testLogout() throws Exception {
        initAuth(false, true, testUserName);

        MockHttpServletRequest request= createRequest("/foo/bar", true);
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        request.setParameter(OAuth2AccessToken.ACCESS_TOKEN, testAccessToken);
        request.addHeader("Authorization",  "Bearer " + testAccessToken);
        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie(GeoServerOAuthAuthenticationFilter.SESSION_COOKIE_NAME, testAccessToken);
        request.setCookies(cookies);

        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNotNull(ctx);
        Authentication auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, auth.getPrincipal());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));

        GeoServerOAuthAuthenticationFilter filter = (GeoServerOAuthAuthenticationFilter) provider.createFilter(config);
        assertNotNull(filter.getAccessToken(request));
        filter.logout(request, response, auth);

        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

}
