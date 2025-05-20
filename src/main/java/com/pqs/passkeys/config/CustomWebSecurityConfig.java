package com.pqs.passkeys.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService;
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.List;

@Configuration
@EnableWebSecurity
public class CustomWebSecurityConfig {

    private final Log logger = LogFactory.getLog(getClass());

    @Autowired
    private ApplicationContext applicationContext;

    @Bean
    public WebAuthnAuthenticationProvider webAuthnAuthenticationProvider(WebAuthnAuthenticatorService authenticatorService, WebAuthnManager webAuthnManager) {
        return new WebAuthnAuthenticationProvider(authenticatorService, webAuthnManager);
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
        return new ProviderManager(providers);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            // ignore static resources
            web.ignoring().requestMatchers(
                    "/favicon.ico",
                    "/js/**",
                    "/css/**",
                    "/webjars/**");
        };
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // WebAuthn Login
        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
                .defaultSuccessUrl("/", true)
                .failureHandler((request, response, exception) -> {
                    logger.error("Login error", exception);
                    response.sendRedirect("/login?error=Login failed: " + exception.getMessage());
                })
                .attestationOptionsEndpoint()
                .rp()
                .name("WebAuthn4J Passkeys Demo")
                .and()
                .pubKeyCredParams(
                        // supported algorithms for cryptography
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
                )
                .attestation(AttestationConveyancePreference.DIRECT)
                .extensions()
                .uvm(true)
                .credProps(true)
                .extensionProviders()
                .and()
                .assertionOptionsEndpoint()
                .extensions()
                .extensionProviders();

        http.headers(headers -> {
            // 'publickey-credentials-get *' allows getting WebAuthn credentials to all nested browsing contexts (iframes) regardless of their origin.
            headers.permissionsPolicy(config -> config.policy("publickey-credentials-get *"));
            // Disable "X-Frame-Options" to allow cross-origin iframe access
            headers.frameOptions(Customizer.withDefaults()).disable();
        });


        // Authorization
        http.authorizeHttpRequests(authz -> authz
                .requestMatchers(HttpMethod.GET, "/login").permitAll()
                .requestMatchers(HttpMethod.POST, "/signup").permitAll()
                .anyRequest().access(getWebExpressionAuthorizationManager("@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication)"))
        );

        http.exceptionHandling(eh -> eh.accessDeniedHandler((request, response, accessDeniedException) -> {
            logger.error("Access denied", accessDeniedException);
            response.sendRedirect("/login");
        }));

        http.authenticationManager(authenticationManager);

        // As WebAuthn has its own CSRF protection mechanism (challenge), CSRF token is disabled here
        http.csrf(csrf -> {
            csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
            csrf.ignoringRequestMatchers("/webauthn/**");
        });

        return http.build();

    }

    private WebExpressionAuthorizationManager getWebExpressionAuthorizationManager(final String expression) {
        var expressionHandler = new DefaultHttpSecurityExpressionHandler();
        expressionHandler.setApplicationContext(applicationContext);
        var authorizationManager = new WebExpressionAuthorizationManager(expression);
        authorizationManager.setExpressionHandler(expressionHandler);
        return authorizationManager;
    }
}

