package com.lungesoft.architecture.web.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableOAuth2Client
public class OAuthSecurityClientConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Bean
    public OAuth2ClientContextFilter oAuth2ClientContextFilter() {
        return new OAuth2ClientContextFilter();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.logout().and().authorizeRequests()
                .antMatchers("/index.html",
                        "/",
                        "/resource/rest/**",
                        "/oauth/**",
                        "/auth/**",
                        "/oauth").permitAll().anyRequest()
                .authenticated()
                .and()
                .addFilterAfter(oAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(oauth2ClientAuthenticationProcessingFilter(), BasicAuthenticationFilter.class)
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
        http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
            if (authException != null) {
                response.sendRedirect(request.getContextPath() + "/oauth");
            }
        });
    }

    private OAuth2ClientAuthenticationProcessingFilter oauth2ClientAuthenticationProcessingFilter() {
        OAuth2ClientAuthenticationProcessingFilter oauthFilter = new OAuth2ClientAuthenticationProcessingFilter("/oauth");
        OAuth2RestTemplate ssoTemplate = new OAuth2RestTemplate(settings(), oauth2ClientContext);
        oauthFilter.setRestTemplate(ssoTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(ssoResource().getUserInfoUri(), settings().getClientId());
        tokenServices.setRestTemplate(ssoTemplate);
        oauthFilter.setTokenServices(tokenServices);
        return oauthFilter;
    }

    @Bean
    @ConfigurationProperties("oauth.client")
    public AuthorizationCodeResourceDetails settings() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("oauth.resource")
    public ResourceServerProperties ssoResource() {
        return new ResourceServerProperties();
    }
}
