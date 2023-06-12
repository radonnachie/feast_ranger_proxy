package za.co.discovery.health.bigdata.ranger.feast;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.GlobalSunJaasKerberosConfig;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.client.config.SunJaasKrb5LoginConfig;
import org.springframework.security.kerberos.client.ldap.KerberosLdapContextSource;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private static final String MLFLOW_ROLE = "MlflowUser";
    @Value("${app.ad-domain}")
    private String adDomain;

    @Value("${app.ad-server}")
    private String adServer;

    @Value("${app.service-principal}")
    private String servicePrincipal;

    @Value("${app.keytab-location}")
    private String keytabLocation;

    @Value("${app.ldap-search-base}")
    private String ldapSearchBase;

    @Value("${app.ldap-search-filter}")
    private String ldapSearchFilter;

    private static final String[] STATIC_RESOURCES = new String[] {
            "/**.js", "/**.css", "/**.map",
            "/**.png", "/**.jpg", "/favicon.ico",
            "/**.woff2", "/**.otf", "/access-denied", "login"
    };



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider = kerberosServiceAuthenticationProvider();
        ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider = activeDirectoryLdapAuthenticationProvider();
        ProviderManager providerManager = new ProviderManager(kerberosServiceAuthenticationProvider,
                activeDirectoryLdapAuthenticationProvider);

        http

                .authorizeHttpRequests((authz) -> authz

                        .antMatchers(STATIC_RESOURCES).permitAll()
                        .antMatchers("/ajax-api/**").hasAuthority(MLFLOW_ROLE)
                        .antMatchers("/api/**").hasAuthority(MLFLOW_ROLE)
                        .antMatchers("/**").hasAuthority(MLFLOW_ROLE)

                )
                .exceptionHandling()
                    .authenticationEntryPoint(spnegoEntryPoint())
                    .and()
                .formLogin().loginPage("/login")
                .failureUrl("/login?status=error")
                .permitAll()

                .and().headers().contentTypeOptions().disable()
                .and().headers().xssProtection().disable()
                .and().headers().frameOptions().disable()
                .and().csrf().disable()

                .authenticationProvider(activeDirectoryLdapAuthenticationProvider())
                .authenticationProvider(kerberosServiceAuthenticationProvider())

                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                .and()
                .addFilterBefore(spnegoAuthenticationProcessingFilter(providerManager),
                        BasicAuthenticationFilter.class)
        ;

        return http.build();
    }


    @Bean
    public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
        return new ActiveDirectoryLdapAuthenticationProvider(adDomain, adServer);
    }

    @Bean
    public SpnegoEntryPoint spnegoEntryPoint() {
        return new SpnegoEntryPoint("/login");
    }

    // @Bean
    public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
            AuthenticationManager authenticationManager) {
        SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() throws Exception {
        KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
        provider.setTicketValidator(sunJaasKerberosTicketValidator());
        provider.setUserDetailsService(ldapUserDetailsService());
        return provider;
    }

    @Bean
    public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
        SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
        ticketValidator.setServicePrincipal(servicePrincipal);
        ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
        ticketValidator.setDebug(true);
        return ticketValidator;
    }

    @Bean
    public KerberosLdapContextSource kerberosLdapContextSource() throws Exception {
        KerberosLdapContextSource contextSource = new KerberosLdapContextSource(adServer);
        contextSource.setLoginConfig(loginConfig());
        return contextSource;
    }

    public SunJaasKrb5LoginConfig loginConfig() throws Exception {
        SunJaasKrb5LoginConfig loginConfig = new SunJaasKrb5LoginConfig();
        loginConfig.setKeyTabLocation(new FileSystemResource(keytabLocation));
        loginConfig.setServicePrincipal(servicePrincipal);

        loginConfig.setDebug(true);
        loginConfig.setIsInitiator(true);
        loginConfig.afterPropertiesSet();
        return loginConfig;
    }

    @Bean
    public LdapUserDetailsService ldapUserDetailsService() throws Exception {
        FilterBasedLdapUserSearch userSearch =
        //        new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter, kerberosLdapContextSource());
                  new SimpleFilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter, kerberosLdapContextSource());
        LdapUserDetailsService service =
                new LdapUserDetailsService(userSearch, new ActiveDirectoryLdapAuthoritiesPopulator());
        service.setUserDetailsMapper(new LdapUserDetailsMapper());
        return service;
    }

    @Bean
    public GlobalSunJaasKerberosConfig globalSunJaasKerberosConfig() throws Exception {

        GlobalSunJaasKerberosConfig config = new GlobalSunJaasKerberosConfig();
        config.setKrbConfLocation("/etc/krb5.conf");

        config.setDebug(true);
        config.afterPropertiesSet();
        return config;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    public class CustomAccessDeniedHandler implements AccessDeniedHandler {

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exc) throws IOException {
            response.sendRedirect("/access-denied");
        }
    }
}