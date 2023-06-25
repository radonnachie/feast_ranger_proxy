package za.co.discovery.health.bigdata.ranger.feast;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.GlobalSunJaasKerberosConfig;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
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

    private static final String FEAST_ROLE = "Feast-users";
    @Value("${app.ad-domain}")
    private String adDomain;

    @Value("${app.ad-server}")
    private String adServer;

    @Value("${app.service-principal}")
    private String servicePrincipal;


    @Value("${app.keytab-location}")
    private String keytabLocation;

    @Value("${ldap.search-base}")
    private String ldapSearchBase;

    @Value("${ldap.search-filter}")
    private String ldapSearchFilter;

    @Value("${ldap.keytab}")
    private String ldapKeytab;

    @Value("${ldap.service-principal}")
    private String ldapKerberosPrincipal;


    private static final String[] STATIC_RESOURCES = new String[] {
            "/**.js", "/**.css", "/**.map",
            "/**.png", "/**.jpg", "/favicon.ico",
            "/**.woff2", "/**.otf", "/access-denied", "/login", "/static-files/**"
    };



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider = kerberosServiceAuthenticationProvider();
        ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider = activeDirectoryLdapAuthenticationProvider();
        ProviderManager providerManager = new ProviderManager(
                kerberosServiceAuthenticationProvider,
                activeDirectoryLdapAuthenticationProvider
        );

        http

                .authorizeHttpRequests((authz) -> authz

                        .antMatchers(STATIC_RESOURCES).permitAll()
                        .antMatchers("/ajax-api/**").hasAuthority(FEAST_ROLE)
                        .antMatchers("/api/**").hasAuthority(FEAST_ROLE)
                        .antMatchers("/**").hasAuthority(FEAST_ROLE)
                        .anyRequest().authenticated()

                )
                .exceptionHandling()
                    .authenticationEntryPoint(spnegoEntryPoint())
                    .and()
                .formLogin()
                .loginPage("/login")

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


//    @Bean
//    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
//        return http.getSharedObject(AuthenticationManagerBuilder.class)
//                .authenticationProvider(kerberosAuthenticationProvider())
//                .authenticationProvider(kerberosServiceAuthenticationProvider())
//                .build();
//    }


    @Bean
    public ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider() {
        ActiveDirectoryLdapAuthenticationProvider adProvider = new ActiveDirectoryLdapAuthenticationProvider(adDomain, adServer);
        adProvider.setSearchFilter(ldapSearchFilter);
        return adProvider;
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

    @Bean
    public SunJaasKrb5LoginConfig loginConfig() throws Exception {
        SunJaasKrb5LoginConfig loginConfig = new SunJaasKrb5LoginConfig();
        loginConfig.setKeyTabLocation(new FileSystemResource(ldapKeytab));
        loginConfig.setServicePrincipal(ldapKerberosPrincipal);

        //loginConfig.setUseTicketCache(true);
        loginConfig.setDebug(true);
        loginConfig.setIsInitiator(true);
        loginConfig.afterPropertiesSet();
        return loginConfig;
    }

    @Bean
    public LdapUserDetailsService ldapUserDetailsService() throws Exception {
        // For forms based auth the ActiveDirectoryLdapAuthenticationProvider there are two parameters sent to the search filter
        // param 0:  the fully qualified username, param1: the simple username , we need to use {1}
        // The searchForUser method of FilterBasedLdapUserSearch only contains 1
        // We therefor need to modify the search filter to reference param {0}
        String modifiedSearchFilter = ldapSearchFilter.replace("{1}", "{0}");
        FilterBasedLdapUserSearch userSearch =
        //        new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearchFilter, kerberosLdapContextSource());
                  new SimpleFilterBasedLdapUserSearch(ldapSearchBase, modifiedSearchFilter, kerberosLdapContextSource());
        LdapUserDetailsService service =
                new LdapUserDetailsService(userSearch, new ActiveDirectoryLdapAuthoritiesPopulator());
        service.setUserDetailsMapper(new LdapUserDetailsMapper());
        return service;
    }

    @Bean
    public GlobalSunJaasKerberosConfig globalSunJaasKerberosConfig() throws Exception {

        GlobalSunJaasKerberosConfig config = new GlobalSunJaasKerberosConfig();
        config.setKrbConfLocation("C:\\Users\\radonn\\Work\\environments\\feast\\feast-ranger\\feast-ranger-auth\\src\\main\\resources\\krb5.conf");
        config.setDebug(true);
        config.afterPropertiesSet();
        return config;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }

    public static class CustomAccessDeniedHandler implements AccessDeniedHandler {

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exc) throws IOException {
            response.sendRedirect("/access-denied");
        }
    }
}