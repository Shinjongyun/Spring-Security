package konkuk.Shin.auth.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import konkuk.Shin.auth.security.exception.handler.CustomAccessDeniedHandler;
import konkuk.Shin.auth.security.exception.handler.CustomAuthenticationEntryPoint;
import konkuk.Shin.auth.jwt.filter.JwtAuthenticationFilter;
import konkuk.Shin.auth.jwt.exception.JwtExceptionHandlerFilter;
import konkuk.Shin.auth.security.exception.handler.CustomSessionExpiredStrategy;
import konkuk.Shin.auth.security.local.login.CustomAuthenticationProvider;
import konkuk.Shin.auth.security.exception.handler.CustomJsonAuthenticationFailureHandler;
import konkuk.Shin.auth.security.local.login.CustomLoginFilter;
import konkuk.Shin.auth.security.oauth2.CustomAuthenticationSuccessHandler;
import konkuk.Shin.auth.security.oauth2.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomJsonAuthenticationFailureHandler customJsonAuthenticationFailureHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final JwtExceptionHandlerFilter jwtExceptionHandlerFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final ObjectMapper objectMapper;
    private final AuthenticationConfiguration configuration;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSessionExpiredStrategy customSessionExpiredStrategy;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CustomLoginFilter customLoginFilter() throws Exception {
        return new CustomLoginFilter(
                authenticationManager(),
                objectMapper,
                customAuthenticationSuccessHandler,
                customJsonAuthenticationFailureHandler
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CustomLoginFilter customLoginFilter,
                                                   CorsConfigurationSource corsConfigurationSource) throws Exception {


        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .httpBasic(b -> b.disable())
                .formLogin(fl -> fl.disable())
                .sessionManagement(sm -> sm
                        .sessionFixation(sf -> sf.changeSessionId())
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                        .expiredSessionStrategy(customSessionExpiredStrategy)
                        .sessionRegistry(sessionRegistry())
                );

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/error",
                                "/favicon.ico",
                                "/actuator/health",
                                "/api/auth/**",
                                "/api/users/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                );

        http
                .addFilterBefore(jwtExceptionHandlerFilter, LogoutFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(customLoginFilter, UsernamePasswordAuthenticationFilter.class);

        http
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                );

        http
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler(customAuthenticationSuccessHandler)
                );

        return http.build();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public static ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
    }
}
