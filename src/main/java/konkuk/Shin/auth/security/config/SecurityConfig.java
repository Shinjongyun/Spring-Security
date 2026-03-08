package konkuk.Shin.auth.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import konkuk.Shin.auth.security.exception.handler.CustomAccessDeniedHandler;
import konkuk.Shin.auth.security.exception.handler.CustomAuthenticationEntryPoint;
import konkuk.Shin.auth.jwt.filter.JwtAuthenticationFilter;
import konkuk.Shin.auth.jwt.exception.JwtExceptionHandlerFilter;
import konkuk.Shin.auth.security.local.login.CustomAuthenticationProvider;
import konkuk.Shin.auth.security.exception.handler.CustomJsonAuthenticationFailureHandler;
import konkuk.Shin.auth.security.local.login.CustomLoginFilter;
import konkuk.Shin.auth.security.oauth2.CustomAuthenticationSuccessHandler;
import konkuk.Shin.auth.security.oauth2.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationProvider customAuthenticationProvider;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private final CustomJsonAuthenticationFailureHandler customJsonAuthenticationFailureHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtExceptionHandlerFilter jwtExceptionHandlerFilter;
    private final ObjectMapper objectMapper;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(customAuthenticationProvider);
    }

    @Bean
    public CustomLoginFilter customLoginFilter() {
        return new CustomLoginFilter(
                authenticationManager(),
                objectMapper,
                customAuthenticationSuccessHandler,
                customJsonAuthenticationFailureHandler
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/users/signup",
                                "/api/auth/login/**",
                                "/login/oauth2/**",
                                "/oauth2/authorization/**",
                                "/api/login/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )

                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo ->
                                userInfo.userService(customOAuth2UserService))
                        .successHandler(customAuthenticationSuccessHandler)
                )

                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )

                .addFilterBefore(jwtExceptionHandlerFilter, LogoutFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(customLoginFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilterRegistration() {
        FilterRegistrationBean<JwtAuthenticationFilter> registration = new FilterRegistrationBean<>(jwtAuthenticationFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public FilterRegistrationBean<JwtExceptionHandlerFilter> jwtExceptionHandlerFilterRegistration() {
        FilterRegistrationBean<JwtExceptionHandlerFilter> registration = new FilterRegistrationBean<>(jwtExceptionHandlerFilter);
        registration.setEnabled(false);
        return registration;
    }
}
