package vn.iotstar.jwtnimbus.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import vn.iotstar.jwtnimbus.security.JwtAuthenticationFilter;
import vn.iotstar.jwtnimbus.security.RestSecurityErrorHandler;

import java.util.List;

/**
 * Tuong ung "Buoc 7: Khoi tao mot class SecurityConfig" trong bai giang.
 *
 * <p>Chinh sach truy cap giu nguyen tinh than bai giang:
 * <ul>
 *   <li>{@code /auth/**} -&gt; cho phep (dang ky, dang nhap)</li>
 *   <li>{@code /user/**}, {@code /login}, {@code /images/**}, {@code /js/**}, {@code /css/**} -&gt; cho phep (view + tai nguyen tinh)</li>
 *   <li>{@code /users/me}, {@code /users} -&gt; phai xac thuc (Bearer token)</li>
 *   <li>con lai -&gt; phai xac thuc</li>
 * </ul>
 *
 * <p>Khac biet co chu y so voi bai giang:
 * <ul>
 *   <li>CSRF duoc tat vi API dung Bearer token trong header, khong dung cookie/session
 *       =&gt; khong co "ambient authority" nen khong co nguy co CSRF. Neu sau nay dung cookie,
 *       PHAI bat lai CSRF.</li>
 *   <li>CORS chi cho phep origin cau hinh trong {@code app.cors.allowed-origins}, khong dung {@code *}.</li>
 *   <li>Them {@code exceptionHandling} tra ve JSON 401/403 thay vi trang HTML mac dinh.</li>
 *   <li>H2 console chi duoc mo khi {@code spring.h2.console.enabled=true} (mac dinh chi o profile dev).</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    /** Duong dan cong khai, khong can token. */
    private static final String[] PUBLIC_PATHS = {
            "/", "/login", "/register", "/error",
            // /user/profile la trang Thymeleaf: trang duoc phep tai, con du lieu thi lay bang
            // GET /users/me (co token). Giong bai giang: requestMatchers("/user/**").permitAll()
            "/user/**",
            "/css/**", "/js/**", "/images/**", "/favicon.ico",
            "/auth/signup", "/auth/login"
    };

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    private final RestSecurityErrorHandler restSecurityErrorHandler;

    private final List<String> allowedOrigins;

    private final boolean h2ConsoleEnabled;

    private final String h2ConsolePath;

    public SecurityConfiguration(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            RestSecurityErrorHandler restSecurityErrorHandler,
            @Value("${app.cors.allowed-origins}") List<String> allowedOrigins,
            @Value("${spring.h2.console.enabled:false}") boolean h2ConsoleEnabled,
            @Value("${spring.h2.console.path:/h2-console}") String h2ConsolePath) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.restSecurityErrorHandler = restSecurityErrorHandler;
        this.allowedOrigins = allowedOrigins;
        this.h2ConsoleEnabled = h2ConsoleEnabled;
        this.h2ConsolePath = h2ConsolePath;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // API stateless dung Bearer token => khong dung cookie => CSRF khong ap dung.
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .headers(httpHeaders -> {
                    // Cho phep H2 console hien thi trong iframe (chi co y nghia khi console duoc bat).
                    httpHeaders.frameOptions(frameOptions -> frameOptions.sameOrigin());

                    // CSP luon duoc bat: day la lop giam thieu quan trong vi token duoc luu trong
                    // localStorage (neu co XSS thi script la co the doc token).
                    // H2 console can inline script/style nen phai noi long khi console duoc bat.
                    String scriptAndStyle = h2ConsoleEnabled
                            ? "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                            : "script-src 'self'; style-src 'self'; ";

                    httpHeaders.contentSecurityPolicy(csp -> csp.policyDirectives(
                            "default-src 'self'; "
                                    + scriptAndStyle
                                    + "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
                                    + "form-action 'self'; frame-ancestors 'self'"));
                })
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(PUBLIC_PATHS).permitAll();
                    auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
                    if (h2ConsoleEnabled) {
                        auth.requestMatchers(h2ConsolePath + "/**").permitAll();
                    }
                    auth.anyRequest().authenticated();
                })
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(restSecurityErrorHandler)
                        .accessDeniedHandler(restSecurityErrorHandler))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    /**
     * {@link JwtAuthenticationFilter} duoc danh dau {@code @Component} nen Spring Boot se tu dong
     * dang ky no nhu mot servlet filter cho MOI request. Nhung no da duoc them vao
     * SecurityFilterChain o tren, neu khong tat dang ky nay thi filter se chay hai lan.
     */
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilterRegistration(
            JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(allowedOrigins);
        configuration.setAllowedMethods(List.of("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Cache-Control"));
        configuration.setExposedHeaders(List.of("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
