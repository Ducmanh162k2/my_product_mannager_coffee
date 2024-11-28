//package com.cnf.ultils;
//
//
//import com.cnf.services.CustomUserDetailService;
//import com.cnf.services.OAuthService;
//import com.cnf.services.UserService;
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
//import org.springframework.security.web.SecurityFilterChain;
//
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
//@RequiredArgsConstructor
//public class SecurityConfig {
//    private final UserService userService;
//    private final OAuthService oAuthService;
//    @Bean
//    public UserDetailsService userDetailsService() {
//        return new CustomUserDetailService();
//    }
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//    @Bean
//    public DaoAuthenticationProvider authenticationProvider() {
//        DaoAuthenticationProvider auth = new DaoAuthenticationProvider();
//        auth.setUserDetailsService(userDetailsService());
//        auth.setPasswordEncoder(passwordEncoder());
//        return auth;
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
//            Exception {
//        return http.csrf(csrf -> csrf.disable())
//                .headers(headers -> headers
//                        .frameOptions(frameOptions -> frameOptions.disable()) // Loại bỏ X-Frame-Options header
//                )
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/cart/checkout")
//                        .authenticated()
//                        .requestMatchers("/product/comment")
//                        .authenticated()
//                        .requestMatchers("/assets/**", "/client_assets/**","staff_assets/**","/filter_assets/**" ,"/","/forgotpassword", "/reset_password", "/register","/product-images/**", "/avt-images/**","/blog-images/**","/blog/detail/**","/sendEmail",
//                                "/error","/product/**","/cart/**","/add-to-cart/**", "/webjars/jquery/3.6.4/jquery.min.js","/getComments","/getTotalComment",
//                                "/total_items","/getCart","/getSumPrice","/wishlist/**","/add-to-wishlist/**","/getProduct/**","/search/**", "/about", "/contact")
//                        .permitAll()
//                        .requestMatchers( "/admin/**")
//                        .hasAnyAuthority("ADMIN")
//                        .requestMatchers("/staff/**")
//                        .hasAnyAuthority("STAFF")
//                        .anyRequest().authenticated()
//                )
//                .logout(logout -> logout.logoutUrl("/logout")
//                        .logoutSuccessUrl("/login")
//                        .deleteCookies("JSESSIONID")
//                        .invalidateHttpSession(true)
//                        .clearAuthentication(true)
//                        .permitAll()
//
//                )
//                .formLogin(formLogin -> formLogin.loginPage("/login")
//                        .loginProcessingUrl("/login")
//                        .defaultSuccessUrl("/")
//                        .permitAll()
//
//                ).oauth2Login(
//                        oauth2Login -> oauth2Login.loginPage("/login")
//                                .failureUrl("/login?error")
//                                .userInfoEndpoint(userInfoEndpoint ->
//                                        userInfoEndpoint
//                                                .userService(oAuthService)
//                                )
//                                .successHandler(
//                                        (request, response, authentication) -> {
//                                            var oidcUser = (DefaultOidcUser)authentication.getPrincipal();
//                                            userService.saveOauthUser(oidcUser.getEmail(), oidcUser.getName(), oidcUser.getFullName());
//                                            response.sendRedirect("/");
//                                        }
//                                )
//                                .permitAll()
//                ).rememberMe(rememberMe -> rememberMe.key("uniqueAndSecret")
//                        .tokenValiditySeconds(86400)
//                        .userDetailsService(userDetailsService())
//                )
//                .exceptionHandling(exceptionHandling ->
//                        exceptionHandling.accessDeniedPage("/403"))
//                .build();
//    }
//}
//

package com.cnf.ultils;

import com.cnf.ultils.CustomAuthenticationFailureHandler;
import com.cnf.services.CustomUserDetailService;
import com.cnf.services.OAuthService;
import com.cnf.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;
    private final OAuthService oAuthService;
    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailService();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider auth = new DaoAuthenticationProvider();
        auth.setUserDetailsService(userDetailsService());
        auth.setPasswordEncoder(passwordEncoder());
        return auth;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/cart/checkout", "/product/comment").authenticated()
                        .requestMatchers("/assets/**", "/client_assets/**","/staff_assets/**","/filter_assets/**", "/",
                                "/forgotpassword", "/reset_password", "/register", "/product-images/**", "/avt-images/**",
                                "/blog-images/**", "/blog/detail/**", "/sendEmail", "/error", "/product/**", "/cart/**",
                                "/add-to-cart/**", "/webjars/jquery/3.6.4/jquery.min.js", "/getComments", "/getTotalComment",
                                "/total_items", "/getCart", "/getSumPrice", "/wishlist/**", "/add-to-wishlist/**", "/getProduct/**",
                                "/search/**", "/about", "/contact").permitAll()
                        .requestMatchers("/admin/**").hasAnyAuthority("ADMIN")
                        .requestMatchers("/staff/**").hasAnyAuthority("STAFF", "ADMIN")
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .deleteCookies("JSESSIONID")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                )
                .formLogin(formLogin -> formLogin
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/")
                        .failureHandler(customAuthenticationFailureHandler)  // Sử dụng AuthenticationFailureHandler tùy chỉnh
                        .permitAll()
                )
                .oauth2Login(oauth2Login -> oauth2Login.loginPage("/login")
                        .failureUrl("/login?error")
                        .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userService(oAuthService))
                        .successHandler((request, response, authentication) -> {
                            var oidcUser = (DefaultOidcUser) authentication.getPrincipal();
                            userService.saveOauthUser(oidcUser.getEmail(), oidcUser.getName(), oidcUser.getFullName());
                            response.sendRedirect("/");
                        })
                        .permitAll()
                )
                .rememberMe(rememberMe -> rememberMe.key("uniqueAndSecret")
                        .tokenValiditySeconds(86400)
                        .userDetailsService(userDetailsService())
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling.accessDeniedPage("/403"))
                .build();
    }
}

