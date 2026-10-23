package protrader.authentication.config;

import java.util.List;

import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import protrader.authentication.token.JwtVerifier;
import protrader.authentication.web.ApiException;
import protrader.authentication.web.ErrorWriter;
import protrader.authentication.web.JwtAuthFilter;
import protrader.authentication.web.PortRoutingFilter;
import protrader.authentication.web.RequestLogFilter;

// later: key-rotation automation, admin UI
/** Stateless bearer-token API: no session, no cookies, no CSRF, no login form. */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, JwtVerifier verifier, ErrorWriter errors, AuthProperties props)
			throws Exception {
		AuthenticationEntryPoint entryPoint = (request, response, e) ->
				errors.write(response, HttpStatus.UNAUTHORIZED, "unauthorized", ApiException.unauthorized().getMessage());

		http.csrf(AbstractHttpConfigurer::disable)
				.formLogin(AbstractHttpConfigurer::disable)
				.httpBasic(AbstractHttpConfigurer::disable)
				.logout(AbstractHttpConfigurer::disable)
				.requestCache(AbstractHttpConfigurer::disable)
				.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.exceptionHandling(e -> e.authenticationEntryPoint(entryPoint)
						.accessDeniedHandler((request, response, ex) ->
								errors.write(response, HttpStatus.FORBIDDEN, "forbidden", "forbidden")))
				.authorizeHttpRequests(a -> a
						.requestMatchers(HttpMethod.POST, "/v1/auth/**").permitAll()
						.requestMatchers(HttpMethod.GET, "/.well-known/jwks.json", "/healthz", "/readyz").permitAll()
						.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.requestMatchers("/error").permitAll()
						// network-level protection: PortRoutingFilter only lets these through on the internal port
						.requestMatchers("/internal/**").permitAll()
						.requestMatchers("/v1/**").authenticated()
						.anyRequest().permitAll())
				.addFilterBefore(new JwtAuthFilter(verifier), AuthorizationFilter.class);

		if (props.corsAllowedOrigins().isEmpty()) {
			http.cors(AbstractHttpConfigurer::disable);
		} else {
			http.cors(c -> c.configurationSource(corsSource(props.corsAllowedOrigins())));
		}
		return http.build();
	}

	private static CorsConfigurationSource corsSource(List<String> origins) {
		CorsConfiguration cors = new CorsConfiguration();
		cors.setAllowedOrigins(origins);
		cors.setAllowedMethods(List.of("GET", "POST", "DELETE", "OPTIONS"));
		cors.setAllowedHeaders(List.of("Authorization", "Content-Type"));
		cors.setAllowCredentials(false);
		cors.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", cors);
		return source;
	}

	/** There are no password-authenticated users in the Spring sense; stops Boot generating a throw-away one. */
	@Bean
	UserDetailsService noUserDetails() {
		return username -> {
			throw new UsernameNotFoundException("no user store");
		};
	}

	@Bean
	FilterRegistrationBean<RequestLogFilter> requestLogFilter() {
		FilterRegistrationBean<RequestLogFilter> bean = new FilterRegistrationBean<>(new RequestLogFilter());
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}

	@Bean
	FilterRegistrationBean<PortRoutingFilter> portRoutingFilter(AuthProperties props, ErrorWriter errors) {
		FilterRegistrationBean<PortRoutingFilter> bean = new FilterRegistrationBean<>(new PortRoutingFilter(props.internalPort(), errors));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
		return bean;
	}

	/** Second listener for /internal/**. Don't route this port through the public load balancer. */
	@Bean
	WebServerFactoryCustomizer<TomcatServletWebServerFactory> internalConnector(AuthProperties props) {
		return factory -> {
			if (props.internalPort() > 0) {
				var connector = new org.apache.catalina.connector.Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
				connector.setPort(props.internalPort());
				factory.addAdditionalConnectors(connector);
			}
		};
	}
}
