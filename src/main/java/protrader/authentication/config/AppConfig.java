package protrader.authentication.config;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import protrader.authentication.google.GoogleDiscovery;
import protrader.authentication.google.GoogleIdTokenVerifier;
import protrader.authentication.google.GoogleTokenExchange;
import protrader.authentication.google.NimbusGoogleIdTokenVerifier;
import protrader.authentication.google.RestClientGoogleTokenExchange;
import protrader.authentication.token.JwtKeyLoader;
import protrader.authentication.token.JwtKeySet;
import protrader.authentication.token.JwtSigner;
import protrader.authentication.token.JwtVerifier;

@Configuration
public class AppConfig {

	private static final Logger log = LoggerFactory.getLogger(AppConfig.class);
	private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3);
	private static final Duration READ_TIMEOUT = Duration.ofSeconds(5);

	@Bean
	Clock clock() {
		return Clock.systemUTC();
	}

	@Bean
	JwtKeySet jwtKeySet(AuthProperties props, Environment env) {
		return JwtKeyLoader.load(props.jwt(), env.acceptsProfiles(Profiles.of("dev")));
	}

	@Bean
	JwtSigner jwtSigner(JwtKeySet keys, AuthProperties props, Clock clock) {
		return new JwtSigner(keys, props.jwt().issuer(), props.jwt().audience(), props.accessTokenTtl(), clock);
	}

	@Bean
	JwtVerifier jwtVerifier(JwtKeySet keys, AuthProperties props, Clock clock) {
		return new JwtVerifier(keys, props.jwt().issuer(), props.jwt().audience(), clock);
	}

	private static JdkClientHttpRequestFactory timeouts() {
		JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build());
		factory.setReadTimeout(READ_TIMEOUT);
		return factory;
	}

	@Bean
	RestClient googleRestClient(RestClient.Builder builder) {
		return builder.requestFactory(timeouts()).build();
	}

	@Bean
	GoogleDiscovery googleDiscovery(RestClient googleRestClient, AuthProperties props) {
		return new GoogleDiscovery(googleRestClient, props.google().discoveryUrl());
	}

	@Bean
	GoogleTokenExchange googleTokenExchange(RestClient googleRestClient, GoogleDiscovery discovery, AuthProperties props) {
		var g = props.google();
		if (g.clientId().isBlank()) {
			log.warn("GOOGLE_CLIENT_ID is not set: Google sign-in will reject every request");
		}
		return new RestClientGoogleTokenExchange(googleRestClient, discovery, g.clientId(), g.clientSecret());
	}

	@Bean
	GoogleIdTokenVerifier googleIdTokenVerifier(GoogleDiscovery discovery, AuthProperties props) {
		Supplier<JwtDecoder> decoder = new Supplier<>() {
			private volatile JwtDecoder cached;

			@Override
			public JwtDecoder get() {
				JwtDecoder d = cached;
				if (d == null) {
					RestTemplate rest = new RestTemplate(timeouts());
					NimbusJwtDecoder nimbus = NimbusJwtDecoder.withJwkSetUri(discovery.endpoints().jwksUri())
							.jwsAlgorithm(SignatureAlgorithm.RS256)
							.restOperations(rest)
							.build();
					// exp / nbf with the default 60 s skew; iss, aud and the rest are checked by the verifier
					// Google sometimes sends iss as the bare host "accounts.google.com", which is not a URL
					nimbus.setClaimSetConverter(MappedJwtClaimSetConverter.withDefaults(java.util.Map.of("iss", o -> o == null ? null : o.toString())));
					nimbus.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(Duration.ofSeconds(60))));
					cached = d = nimbus;
				}
				return d;
			}
		};
		return new NimbusGoogleIdTokenVerifier(decoder, props.google().clientId(), props.google().extraAudiences());
	}
}
