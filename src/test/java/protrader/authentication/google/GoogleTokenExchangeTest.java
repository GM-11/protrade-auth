package protrader.authentication.google;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.SocketTimeoutException;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class GoogleTokenExchangeTest {

	private static final String TOKEN_URL = "https://oauth2.googleapis.com/token";

	private MockRestServiceServer server;
	private RestClientGoogleTokenExchange exchange;
	private GoogleDiscovery discovery;
	private RestClient client;

	@BeforeEach
	void setUp() {
		RestClient.Builder builder = RestClient.builder();
		server = MockRestServiceServer.bindTo(builder).build();
		client = builder.build();
		discovery = new GoogleDiscovery(new GoogleEndpoints(TOKEN_URL, "https://www.googleapis.com/oauth2/v3/certs"));
		exchange = new RestClientGoogleTokenExchange(client, discovery, "client-id", "client-secret");
	}

	@Test
	void sendsTheStandardAuthorizationCodeFormWithPkce() {
		server.expect(requestTo(TOKEN_URL))
				.andExpect(method(HttpMethod.POST))
				.andExpect(request -> assertThat(request.getHeaders().getContentType().toString()).startsWith("application/x-www-form-urlencoded"))
				.andExpect(content().formDataContains(Map.of(
						"grant_type", "authorization_code",
						"code", "the-code",
						"code_verifier", "the-verifier",
						"redirect_uri", "https://app.example.com/cb",
						"client_id", "client-id",
						"client_secret", "client-secret")))
				.andRespond(withSuccess("{\"access_token\":\"ignored\",\"refresh_token\":\"ignored\",\"id_token\":\"the.id.token\",\"scope\":\"openid email\"}",
						MediaType.APPLICATION_JSON));
		assertThat(exchange.exchange("the-code", "the-verifier", "https://app.example.com/cb")).isEqualTo("the.id.token");
		server.verify();
	}

	@Test
	void googleRejectingTheCodeIsRejected() {
		server.expect(requestTo(TOKEN_URL)).andRespond(withStatus(HttpStatus.BAD_REQUEST)
				.contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"invalid_grant\"}"));
		assertThatThrownBy(() -> exchange.exchange("c", "v", "r"))
				.isInstanceOf(GoogleRejectedException.class)
				.hasMessageNotContaining("invalid_grant");
	}

	@Test
	void timeoutIsUnavailable() {
		server.expect(requestTo(TOKEN_URL)).andRespond(withException(new SocketTimeoutException("read timed out")));
		assertThatThrownBy(() -> exchange.exchange("c", "v", "r")).isInstanceOf(GoogleUnavailableException.class);
	}

	@Test
	void googleServerErrorIsUnavailable() {
		server.expect(requestTo(TOKEN_URL)).andRespond(withServerError());
		assertThatThrownBy(() -> exchange.exchange("c", "v", "r")).isInstanceOf(GoogleUnavailableException.class);
	}

	@Test
	void responseWithoutAnIdTokenIsRejected() {
		server.expect(requestTo(TOKEN_URL)).andRespond(withSuccess("{\"access_token\":\"x\"}", MediaType.APPLICATION_JSON));
		assertThatThrownBy(() -> exchange.exchange("c", "v", "r")).isInstanceOf(GoogleRejectedException.class);
	}

	@Test
	void doesNotRetryASingleUseCode() {
		server.expect(requestTo(TOKEN_URL)).andRespond(withServerError());
		assertThatThrownBy(() -> exchange.exchange("c", "v", "r")).isInstanceOf(GoogleUnavailableException.class);
		server.verify(); // exactly one request was expected and made; a second would have failed with "no further requests expected"
	}

	@Test
	void endpointsComeFromTheDiscoveryDocument() {
		RestClient.Builder builder = RestClient.builder();
		MockRestServiceServer s = MockRestServiceServer.bindTo(builder).build();
		GoogleDiscovery d = new GoogleDiscovery(builder.build(), "https://accounts.google.com/.well-known/openid-configuration");
		s.expect(requestTo("https://accounts.google.com/.well-known/openid-configuration"))
				.andRespond(withSuccess("{\"issuer\":\"https://accounts.google.com\",\"token_endpoint\":\"https://t.example/token\",\"jwks_uri\":\"https://t.example/certs\",\"more\":1}",
						MediaType.APPLICATION_JSON));
		assertThat(d.endpoints()).isEqualTo(new GoogleEndpoints("https://t.example/token", "https://t.example/certs"));
		assertThat(d.endpoints().tokenEndpoint()).isEqualTo("https://t.example/token"); // cached: no second request
		s.verify();
	}

	@Test
	void discoveryFailureIsUnavailable() {
		RestClient.Builder builder = RestClient.builder();
		MockRestServiceServer s = MockRestServiceServer.bindTo(builder).build();
		GoogleDiscovery d = new GoogleDiscovery(builder.build(), "https://accounts.google.com/.well-known/openid-configuration");
		s.expect(requestTo("https://accounts.google.com/.well-known/openid-configuration")).andRespond(withServerError());
		assertThatThrownBy(d::endpoints).isInstanceOf(GoogleUnavailableException.class);
	}
}
