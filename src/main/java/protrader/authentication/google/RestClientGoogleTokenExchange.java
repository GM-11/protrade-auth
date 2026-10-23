package protrader.authentication.google;

import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * POSTs the code to Google's token endpoint. Single attempt: an authorization code is single-use,
 * so a retry could only fail. Never logs the code, verifier, secret or Google's response body.
 */
public class RestClientGoogleTokenExchange implements GoogleTokenExchange {

	@JsonIgnoreProperties(ignoreUnknown = true)
	record TokenResponse(@JsonProperty("id_token") String idToken) {
	}

	private final RestClient client;
	private final GoogleDiscovery discovery;
	private final String clientId;
	private final String clientSecret;

	public RestClientGoogleTokenExchange(RestClient client, GoogleDiscovery discovery, String clientId, String clientSecret) {
		this.client = client;
		this.discovery = discovery;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	@Override
	public String exchange(String code, String codeVerifier, String redirectUri) {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("grant_type", "authorization_code");
		form.add("code", code);
		form.add("code_verifier", codeVerifier);
		form.add("redirect_uri", redirectUri);
		form.add("client_id", clientId);
		form.add("client_secret", clientSecret);
		try {
			TokenResponse response = client.post()
					.uri(discovery.endpoints().tokenEndpoint())
					.contentType(MediaType.APPLICATION_FORM_URLENCODED)
					.body(form)
					.retrieve()
					.body(TokenResponse.class);
			if (response == null || response.idToken() == null || response.idToken().isBlank()) {
				throw new GoogleRejectedException("token response without id_token");
			}
			return response.idToken();
		} catch (HttpClientErrorException e) {
			throw new GoogleRejectedException("token endpoint answered " + e.getStatusCode().value());
		} catch (RestClientException e) {
			// timeouts, connection errors, 5xx, unreadable body
			throw new GoogleUnavailableException("Google token endpoint unavailable", e);
		}
	}
}
