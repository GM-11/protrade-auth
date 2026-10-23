package protrader.authentication.google;

import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Google's OpenID discovery document, fetched once on first use, so endpoints are never hard-coded twice. */
public class GoogleDiscovery {

	@JsonIgnoreProperties(ignoreUnknown = true)
	record Document(@JsonProperty("token_endpoint") String tokenEndpoint, @JsonProperty("jwks_uri") String jwksUri) {
	}

	private final RestClient client;
	private final String discoveryUrl;
	private volatile GoogleEndpoints endpoints;

	public GoogleDiscovery(RestClient client, String discoveryUrl) {
		this.client = client;
		this.discoveryUrl = discoveryUrl;
	}

	/** For tests: endpoints already known. */
	public GoogleDiscovery(GoogleEndpoints fixed) {
		this.client = null;
		this.discoveryUrl = null;
		this.endpoints = fixed;
	}

	public GoogleEndpoints endpoints() {
		GoogleEndpoints e = endpoints;
		if (e != null) {
			return e;
		}
		try {
			Document doc = client.get().uri(discoveryUrl).retrieve().body(Document.class);
			if (doc == null || doc.tokenEndpoint() == null || doc.jwksUri() == null) {
				throw new GoogleUnavailableException("incomplete Google discovery document", null);
			}
			e = new GoogleEndpoints(doc.tokenEndpoint(), doc.jwksUri());
			endpoints = e;
			return e;
		} catch (RestClientException ex) {
			throw new GoogleUnavailableException("cannot fetch Google discovery document", ex);
		}
	}
}
