package protrader.authentication.support;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Tiny HTTP/1.1 client for the integration tests: nothing between the test and the wire. */
public final class Http {

	public record Response(int status, String body, HttpHeaders headers) {

		public JsonNode json() {
			return MAPPER.readTree(body);
		}

		public String error() {
			return json().get("error").asString();
		}
	}

	private static final JsonMapper MAPPER = JsonMapper.builder().build();
	private static final HttpClient CLIENT = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

	private final String base;

	public Http(String base) {
		this.base = base;
	}

	public Response get(String path) {
		return get(path, null);
	}

	public Response get(String path, String bearer) {
		return send("GET", path, null, null, bearer);
	}

	public Response delete(String path, String bearer) {
		return send("DELETE", path, null, null, bearer);
	}

	public Response post(String path, String json) {
		return post(path, json, null);
	}

	public Response post(String path, String json, String bearer) {
		return send("POST", path, "application/json", json.getBytes(StandardCharsets.UTF_8), bearer);
	}

	public Response send(String method, String path, String contentType, byte[] body, String bearer) {
		return send(method, path, contentType, body, bearer, java.util.Map.of());
	}

	public Response send(String method, String path, String contentType, byte[] body, String bearer, java.util.Map<String, String> headers) {
		HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
				.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
		if (contentType != null) {
			b.header("Content-Type", contentType);
		}
		if (bearer != null) {
			b.header("Authorization", "Bearer " + bearer);
		}
		headers.forEach(b::header);
		try {
			HttpResponse<String> r = CLIENT.send(b.build(), HttpResponse.BodyHandlers.ofString());
			return new Response(r.statusCode(), r.body(), r.headers());
		} catch (IOException | InterruptedException e) {
			throw new IllegalStateException(e);
		}
	}
}
