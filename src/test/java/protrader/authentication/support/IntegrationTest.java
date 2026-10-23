package protrader.authentication.support;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import tools.jackson.databind.JsonNode;

/** Real server on a random port, real Postgres in Testcontainers (the unique indexes and conditional UPDATEs are the point). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
		"auth.google.client-id=test-web-client",
		"auth.google.client-secret=test-secret",
		"auth.google.allowed-redirect-uris=https://app.example.com/auth/callback",
		"auth.google.extra-audiences=test-android-client",
})
@ActiveProfiles({"dev", "test"})
@Import(FakeGoogleConfig.class)
public abstract class IntegrationTest {

	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine");

	static {
		POSTGRES.start();
		// application.yml reads ${INTERNAL_PORT}; one fixed port for the shared context
		System.setProperty("INTERNAL_PORT", Integer.toString(freePort()));
	}

	private static int freePort() {
		try (ServerSocket s = new ServerSocket(0)) {
			return s.getLocalPort();
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
		registry.add("spring.datasource.username", POSTGRES::getUsername);
		registry.add("spring.datasource.password", POSTGRES::getPassword);
	}

	@LocalServerPort
	protected int port;

	@Value("${auth.internal-port}")
	protected int internalPort;

	@Autowired
	protected JdbcClient jdbc;

	@Autowired
	protected FakeGoogle google;

	protected Http http() {
		return new Http("http://127.0.0.1:" + port);
	}

	protected Http internal() {
		return new Http("http://127.0.0.1:" + internalPort);
	}

	protected static String uniqueEmail() {
		return "user-" + UUID.randomUUID() + "@example.com";
	}

	/** A fresh server-issued Google nonce. */
	protected String newNonce() {
		Http.Response r = http().post("/v1/auth/google/nonce", "");
		if (r.status() != 200) {
			throw new AssertionError("nonce failed: " + r.status() + " " + r.body());
		}
		return r.json().get("nonce").asString();
	}

	/** The id_token shape with a freshly issued nonce. */
	protected Http.Response googleIdTokenLogin(String idToken) {
		return http().post("/v1/auth/google", "{\"id_token\":\"" + idToken + "\",\"nonce\":\"" + newNonce() + "\"}");
	}

	/** Signs up and logs in; returns the login response JSON. */
	protected JsonNode newUser(String email) {
		Http.Response signup = http().post("/v1/auth/signup", "{\"email\":\"" + email + "\",\"password\":\"correct horse\",\"display_name\":\"Tester\"}");
		if (signup.status() != 201) {
			throw new AssertionError("signup failed: " + signup.status() + " " + signup.body());
		}
		Http.Response login = http().post("/v1/auth/login", "{\"email\":\"" + email + "\",\"password\":\"correct horse\"}");
		if (login.status() != 200) {
			throw new AssertionError("login failed: " + login.status() + " " + login.body());
		}
		return login.json();
	}
}
