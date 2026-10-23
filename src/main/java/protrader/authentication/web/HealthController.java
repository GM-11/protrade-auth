package protrader.authentication.web;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import protrader.authentication.token.JwtKeySet;

@RestController
public class HealthController {

	private final JdbcClient jdbc;
	private final JwtKeySet keys;

	public HealthController(JdbcClient jdbc, JwtKeySet keys) {
		this.jdbc = jdbc;
		this.keys = keys;
	}

	/** Up if the process is up. */
	@GetMapping("/healthz")
	Map<String, String> healthz() {
		return Map.of("status", "ok");
	}

	/** Ready only if the database answers and the signing key is loaded. */
	@GetMapping("/readyz")
	ResponseEntity<Map<String, String>> readyz() {
		boolean ready = keys.signingKey() != null && dbUp();
		return ResponseEntity.status(ready ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE)
				.body(Map.of("status", ready ? "ok" : "unavailable"));
	}

	private boolean dbUp() {
		try {
			return jdbc.sql("SELECT 1").query(Integer.class).single() == 1;
		} catch (RuntimeException e) {
			return false;
		}
	}
}
