package protrader.authentication.web;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import protrader.authentication.token.JwtKeySet;

@RestController
public class JwksController {

	private final JwtKeySet keys;

	public JwksController(JwtKeySet keys) {
		this.keys = keys;
	}

	@GetMapping("/.well-known/jwks.json")
	ResponseEntity<Map<String, Object>> jwks() {
		return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofSeconds(300)).cachePublic()).body(keys.jwks());
	}
}
