package protrader.authentication.web;

import java.util.List;
import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import protrader.authentication.apikey.ApiKeyService;
import protrader.authentication.web.Dtos.Snapshot;
import protrader.authentication.web.Dtos.SnapshotKey;

/** The gateway's key table (contract §4.1). Reachable only on the internal port (see PortRoutingFilter). */
@RestController
public class InternalApiKeyController {

	private final ApiKeyService keys;

	public InternalApiKeyController(ApiKeyService keys) {
		this.keys = keys;
	}

	@GetMapping("/internal/v1/api-keys")
	ResponseEntity<Snapshot> snapshot(@RequestParam(name = "if_newer_than", required = false) String ifNewerThan) {
		Optional<ApiKeyService.Snapshot> snap = keys.snapshotIfNewer(parseOrZero(ifNewerThan));
		if (snap.isEmpty()) {
			return ResponseEntity.status(304).build();
		}
		List<SnapshotKey> out = snap.get().keys().stream()
				.map(r -> new SnapshotKey(r.keyId(), r.accountId(), r.secretSha256(), r.disabled(), r.label()))
				.toList();
		return ResponseEntity.ok(new Snapshot(snap.get().version(), out));
	}

	private static long parseOrZero(String s) {
		try {
			long n = Long.parseLong(s);
			return Math.max(n, 0);
		} catch (NumberFormatException e) {
			return 0;
		}
	}
}
