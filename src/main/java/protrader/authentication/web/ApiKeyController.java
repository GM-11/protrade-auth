package protrader.authentication.web;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import protrader.authentication.apikey.ApiKeyService;
import protrader.authentication.web.Dtos.CreateKeyRequest;
import protrader.authentication.web.Dtos.CreatedKeyResponse;
import protrader.authentication.web.Dtos.KeyList;
import protrader.authentication.web.Dtos.KeyView;

@RestController
@RequestMapping("/v1/api-keys")
public class ApiKeyController {

	private final ApiKeyService keys;

	public ApiKeyController(ApiKeyService keys) {
		this.keys = keys;
	}

	@PostMapping
	ResponseEntity<CreatedKeyResponse> create(@AuthenticationPrincipal AccountPrincipal principal, @JsonBody CreateKeyRequest request) {
		ApiKeyService.Created c = keys.create(principal.accountId(), request.label());
		return ResponseEntity.status(HttpStatus.CREATED)
				.body(new CreatedKeyResponse(c.keyId(), c.secret(), c.label(), Timestamps.format(c.createdAt())));
	}

	@GetMapping
	KeyList list(@AuthenticationPrincipal AccountPrincipal principal) {
		List<KeyView> views = keys.list(principal.accountId()).stream()
				.map(r -> new KeyView(r.keyId(), r.label(), Timestamps.format(r.createdAt()), r.disabled()))
				.toList();
		return new KeyList(views);
	}

	@DeleteMapping("/{keyId}")
	ResponseEntity<Void> disable(@AuthenticationPrincipal AccountPrincipal principal, @PathVariable String keyId) {
		keys.disable(principal.accountId(), keyId);
		return ResponseEntity.noContent().build();
	}
}
