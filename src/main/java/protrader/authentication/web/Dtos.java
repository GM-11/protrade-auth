package protrader.authentication.web;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Request and response bodies of §3.1. Field names are the contract's, in snake_case. */
public final class Dtos {

	private Dtos() {
	}

	public record SignupRequest(String email, String password, @JsonProperty("display_name") String displayName) {
	}

	public record SignupResponse(@JsonProperty("account_id") String accountId) {
	}

	public record NonceResponse(String nonce, @JsonProperty("expires_in") long expiresIn) {
	}

	public record LoginRequest(String email, String password) {
	}

	public record RefreshRequest(@JsonProperty("refresh_token") String refreshToken) {
	}

	public record MeResponse(
			@JsonProperty("account_id") String accountId,
			String email,
			@JsonProperty("display_name") String displayName,
			@JsonProperty("created_at") String createdAt) {
	}

	public record CreateKeyRequest(String label) {
	}

	public record CreatedKeyResponse(
			@JsonProperty("key_id") String keyId,
			String secret,
			String label,
			@JsonProperty("created_at") String createdAt) {
	}

	public record KeyView(
			@JsonProperty("key_id") String keyId,
			String label,
			@JsonProperty("created_at") String createdAt,
			boolean disabled) {
	}

	public record KeyList(List<KeyView> keys) {
	}

	/** Gateway snapshot entry. account_id is a JSON number here (Go uint64); no other fields, the gateway rejects unknown ones. */
	public record SnapshotKey(
			@JsonProperty("key_id") String keyId,
			@JsonProperty("account_id") long accountId,
			@JsonProperty("secret_sha256") String secretSha256,
			boolean disabled,
			String label) {
	}

	public record Snapshot(long version, List<SnapshotKey> keys) {
	}
}
