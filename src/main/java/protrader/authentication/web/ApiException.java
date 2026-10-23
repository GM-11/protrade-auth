package protrader.authentication.web;

import org.springframework.http.HttpStatus;

/** A business answer with the contract's error shape: {"error":"<code>","message":"...","field":"..."}. */
public class ApiException extends RuntimeException {

	private final HttpStatus status;
	private final String code;
	private final String field;

	public ApiException(HttpStatus status, String code, String message, String field) {
		super(message);
		this.status = status;
		this.code = code;
		this.field = field;
	}

	public ApiException(HttpStatus status, String code, String message) {
		this(status, code, message, null);
	}

	public static ApiException invalidField(String field, String message) {
		return new ApiException(HttpStatus.UNPROCESSABLE_ENTITY, "invalid_field", message, field);
	}

	public static ApiException unauthorized() {
		return new ApiException(HttpStatus.UNAUTHORIZED, "unauthorized", "missing or invalid access token");
	}

	public static ApiException badCredentials() {
		return new ApiException(HttpStatus.UNAUTHORIZED, "bad_credentials", "invalid credentials");
	}

	public HttpStatus status() {
		return status;
	}

	public String code() {
		return code;
	}

	public String field() {
		return field;
	}
}
