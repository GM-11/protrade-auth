package protrader.authentication.web;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(String error, String message, String field) {

	public static ApiError of(String error, String message) {
		return new ApiError(error, message, null);
	}

	/** The error for failures that carry only an HTTP status (unknown path, wrong method, container errors). */
	public static ApiError forStatus(int status, String reason) {
		String code = switch (status) {
			case 404 -> "not_found";
			case 405 -> "method_not_allowed";
			case 413 -> "request_too_large";
			case 415 -> "content_type_must_be_json";
			default -> status >= 500 ? "internal" : "bad_request";
		};
		return of(code, reason);
	}
}
