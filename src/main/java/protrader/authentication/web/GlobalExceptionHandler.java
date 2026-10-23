package protrader.authentication.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Every error leaves as {"error":...} JSON, never HTML and never an exception message. */
@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(ApiException.class)
	ResponseEntity<ApiError> api(ApiException e) {
		return ResponseEntity.status(e.status()).body(new ApiError(e.code(), e.getMessage(), e.field()));
	}

	@ExceptionHandler(Exception.class)
	ResponseEntity<ApiError> unexpected(Exception e) {
		// Spring's own 4xx exceptions (no handler, wrong method, bad parameter, ...): keep the status, drop the detail
		if (e instanceof ErrorResponse er && er.getStatusCode().is4xxClientError()) {
			return ResponseEntity.status(er.getStatusCode()).body(ApiError.forStatus(er.getStatusCode().value(), "request not accepted"));
		}
		log.error("unhandled exception", e);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiError.of("internal", "internal error"));
	}
}
