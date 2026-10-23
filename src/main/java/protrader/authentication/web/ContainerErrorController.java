package protrader.authentication.web;

import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

/** Replaces Boot's white-label HTML page for errors raised by the container itself. */
@RestController
public class ContainerErrorController implements ErrorController {

	@RequestMapping("/error")
	ResponseEntity<ApiError> error(HttpServletRequest request) {
		Object attr = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
		HttpStatus status = attr instanceof Integer c && HttpStatus.resolve(c) != null ? HttpStatus.valueOf(c) : HttpStatus.INTERNAL_SERVER_ERROR;
		return ResponseEntity.status(status).body(ApiError.forStatus(status.value(), status.getReasonPhrase()));
	}
}
