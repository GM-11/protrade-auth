package protrader.authentication.web;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

/** Writes the contract error body from places Spring MVC's advice doesn't reach (servlet and security filters). */
@Component
public class ErrorWriter {

	private final JsonMapper mapper;

	public ErrorWriter(JsonMapper mapper) {
		this.mapper = mapper;
	}

	public void write(HttpServletResponse response, HttpStatus status, String code, String message) throws IOException {
		response.setStatus(status.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.getOutputStream().write(mapper.writeValueAsBytes(ApiError.of(code, message)));
	}
}
