package protrader.authentication.web;

import java.io.IOException;

import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import jakarta.servlet.http.HttpServletRequest;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.cfg.CoercionAction;
import tools.jackson.databind.cfg.CoercionInputShape;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.type.LogicalType;

/**
 * Same request handling as order_gateway/handlers: Content-Type must be JSON (415), body at most
 * 16 KB (413), unparseable JSON or unknown fields give invalid_json (400), anything after the JSON
 * object gives malformed_json (400). Parse errors never echo the body back.
 */
public class JsonBodyArgumentResolver implements HandlerMethodArgumentResolver {

	static final int MAX_BODY_BYTES = 16 * 1024;

	// trailing data is checked by hand below, to tell it apart (malformed_json) from bad content (invalid_json)
	private final JsonMapper mapper = JsonMapper.builder()
			.enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
			.disable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
			.withCoercionConfig(LogicalType.Textual, c -> c
					.setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
					.setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
					.setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail))
			.build();

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return parameter.hasParameterAnnotation(JsonBody.class);
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
			WebDataBinderFactory binderFactory) throws Exception {
		HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
		if (!isJson(request.getContentType())) {
			throw new ApiException(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "content_type_must_be_json", "Content-Type must be application/json");
		}
		if (request.getContentLengthLong() > MAX_BODY_BYTES) {
			throw tooLarge();
		}
		byte[] body = readBounded(request);

		ObjectReader reader = mapper.readerFor(parameter.getParameterType());
		try (JsonParser parser = reader.createParser(body)) {
			Object value = reader.readValue(parser);
			if (value == null) {
				throw invalidJson();
			}
			try {
				if (parser.nextToken() != null) {
					throw malformed();
				}
			} catch (JacksonException e) {
				throw malformed();
			}
			return value;
		} catch (JacksonException e) {
			throw invalidJson();
		}
	}

	private static boolean isJson(String contentType) {
		if (contentType == null) {
			return false;
		}
		try {
			MediaType type = MediaType.parseMediaType(contentType);
			return MediaType.APPLICATION_JSON.equalsTypeAndSubtype(type);
		} catch (InvalidMediaTypeException e) {
			return false;
		}
	}

	private static byte[] readBounded(HttpServletRequest request) throws IOException {
		byte[] body = request.getInputStream().readNBytes(MAX_BODY_BYTES + 1);
		if (body.length > MAX_BODY_BYTES) {
			throw tooLarge();
		}
		return body;
	}

	private static ApiException tooLarge() {
		return new ApiException(HttpStatus.CONTENT_TOO_LARGE, "request_too_large", "request body is larger than 16 KB");
	}

	private static ApiException invalidJson() {
		return new ApiException(HttpStatus.BAD_REQUEST, "invalid_json", "body is not valid JSON for this endpoint");
	}

	private static ApiException malformed() {
		return new ApiException(HttpStatus.BAD_REQUEST, "malformed_json", "extra data after the JSON object");
	}
}
