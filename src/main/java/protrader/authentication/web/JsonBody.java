package protrader.authentication.web;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller parameter that is the JSON request body, parsed by {@link JsonBodyArgumentResolver}
 * with the gateway's rules (415 / 413 / invalid_json / malformed_json).
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface JsonBody {
}
