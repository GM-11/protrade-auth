package protrader.authentication.web;

import java.io.IOException;
import java.util.List;
import java.util.OptionalLong;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import protrader.authentication.token.JwtVerifier;

/**
 * Puts the account id in the security context when a valid bearer token is present. A missing or
 * bad token just leaves the request unauthenticated; the entry point then answers 401.
 * Deliberately not a Spring bean: a bean would also be registered as a plain servlet filter,
 * outside the security chain.
 */
public final class JwtAuthFilter extends OncePerRequestFilter {

	static final String ACCOUNT_ATTRIBUTE = "protrader.accountId";

	private final JwtVerifier verifier;

	public JwtAuthFilter(JwtVerifier verifier) {
		this.verifier = verifier;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String header = request.getHeader("Authorization");
		if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
			OptionalLong account = verifier.verify(header.substring(7).trim());
			if (account.isPresent()) {
				SecurityContext context = SecurityContextHolder.createEmptyContext();
				context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
						new AccountPrincipal(account.getAsLong()), null, List.of()));
				SecurityContextHolder.setContext(context);
				request.setAttribute(ACCOUNT_ATTRIBUTE, account.getAsLong());
			}
		}
		chain.doFilter(request, response);
	}
}
