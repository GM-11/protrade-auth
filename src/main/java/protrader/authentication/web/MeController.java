package protrader.authentication.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import protrader.authentication.account.Account;
import protrader.authentication.account.AccountService;
import protrader.authentication.web.Dtos.MeResponse;

@RestController
public class MeController {

	private final AccountService accounts;

	public MeController(AccountService accounts) {
		this.accounts = accounts;
	}

	@GetMapping("/v1/me")
	MeResponse me(@AuthenticationPrincipal AccountPrincipal principal) {
		Account a = accounts.get(principal.accountId());
		return new MeResponse(Long.toString(a.id()), a.email(), a.displayName(), Timestamps.format(a.createdAt()));
	}
}
