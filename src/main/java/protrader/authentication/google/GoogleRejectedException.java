package protrader.authentication.google;

/** Google or our checks said no. The reason is deliberately not carried to the client. */
public class GoogleRejectedException extends RuntimeException {

	public GoogleRejectedException(String reasonForLogs) {
		super(reasonForLogs);
	}
}
