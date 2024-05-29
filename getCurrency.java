import java.util.Locale;
import java.util.Currency;

/**
 * Helper to get currency value from an Android system
 */
public class getCurrency {
    public static void main(String... args) {
       Locale locale = Locale.getDefault();
       Currency currency = Currency.getInstance(locale);
       System.out.print(currency.getCurrencyCode());
    }
}
