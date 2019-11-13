package main.de.htw.berlin.s0551733.sharknetpki;

import java.security.PublicKey;
import java.util.Date;

public interface SharknetPublicKey {

    String getAlias();
    String getUuid();
    PublicKey getPublicKey();
    Date getValidityPeriod();
}
