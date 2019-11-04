package main.de.htw.berlin.s0551733.sharknetpki;

import java.security.PublicKey;

public interface SharknetPublicKey {

    String getAlias();
    String getUuid();
    PublicKey getPublicKey();
}
