package main.de.htw.berlin.s0551733.sharknetpki.interfaces;

import java.security.PublicKey;
import java.util.Date;

public interface SharknetPublicKey {

    User getOwner();
    void setAlias(String newAlias);
    PublicKey getPublicKey();
    Date getExpirationDate();
}
