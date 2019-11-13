package main.de.htw.berlin.s0551733.sharknetpki.impl;

import main.de.htw.berlin.s0551733.sharknetpki.SharknetPublicKey;
import main.de.htw.berlin.s0551733.sharknetpki.User;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;
import java.util.Objects;

public class SharknetPublicKeyImpl implements Serializable, SharknetPublicKey {

    private User keyOwner;
    private PublicKey publicKey;
    private Date validityPeriod;

    public SharknetPublicKeyImpl(User keyOwner, PublicKey publicKey, Date validityPeriod) {
        this.keyOwner = keyOwner;
        this.publicKey = publicKey;
        this.validityPeriod = validityPeriod;
    }

    @Override
    public String getAlias() {
        return this.keyOwner.getAlias();
    }

    @Override
    public String getUuid() {
        return this.keyOwner.getUuid();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Date getValidityPeriod() {
        return this.validityPeriod;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SharknetPublicKeyImpl that = (SharknetPublicKeyImpl) o;
        return Objects.equals(this.getUuid(), that.getUuid());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getUuid());
    }
}
