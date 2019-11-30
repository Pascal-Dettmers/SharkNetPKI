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
    private Date expirationDate;

    public SharknetPublicKeyImpl(User keyOwner, PublicKey publicKey, Date expirationDate) {
        this.keyOwner = keyOwner;
        this.publicKey = publicKey;
        this.expirationDate = expirationDate;
    }

    @Override
    public String getAlias() {
        return this.keyOwner.getAlias();
    }

    @Override
    public void setAlias(String newAlias) {
        this.keyOwner.setAlias(newAlias);

    }

    @Override
    public String getUuid() {
        return this.keyOwner.getUuid();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Date getExpirationDate() {
        return this.expirationDate;
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
