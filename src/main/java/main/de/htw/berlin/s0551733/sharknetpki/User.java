package main.de.htw.berlin.s0551733.sharknetpki;

public interface User {
    String getUuid();
    String getAlias();
    void setAlias(String newAlias);
}
