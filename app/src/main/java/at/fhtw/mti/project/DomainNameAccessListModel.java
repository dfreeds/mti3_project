/*
 * Developed by David Fritz 2016.
 */

package at.fhtw.mti.project;

/**
 * Created by dfritz on 25/03/16.
 */
public class DomainNameAccessListModel {
    private String domainName;
    private boolean blacklisted;

    public DomainNameAccessListModel (String domainName)
    {
        this.domainName = domainName;
        blacklisted = false;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public boolean isBlacklisted() {
        return blacklisted;
    }

    public void setBlacklisted(boolean blacklisted) {
        this.blacklisted = blacklisted;
    }

    @Override
    public int hashCode() {
        return domainName.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return this.domainName.equals(((DomainNameAccessListModel) o).domainName);
    }
}
