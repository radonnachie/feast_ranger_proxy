package za.co.discovery.health.bigdata.ranger.feast;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;

public class SimpleFilterBasedLdapUserSearch  extends FilterBasedLdapUserSearch {

    public SimpleFilterBasedLdapUserSearch(String searchBase, String searchFilter, BaseLdapPathContextSource contextSource) {
        super(searchBase, searchFilter, contextSource);
    }

    @Override
    public DirContextOperations searchForUser(String username) {
        return super.searchForUser(username.split("@")[0]);
    }
}
