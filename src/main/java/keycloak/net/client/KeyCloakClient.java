
package keycloak.net.client;

import java.util.Map;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;

public class KeyCloakClient extends AbstractKeyManager {

	private static final Log log = LogFactory.getLog(KeyCloakClient.class);
	private KeyManagerConfiguration configuration;


	public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
		this.configuration = keyManagerConfiguration;
	}

	public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
		return configuration;
	}

	public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
		log.info(" Creating Application request : ["+oAuthAppRequest.getOAuthApplicationInfo().getClientName()+"] ");

		log.info(" Calling Keycloak .... ");
		return null;
	}

	public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
		return null;
	}

	public void deleteApplication(String s) throws APIManagementException {

	}

	public OAuthApplicationInfo retrieveApplication(String s) throws APIManagementException {
		return null;
	}

	public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest) throws APIManagementException {
		return null;
	}

	public AccessTokenInfo getTokenMetaData(String s) throws APIManagementException {
		return null;
	}


	public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
		return null;
	}

	public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
		return null;
	}


	public boolean registerNewResource(API api, Map map) throws APIManagementException {
		return false;
	}

	public Map getResourceByApiId(String s) throws APIManagementException {
		return null;
	}

	public boolean updateRegisteredResource(API api, Map map) throws APIManagementException {
		return false;
	}

	public void deleteRegisteredResourceByAPIId(String s) throws APIManagementException {

	}

	public void deleteMappedApplication(String s) throws APIManagementException {

	}

	public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
		return null;
	}

	public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
		return null;
	}

	public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {
		return null;
	}
}
