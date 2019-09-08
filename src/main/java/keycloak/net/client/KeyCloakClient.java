
package keycloak.net.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import keycloak.net.constants.KeyCloakConstants;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
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

	// We need to maintain a mapping between Consumer Key and id. To get details of a specific client,
	// we need to call client registration endpoint using id.
	Map<String, String> nameIdMapping = new HashMap<String, String>();

	public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
		this.configuration = keyManagerConfiguration;
	}

	public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
		return configuration;
	}

	public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

		OAuthApplicationInfo applicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
		log.info(" Creating Application request  : ["+applicationInfo.getClientName()+"] ");

		KeyManagerConfiguration keyManagerConfiguration = getKeyManagerConfiguration();

		String registrationEp = keyManagerConfiguration.getParameter(KeyCloakConstants.CLIENT_REG_ENDPOINT);
		String registrationAccessToken = keyManagerConfiguration.getParameter(KeyCloakConstants.REGISTRAION_ACCESS_TOKEN);

		HttpPost httpPost = new HttpPost(registrationEp.trim());
		HttpClient httpClient = new DefaultHttpClient();

		String messageBody = createMessageBody(applicationInfo);

		httpPost.setEntity(new StringEntity(messageBody, KeyCloakConstants.UTF_8));
		httpPost.setHeader(KeyCloakConstants.CONTENT_TYPE, KeyCloakConstants.APPLICATION_JSON_CONTENT_TYPE);
		httpPost.setHeader(KeyCloakConstants.AUTHORIZATION, KeyCloakConstants.BEARER + registrationAccessToken);

		BufferedReader reader = null;
		try {
			HttpResponse response = httpClient.execute(httpPost);
			int responseCode = response.getStatusLine().getStatusCode();

			JSONObject parsedObject;
			HttpEntity entity = response.getEntity();
			reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeyCloakConstants.UTF_8));

			// If successful a 201 will be returned.
			if (HttpStatus.SC_CREATED == responseCode) {

				parsedObject = getParsedObjectByReader(reader);
				if (parsedObject != null) {
					applicationInfo = createOAuthAppfromResponse(parsedObject);

					// We need the id when retrieving a single OAuth Client. So we have to maintain a mapping
					// between the consumer key and the ID.
					nameIdMapping.put(applicationInfo.getClientId(), String.valueOf(applicationInfo.getParameter("id")));

					return applicationInfo;
				}
			} else {
				log.error("Error in app creation. Response code is ["+responseCode+"].");
			}
		} catch (Exception e) {
			log.error(" Error in creating application. Reason ["+e.getMessage()+"].");
		} finally {
			//close buffer reader.
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			httpClient.getConnectionManager().shutdown();
		}
		return null;
	}

	/**
	 * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
	 *
	 * @param reader {@code BufferedReader} object from response.
	 * @return JSON payload as a name value map.
	 */
	private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {

		JSONObject parsedObject = null;
		JSONParser parser = new JSONParser();
		if (reader != null) {
			parsedObject = (JSONObject) parser.parse(reader);
		}
		return parsedObject;
	}

	private OAuthApplicationInfo createOAuthAppfromResponse(Map responseMap) {
		OAuthApplicationInfo info = new OAuthApplicationInfo();
		Object clientId = responseMap.get(KeyCloakConstants.CLIENT_ID);
		info.setClientId((String) clientId);

		Object clientSecret = responseMap.get(KeyCloakConstants.CLIENT_SECRET);
		info.setClientSecret((String) clientSecret);

		Object id = responseMap.get("id");
		info.addParameter("id", id);

		Object contactName = responseMap.get(KeyCloakConstants.CLIENT_CONTACT_NAME);
		if (contactName != null) {
			info.addParameter("contactName", contactName);
		}

		Object contactMail = responseMap.get(KeyCloakConstants.CLIENT_CONTAT_EMAIL);
		if (contactMail != null) {
			info.addParameter("contactMail", contactMail);
		}

		Object scopes = responseMap.get(KeyCloakConstants.SCOPES);
		if (scopes != null) {
			info.addParameter("scopes", scopes);
		}

		return info;
	}

	private String createMessageBody(OAuthApplicationInfo applicationInfo) {
		Map<String, Object> paramMap = new HashMap<String, Object>();
		paramMap.put("enabled", "true");
		paramMap.put("clientId", applicationInfo.getClientName()); // TODO *** clientid or client name ??
		paramMap.put("protocol", "openid-connect");
		paramMap.put("rootUrl", applicationInfo.getCallBackURL());

		String jsonString = JSONObject.toJSONString(paramMap);
		log.info(" JSON body constructed : " + jsonString);

		return jsonString;
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
