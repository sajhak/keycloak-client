
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
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
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

	// Mapping between client key key and new registration access token
	// Registration access token is updated (creates a new one, after adding or retriving, or deleting..) always
	Map<String, String> clientKeyToRegAccessTokenMap = new HashMap<String, String>();

	public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
		this.configuration = keyManagerConfiguration;
	}

	public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
		return configuration;
	}

	public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

		OAuthApplicationInfo applicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
		log.info(" Creating Application request  : ["+applicationInfo.getClientName()+"] ");

		String registrationEp = getKeyManagerConfiguration().getParameter(KeyCloakConstants.CLIENT_REG_ENDPOINT);
		String registrationAccessToken = getKeyManagerConfiguration().getParameter(KeyCloakConstants.REGISTRAION_ACCESS_TOKEN);

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
					log.info(" Response from app creation: " + parsedObject.toJSONString());
					applicationInfo = createOAuthAppfromResponse(parsedObject);

					// We need the id when retrieving a single OAuth Client. So we have to maintain a mapping
					// between the consumer key and the ID.
					clientKeyToRegAccessTokenMap.put(applicationInfo.getClientId(),
							String.valueOf(applicationInfo.getParameter("regAccessToken")));

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

		// Get registration access token
		Object regAccessToken = responseMap.get("registrationAccessToken"); // TODO move to constants
		if (regAccessToken != null) {
			info.addParameter("regAccessToken", regAccessToken);
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

	// TODO implement
	public OAuthApplicationInfo updateApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
		return null;
	}

	public void deleteApplication(String applicationName) throws APIManagementException {
		log.info(" Deleting application [" + applicationName + "] ."); // applicationName is clientId
		log.info(" Latest bearer token in delete [ " + clientKeyToRegAccessTokenMap.get(applicationName) + " ].");

		String retrieveEndpoint = getKeyManagerConfiguration().getParameter(KeyCloakConstants.CLIENT_REG_ENDPOINT)+"/"+applicationName;
		String newRegAccessToken = clientKeyToRegAccessTokenMap.get(applicationName);

		HttpDelete httpDelete = new HttpDelete(retrieveEndpoint.trim());
		httpDelete.setHeader(KeyCloakConstants.CONTENT_TYPE, KeyCloakConstants.APPLICATION_JSON_CONTENT_TYPE);
		httpDelete.setHeader(KeyCloakConstants.AUTHORIZATION, KeyCloakConstants.BEARER + newRegAccessToken);

		HttpClient httpClient = new DefaultHttpClient();

		BufferedReader reader = null;
		try {
			HttpResponse response = httpClient.execute(httpDelete);
			int responseCode = response.getStatusLine().getStatusCode();

			HttpEntity entity = response.getEntity();
			reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeyCloakConstants.UTF_8));

			// If successful 204 will be returned.
			if (HttpStatus.SC_NO_CONTENT == responseCode) {

				log.info(" Response from app deletion ");
				// Remove key from map
				clientKeyToRegAccessTokenMap.remove(applicationName);

			} else {
				log.error("Error in app deletion. Response code is ["+responseCode+"].");
			}
		} catch (Exception e) {
			log.error(" Error in deleting application. Reason ["+e.getMessage()+"].");
		} finally {
			//close buffer reader.
			if (reader != null) {
				IOUtils.closeQuietly(reader);
			}
			httpClient.getConnectionManager().shutdown();
		}
	}

	public OAuthApplicationInfo retrieveApplication(String applicationName) throws APIManagementException {
		log.info(" Retrieving application [" + applicationName + "] ."); // applicationName is clientId
		log.info(" Latest bearer token [ " + clientKeyToRegAccessTokenMap.get(applicationName) + " ].");

		String retrieveEndpoint = getKeyManagerConfiguration().getParameter(KeyCloakConstants.CLIENT_REG_ENDPOINT)+"/"+applicationName;
		String newRegAccessToken = clientKeyToRegAccessTokenMap.get(applicationName);

		HttpGet htttpGet = new HttpGet(retrieveEndpoint.trim());
		htttpGet.setHeader(KeyCloakConstants.CONTENT_TYPE, KeyCloakConstants.APPLICATION_JSON_CONTENT_TYPE);
		htttpGet.setHeader(KeyCloakConstants.AUTHORIZATION, KeyCloakConstants.BEARER + newRegAccessToken);

		HttpClient httpClient = new DefaultHttpClient();

		BufferedReader reader = null;
		try {
			HttpResponse response = httpClient.execute(htttpGet);
			int responseCode = response.getStatusLine().getStatusCode();

			JSONObject parsedObject;
			HttpEntity entity = response.getEntity();
			reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeyCloakConstants.UTF_8));

			// If successful 200 will be returned.
			if (HttpStatus.SC_OK == responseCode) {

				parsedObject = getParsedObjectByReader(reader);

				if (parsedObject != null) {
					log.info(" Response from app creation: " + parsedObject.toJSONString());
					OAuthApplicationInfo applicationInfo = createOAuthAppfromResponse(parsedObject);

					// No change in regAccessToken in a retrieval.
					// No need to update the map

					return applicationInfo;
				}
			} else {
				log.error("Error in app retrieval. Response code is ["+responseCode+"].");
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

		log.warn(" ***** Will be returning null ******* ");
		return null;
	}

	// TODO implement
	public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest) throws APIManagementException {
		return null;
	}

	// TODO implement
	public AccessTokenInfo getTokenMetaData(String s) throws APIManagementException {
		return null;
	}


	public OAuthApplicationInfo buildFromJSON(String s) throws APIManagementException {
		return null;
	}

	// TODO implement
	public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {
		return null;
	}


	public boolean registerNewResource(API api, Map map) throws APIManagementException {
		return true;
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

	// TODO implement
	public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
		return null;
	}

	// TODO implement
	public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
		return null;
	}

	// TODO implement
	public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {
		return null;
	}
}
