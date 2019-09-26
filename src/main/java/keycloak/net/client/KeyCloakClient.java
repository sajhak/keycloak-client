package keycloak.net.client;

import keycloak.net.ClientDTO;
import keycloak.net.constants.KeyCloakConstants;
import org.apache.axis2.util.URL;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.json.JSONException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.*;

public class KeyCloakClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(KeyCloakClient.class);
    private static final String OAUTH_RESPONSE_ACCESSTOKEN = "access_token";
    private static final String OAUTH_RESPONSE_EXPIRY_TIME = "expires_in";
    private static final String GRANT_TYPE_VALUE = "client_credentials";
    private static final String GRANT_TYPE_PARAM_VALIDITY = "validity_period";
    private static final String CONFIG_ELEM_OAUTH = "OAuth";
    // Mapping between client key key and new registration access token
    // Registration access token is updated (creates a new one, after adding or retriving, or deleting..) always
    Map<String, ClientDTO> clientKeyToRegAccessTokenMap = new HashMap<String, ClientDTO>();
    private KeyManagerConfiguration configuration;

    public void loadConfiguration(KeyManagerConfiguration keyManagerConfiguration) throws APIManagementException {
        this.configuration = keyManagerConfiguration;
    }

    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    public OAuthApplicationInfo createApplication(OAuthAppRequest oAuthAppRequest) throws APIManagementException {

        OAuthApplicationInfo applicationInfo = oAuthAppRequest.getOAuthApplicationInfo();
        log.info(" Creating Application request  : [" + applicationInfo.getClientName() + "] ");

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

                    // Adding to db map
                    clientKeyToRegAccessTokenMap.put(applicationInfo.getClientId(),
                            new ClientDTO(applicationInfo.getClientId(), applicationInfo.getClientSecret(),
                                    String.valueOf(applicationInfo.getParameter("regAccessToken"))));

                    return applicationInfo;
                }
            } else {
                log.error("Error in app creation. Response code is [" + responseCode + "].");
            }
        } catch (Exception e) {
            log.error(" Error in creating application. Reason [" + e.getMessage() + "].");
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
        paramMap.put("serviceAccountsEnabled", "true");
        paramMap.put("publicClient", "false");

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

        String retrieveEndpoint = getKeyManagerConfiguration().getParameter(KeyCloakConstants.CLIENT_REG_ENDPOINT) + "/" + applicationName;
        String newRegAccessToken = clientKeyToRegAccessTokenMap.get(applicationName).getRegAccessToken();

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
                log.error("Error in app deletion. Response code is [" + responseCode + "].");
            }
        } catch (Exception e) {
            log.error(" Error in deleting application. Reason [" + e.getMessage() + "].");
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

        String retrieveEndpoint = getKeyManagerConfiguration().getParameter(KeyCloakConstants.CLIENT_REG_ENDPOINT) + "/" + applicationName;
        String newRegAccessToken = clientKeyToRegAccessTokenMap.get(applicationName).getRegAccessToken();

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
                log.error("Error in app retrieval. Response code is [" + responseCode + "].");
            }
        } catch (Exception e) {
            log.error(" Error in creating application. Reason [" + e.getMessage() + "].");
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


    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest accessTokenRequest) throws APIManagementException {
        String newAccessToken;
        long validityPeriod;
        AccessTokenInfo tokenInfo = null;

        if (accessTokenRequest == null) {
            log.warn("No information available to generate Token.");
            return null;
        }

        String tokenEndpoint = getKeyManagerConfiguration().getParameter(KeyCloakConstants.TOKEN_URL);
        //To revoke tokens we should call revoke API deployed in API gateway.
        String revokeEndpoint = getKeyManagerConfiguration().getParameter(KeyCloakConstants.REVOKE_URL);
        URL keyMgtURL = new URL(tokenEndpoint);
        int keyMgtPort = keyMgtURL.getPort();
        String keyMgtProtocol = keyMgtURL.getProtocol();

        // Call the /revoke only if there's a token to be revoked.
        try {
            if (accessTokenRequest.getTokenToRevoke() != null && !accessTokenRequest.getTokenToRevoke().isEmpty()) {
                URL revokeEndpointURL = new URL(revokeEndpoint);
                String revokeEndpointProtocol = revokeEndpointURL.getProtocol();
                int revokeEndpointPort = revokeEndpointURL.getPort();

                HttpPost httpRevokePost = new HttpPost(revokeEndpoint);

                // Request parameters.
                List<NameValuePair> revokeParams = new ArrayList<NameValuePair>(3);
                revokeParams.add(new BasicNameValuePair(OAuth.OAUTH_CLIENT_ID, accessTokenRequest.getClientId()));
                revokeParams.add(new BasicNameValuePair(OAuth.OAUTH_CLIENT_SECRET, accessTokenRequest.getClientSecret()));
                revokeParams.add(new BasicNameValuePair("token", accessTokenRequest.getTokenToRevoke()));


                //Revoke the Old Access Token
                httpRevokePost.setEntity(new UrlEncodedFormEntity(revokeParams, "UTF-8"));
                int statusCode;
                try {
                    HttpResponse revokeResponse = executeHTTPrequest(revokeEndpointPort, revokeEndpointProtocol,
                            httpRevokePost);
                    statusCode = revokeResponse.getStatusLine().getStatusCode();
                } finally {

                }

                if (statusCode != 200) {
                    throw new APIManagementException("Token revoke failed : HTTP error code : " + statusCode);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully submitted revoke request for old application token. HTTP status : 200");
                    }
                }
            }

            // When validity time set to a negative value, a token is considered never to expire.
            if (accessTokenRequest.getValidityPeriod() == OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
                // Setting a different -ve value if the set value is -1 (-1 will be ignored by TokenValidator)
                accessTokenRequest.setValidityPeriod(-2L);
            }

            //Generate New Access Token
            HttpPost httpTokpost = new HttpPost(tokenEndpoint);
            List<NameValuePair> tokParams = new ArrayList<NameValuePair>();
            tokParams.add(new BasicNameValuePair(OAuth.OAUTH_GRANT_TYPE, GRANT_TYPE_VALUE));
            tokParams.add(new BasicNameValuePair(GRANT_TYPE_PARAM_VALIDITY,
                    Long.toString(accessTokenRequest.getValidityPeriod())));
            tokParams.add(new BasicNameValuePair(OAuth.OAUTH_CLIENT_ID, accessTokenRequest.getClientId()));
            tokParams.add(new BasicNameValuePair(OAuth.OAUTH_CLIENT_SECRET, accessTokenRequest.getClientSecret()));

            String scopes = String.join(" ", accessTokenRequest.getScope());
            tokParams.add(new BasicNameValuePair("scope", scopes));

            httpTokpost.setEntity(new UrlEncodedFormEntity(tokParams, "UTF-8"));
            try {
                HttpResponse tokResponse = executeHTTPrequest(keyMgtPort, keyMgtProtocol, httpTokpost);
                HttpEntity tokEntity = tokResponse.getEntity();

                if (tokResponse.getStatusLine().getStatusCode() != 200) {
                    throw new APIManagementException("Error occurred while calling token endpoint: HTTP error code : " +
                            tokResponse.getStatusLine().getStatusCode());
                } else {
                    tokenInfo = new AccessTokenInfo();
                    String responseStr = EntityUtils.toString(tokEntity);
                    org.json.JSONObject obj = new org.json.JSONObject(responseStr);
                    newAccessToken = obj.get(OAUTH_RESPONSE_ACCESSTOKEN).toString();
                    validityPeriod = Long.parseLong(obj.get(OAUTH_RESPONSE_EXPIRY_TIME).toString());
                    if (obj.has("scope")) {
                        tokenInfo.setScope(((String) obj.get("scope")).split(" "));
                    }
                    tokenInfo.setAccessToken(newAccessToken);
                    tokenInfo.setValidityPeriod(validityPeriod);
                }
            } finally {
            }
        } catch (ClientProtocolException e) {
            handleException("Error while creating token - Invalid protocol used", e);
        } catch (UnsupportedEncodingException e) {
            handleException("Error while preparing request for token/revoke APIs", e);
        } catch (IOException e) {
            handleException("Error while creating tokens - " + e.getMessage(), e);
        } catch (JSONException e) {
            handleException("Error while parsing response from token api", e);
        }

        return tokenInfo;
    }


    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

        String introspectionURL = getKeyManagerConfiguration().getParameter(KeyCloakConstants.INTROSPECTION_URL);
        String introspectionConsumerKey = getKeyManagerConfiguration().getParameter(KeyCloakConstants.INTROSPECTION_CK);
        String introspectionConsumerSecret = getKeyManagerConfiguration().getParameter(KeyCloakConstants.INTROSPECTION_CS);

        // Call token introspection endpoint
        HttpPost httpPost = new HttpPost(introspectionURL.trim());
        HttpClient httpClient = new DefaultHttpClient();

        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("token", accessToken));
        params.add(new BasicNameValuePair("client_id", introspectionConsumerKey));
        params.add(new BasicNameValuePair("client_secret", introspectionConsumerSecret));

        BufferedReader reader = null;

        try {

            httpPost.setEntity(new UrlEncodedFormEntity(params, KeyCloakConstants.UTF_8));
            httpPost.setHeader(KeyCloakConstants.CONTENT_TYPE, KeyCloakConstants.URL_ENCODED_CONTENT_TYPE);

            HttpResponse response = httpClient.execute(httpPost);
            int responseCode = response.getStatusLine().getStatusCode();

            JSONObject parsedObject;
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeyCloakConstants.UTF_8));

            if (HttpStatus.SC_OK == responseCode) {

                parsedObject = getParsedObjectByReader(reader);

                if (parsedObject != null) {
                    log.info(" Response from app creation: " + parsedObject.toJSONString());
                    return createAccessTokenInfoFromResponse(parsedObject);
                }
            } else {
                log.error("Error in token validation. Response code is [" + responseCode + "].");
            }
        } catch (Exception e) {
            log.error(" Error in token validation. Reason [" + e.getMessage() + "].");
        } finally {
            //close buffer reader.
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            httpClient.getConnectionManager().shutdown();
        }

        return new AccessTokenInfo();
    }

    private AccessTokenInfo createAccessTokenInfoFromResponse(Map parsedObject) {
        AccessTokenInfo accessTokenInfo = new AccessTokenInfo();

        String clientId = (String) parsedObject.get("client_id");
        log.info("Client id: " + clientId);
        Boolean isTokenValid = (Boolean) parsedObject.get("active");
        log.info("IsTokenValid: " + isTokenValid);
        Long expiryTime = (Long) parsedObject.get("exp");
        log.info("Expiry Time: " + expiryTime);
        Long issueTime = (Long) parsedObject.get("iat");
        log.info("Issue Time: " + issueTime);

        // If token is invalid
        if (!isTokenValid) {
            accessTokenInfo.setTokenValid(false);
            accessTokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
            return accessTokenInfo;
        }

        long currentTime = System.currentTimeMillis();

        accessTokenInfo.setConsumerKey(clientId);
        accessTokenInfo.setTokenValid(true);
        accessTokenInfo.setValidityPeriod(expiryTime-currentTime);
        accessTokenInfo.setIssuedTime(issueTime);

        // TODO scopes
        //accessTokenInfo.setScope(null);

        return accessTokenInfo;
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

    // FIXME - wrong impl. Should not call DB. Tokens are not stored in db
    public Set<String> getActiveTokensByConsumerKey(String consumerKey) throws APIManagementException {
        //return new HashSet<String>();
        return null;
    }

    // FIXME - wrong impl. Should not call DB. Tokens are not stored in db
    public AccessTokenInfo getAccessTokenByConsumerKey(String consumerKey) throws APIManagementException {
//		AccessTokenInfo accessTokenInfo = new AccessTokenInfo();
//		accessTokenInfo.setAccessToken("");
//		return accessTokenInfo;
        return null;
    }

    // TODO implement
    public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {
        return null;
    }

    private HttpResponse executeHTTPrequest(int port, String protocol, HttpPost httpPost) throws IOException {
        HttpClient httpClient = APIUtil.getHttpClient(port, protocol);
        return httpClient.execute(httpPost);
    }
}
