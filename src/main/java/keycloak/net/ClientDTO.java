package keycloak.net;

public class ClientDTO {
    private String clientId;
    private String clientSecret;
    private String regAccessToken;

    public ClientDTO(String clientId, String clientSecret, String regAccessToken) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.regAccessToken = regAccessToken;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRegAccessToken() {
        return regAccessToken;
    }

    public void setRegAccessToken(String regAccessToken) {
        this.regAccessToken = regAccessToken;
    }
}
