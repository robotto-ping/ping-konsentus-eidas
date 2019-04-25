package com.pingidentity.pingaccess.robotto.rules.konsentus;


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;


import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.pa.sdk.accessor.tps.ThirdPartyServiceAccessor;
import com.pingidentity.pa.sdk.accessor.tps.ThirdPartyServiceModel;
import com.pingidentity.pa.sdk.http.Body;
import com.pingidentity.pa.sdk.http.Exchange;
import com.pingidentity.pa.sdk.http.Headers;
import com.pingidentity.pa.sdk.http.Method;
import com.pingidentity.pa.sdk.http.client.ClientRequest;
import com.pingidentity.pa.sdk.http.client.ClientResponse;
import com.pingidentity.pa.sdk.http.client.HttpClient;
import com.pingidentity.pa.sdk.interceptor.Outcome;
import com.pingidentity.pa.sdk.policy.AccessException;
import com.pingidentity.pa.sdk.policy.AsyncRuleInterceptorBase;
import com.pingidentity.pa.sdk.policy.ErrorHandlingCallback;
import com.pingidentity.pa.sdk.policy.Rule;
import com.pingidentity.pa.sdk.policy.SimplePluginConfiguration;
import com.pingidentity.pa.sdk.policy.config.ErrorHandlerConfigurationImpl;
import com.pingidentity.pa.sdk.policy.config.ErrorHandlerUtil;
import com.pingidentity.pa.sdk.policy.error.RuleInterceptorErrorHandlingCallback;
import com.pingidentity.pa.sdk.ssl.SslData;
import com.pingidentity.pa.sdk.ui.ConfigurationBuilder;
import com.pingidentity.pa.sdk.ui.ConfigurationField;
import com.pingidentity.pa.sdk.ui.ConfigurationType;
import com.pingidentity.pa.sdk.ui.UIElement;
import com.pingidentity.pa.sdk.policy.RuleInterceptorCategory;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * 
 * @author robertotto
 * 
 * Please note that this sample code is provided as-is without any warranty or support 
 *
 */


@Rule(category = RuleInterceptorCategory.AccessControl,
type = "EIDASTPPAuth",
expectedConfiguration = KonsentusEIDASRule.Configuration.class,
label = "EIDAS TPP Auth")


public class KonsentusEIDASRule extends AsyncRuleInterceptorBase<KonsentusEIDASRule.Configuration> {
	
	private static final Logger logger = LoggerFactory.getLogger(KonsentusEIDASRule.class);
	private static final ObjectMapper objectMapper = new ObjectMapper();
	private static final String PAYMENTS_SCOPE="payments";
	private static final String ACCOUNTS_SCOPE="accounts";
	private static final int PISP_ROLE_IDENTIFIER = 7;
	private static final int AISP_ROLE_IDENTIFIER = 8;

	 
	 @Override
	    public ErrorHandlingCallback getErrorHandlingCallback()
	    {
	        return new RuleInterceptorErrorHandlingCallback(getTemplateRenderer(),
	                                                        getConfiguration().getErrorHandlerConfiguration());
	    }

	@Override
	public CompletionStage<Outcome> handleRequest(Exchange exchange) {
		
		logger.info("Evaluating rule KonsentusEIDASRule");
		SslData ssd = exchange.getSslData();
		List<X509Certificate> chain = ssd.getClientCertificateChain();
		
		X509Certificate cert = chain.get(0);
		
		 if (cert == null) {
			 logger.info("Client certificate not found - failing");
			 return CompletableFuture.completedFuture(Outcome.RETURN);
		 }
		 try {
			 logger.info("Found client certificate: " + cert.getSubjectDN().getName());
			 logger.debug("Found client certificate: " + Base64.getEncoder().encodeToString(cert.getEncoded()));
			 logger.debug("Request Content Type {}", exchange.getRequest().getHeaders().getContentType().toString());
			 String scopes = "";
			 Body body = exchange.getRequest().getBody();
			 body.read(); 
			 if (exchange.getRequest().getHeaders().getContentType().toString().equals("application/x-www-form-urlencoded")) {
				 Map<String, String[]> formParams = body.parseFormParams();
				 scopes = formParams.get("scope")[0];
			} else  if (exchange.getRequest().getHeaders().getContentType().toString().equals("application/json")) {
				JsonNode requestBody = objectMapper.readTree(body.getContent());
				scopes = requestBody.get("scope").asText();
			}
			logger.info("Requested scopes: {}", scopes);
		/*	if (!(scopes.contains(PAYMENTS_SCOPE) || scopes.contains(ACCOUNTS_SCOPE))) {
				logger.info("No Open Banking scopes requested");
				return CompletableFuture.completedFuture(Outcome.CONTINUE);
			} */
			return sendKonsentusRequest(this.getHttpClient(), this.getConfiguration().getKonsentusService(), Base64.getEncoder().encodeToString(cert.getEncoded()), scopes);
			 
		} catch (CertificateEncodingException | AccessException | IOException e) {
			e.printStackTrace();
			return CompletableFuture.completedFuture(Outcome.RETURN);
		}
		
	}

	
	private CompletionStage<Outcome> sendKonsentusRequest(HttpClient httpClient,
            ThirdPartyServiceModel model, String certificate, String scopes)
	{
		Headers headers = ClientRequest.createHeaders();
		headers.setAccept(Collections.singletonList("application/json"));
		headers.add("fi_reference_id", "testFI");
		headers.add("eidas", certificate);
		headers.add("version", "1");
		String unencodedBasicToken = this.getConfiguration().getUsername() + ":" + this.getConfiguration().getPassword();
		String basicToken = Base64.getEncoder().encodeToString(unencodedBasicToken.getBytes());
		logger.debug("Basic Auth Token {}", basicToken);
		headers.setAuthorization("Basic " + basicToken);
		ClientRequest request = new ClientRequest(Method.GET,
				"/v1/psp/eidas?jurisdiction=" + getConfiguration().getJurisdiction(),
				headers);

		return httpClient.send(request, model).thenApply(clientResponse -> parseKonsentusResponse(clientResponse, scopes));
	}
	
	private Outcome parseKonsentusResponse(ClientResponse clientResponse, String scopes) {
		logger.info("KONSENTUS status " + clientResponse.getStatus());
		logger.info("Konsentus response: {}", new String(clientResponse.getBody(), StandardCharsets.UTF_8));
		try {
			JsonNode konsentusResponse = objectMapper.readTree(clientResponse.getBody());
			JsonNode eIDASValidity = konsentusResponse.get("eIDAS").get("validity");
			logger.debug("eIDASValidity node: {}", eIDASValidity);
			JsonNode registerEntries =  konsentusResponse.get("homeRegister");
			logger.info("registerEntries node: {}", registerEntries);
			boolean validQTSP = eIDASValidity.get("validQTSP").asBoolean();
			boolean validSignature = eIDASValidity.get("validSignature").asBoolean();
			boolean notRevoked = eIDASValidity.get("notRevoked").asBoolean();
			boolean notExpired = eIDASValidity.get("notExpired").asBoolean();
			if (!(validQTSP && validSignature && notRevoked && notExpired)) {
				logger.info("Certificate validity issue");
				logger.info("eIDASValidity node: {}", eIDASValidity);
				return Outcome.RETURN; 
			}
			List<Integer> roles = new ArrayList<Integer>();
			Iterator<JsonNode> tppEntries = registerEntries.get("categoryEntries").elements();
			while (tppEntries.hasNext()) {
				JsonNode tppEntry = tppEntries.next();
				logger.debug("TPP node: {}", tppEntry.asText());
				if (tppEntry.get("pspAuthStatus").asText().equals("Authorised")) {
					logger.info("Authorised TPP register entry with legal name {}", tppEntry.get("pspLegalName"));
					Iterator<JsonNode> tppRoles = tppEntry.get("pspPaymentServices").elements();
					while (tppRoles.hasNext()) 
						roles.add(tppRoles.next().asInt());
				}
			}
			logger.debug("TPP roles: {}", roles);
			if (scopes.contains(PAYMENTS_SCOPE) && !roles.contains(PISP_ROLE_IDENTIFIER)) {
				logger.info("TPP is not authorised for payments scope");
				logger.info("TPP roles: {}", roles);
				return Outcome.RETURN; 
			}
			if (scopes.contains(ACCOUNTS_SCOPE) && !roles.contains(AISP_ROLE_IDENTIFIER)) {
				logger.info("TPP is not authorised for accounts scope");
				logger.info("TPP roles: {}", roles);
				return Outcome.RETURN; 
			}
		} catch (Exception e) {
			e.printStackTrace();
			logger.info("Exception: {}", e.getMessage());
			return Outcome.RETURN; 
		}
		return Outcome.CONTINUE; 
	}
	
	  @Override
	    public List<ConfigurationField> getConfigurationFields()
	    {
	        return ConfigurationBuilder.from(Configuration.class)
	                                   .addAll(ErrorHandlerUtil.getConfigurationFields())
	                                   .toConfigurationFields();
	    }
	  
	public static class Configuration extends SimplePluginConfiguration
    {
		 @UIElement(order = 10,
	                type = ConfigurationType.TEXT,
	                label = "Konsentus Username",
	                required = true)
	        @NotNull
	        private String username;
		 @UIElement(order = 15,
	                type = ConfigurationType.CONCEALED,
	                label = "Konsentus Password",
	                required = true)
	        @NotNull
	        private String password;

		 @UIElement(order = 30,
	                type = ConfigurationType.TEXT,
	                label = "Konsentus Jurisdiction (2 letter country code)",
	                required = true)
	        @NotNull
	        private String jurisdiction;

			public String getJurisdiction() {
			return jurisdiction;
		}

		public void setJurisdiction(String jurisdiction) {
			this.jurisdiction = jurisdiction;
		}

			public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

			@UIElement(order = 20,
	                type = ConfigurationType.SELECT,
	                label = "Konsentus Service",
	                modelAccessor = ThirdPartyServiceAccessor.class,
	                required = true)
	        @NotNull
	        private ThirdPartyServiceModel konsentusService;
	        
	        public ThirdPartyServiceModel getKonsentusService() {
				return konsentusService;
			}

			public void setKonsentusService(ThirdPartyServiceModel konsentusService) {
				this.konsentusService = konsentusService;
			}

			@JsonUnwrapped
	        @Valid
	        private ErrorHandlerConfigurationImpl errorHandlerConfiguration;
	        
	        public ErrorHandlerConfigurationImpl getErrorHandlerConfiguration()
	        {
	            return errorHandlerConfiguration;
	        }

	        public void setErrorHandlerConfiguration(ErrorHandlerConfigurationImpl errorHandlerConfiguration)
	        {
	            this.errorHandlerConfiguration = errorHandlerConfiguration;
	        }
    }

}
