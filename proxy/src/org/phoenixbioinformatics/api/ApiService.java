/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.api;

import org.apache.http.client.methods.CloseableHttpResponse;
import java.io.IOException;
import com.google.gson.Gson;

import java.util.List;
import java.util.ArrayList;

import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;

import org.phoenixbioinformatics.http.RequestFactory;

/**
 * This class handles all of the requests to API services
 */
public class ApiService extends AbstractApiService {
  public static String authorizationUrn = "/authorizations";
  public static String metersUrn = "/meters";
  public static String partnerUrn = "/partners";
  
  // Output from authorizations/access API call
  private class AccessOutput {
    private String status;
  }
  
  // Output from ip/<pk>/increment API call 
  private class IncrementMeteringCountOutput {
    private String message;
  }
  
  // Output from ip/check_limits API call 
  private class CheckMeteringLimitOutput {
    private String status;
  }
  
  // Output from partner/ API call 
  private class PartnerOutput {
    private String partnerId;
    private String name;
  }

  /**
   * Retrieves partner ID based on the request url by making a request to 
   * partner app of the API server.
   * Example: url = "arabidopsis.org"
   *          request to api server: https://testapi.arabidopsis.org/partners?url=arabidopsis.org
   *          returns: partnerId = "tair"
   * @param url                url of client's request
   * @return String indicating the partnerId that the client intends to talk to.
   */
  public static String getPartnerId(String url) {
    String urn = partnerUrn+"/?uri="+url;
    try {
	    String content = callApi(urn, RequestFactory.HttpMethod.GET);
	    Gson gson = new Gson();
	    Type type = new TypeToken<List<PartnerOutput>>(){}.getType();
      
      ArrayList<PartnerOutput> out  = gson.fromJson(content, type);
      if (out.size() > 1) {
        logger.error("multiple partnerId detected for url: "+url);
        for (PartnerOutput entry : out) {
          logger.debug(entry.partnerId);
        }
      }
      else {
        for (PartnerOutput entry : out) {
          return entry.partnerId;
        }
      }
      
	    return null;
    } catch (IOException e) {
	    logger.error("Get Partner Id API Call Failure", e);
      return null;
    }
  }
  
  /**
   * Retrieves the access status of the client in respect to path. At this point,
   * client's partyId, partnerId, and loginKey should be specified. 
   * @param path                resource path that the client tries to access. (e.g: "/news/2015/07/01")
   * @param partyId             client's partyId if path that the client tries to access is not free.
   * @param loginKey            client's login key, if login is required.
   * @param partnerId           partnerId that the client tries to access.
   * @return String indicating the access status. (example: OK, NeedSubscription, NeedLogin)
   */
  public static String checkAccess(String path, String loginKey, String partnerId, String partyId) {	
    String urn = authorizationUrn+"/access/?loginKey="+loginKey+
	    "&partnerId="+partnerId+"&url="+path+"&partyId="+partyId;
    try {
      String content = callApi(urn, RequestFactory.HttpMethod.GET);
	    Gson gson = new Gson();
	    AccessOutput out = gson.fromJson(content, AccessOutput.class);
      
	    return out.status;
    } catch (IOException e) {
	    logger.debug("Check Access API Call Failure", e);
	    return e.getMessage();
    }
  }

  /**
   * Retrieves the metering of the client based on the client's IP address.
   * @param ip                  client's IP address.
   * @return String indicating client's metering status. (OK, Warn, Blocked)
   */
  public static String checkMeteringLimit(String ip) {
    String urn = metersUrn+"/ip/"+ip+"/limit/";
    
    try {
      String content = callApi(urn, RequestFactory.HttpMethod.GET);
      Gson gson = new Gson();
      CheckMeteringLimitOutput out = gson.fromJson(content, CheckMeteringLimitOutput.class);
      
      return out.status;
    } catch (IOException e) {
	    logger.debug("Check Metering Limit API Call Failure", e);
      return e.getMessage();
    }
  }
  
  /**
   * Retrieves the access status of the client in respect to path. At this point,
   * client's partyId, partnerId, and loginKey should be specified.
   * @param path                resource path that the client tries to access. (e.g: "/news/2015/07/01")
   * @param partyId             client's partyId if path that the client tries to access is not free.
   * @param loginKey            client's login key, if login is required.
   * @param partnerId           partnerId that the client tries to access.
   * @return String indicating the access status. (example: OK, NeedSubscription, NeedLogin)
   */
  public static String incrementMeteringCount(String ip) {
    String urn = metersUrn+"/ip/"+ip+"/increment/";
    
    try {
      String content = callApi(urn, RequestFactory.HttpMethod.POST);
      Gson gson = new Gson();
      IncrementMeteringCountOutput out = gson.fromJson(content, IncrementMeteringCountOutput.class);
      String message = out.message;
      
      return message;
    } catch (IOException e) {
	    logger.debug("Increment Metering Count API Call Failure", e);
      return e.getMessage();
    }
  }
}
