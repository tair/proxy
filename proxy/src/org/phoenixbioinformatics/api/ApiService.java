/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.api;

import java.util.Date;
import java.text.SimpleDateFormat;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.NameValuePair;
import java.io.IOException;
import com.google.gson.Gson;

import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;

import org.phoenixbioinformatics.http.RequestFactory;
import org.apache.http.message.BasicNameValuePair;

import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;

/**
 * This class handles all of the requests to API services
 */
public class ApiService extends AbstractApiService {
  public static String authorizationUrn = "/authorizations";
  public static String metersUrn = "/meters";
  public static String partnerUrn = "/partners";
  public static String pageViewsUrn = "/session-logs/page-views";

  // Output from authorizations/access API call
  public class AccessOutput {
    public String status;
    public String userIdentifier;
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
  public static class PartnerOutput {
    public String partnerId;
    public String sourceUri;
    public String targetUri;
  }

  /**
   * Retrieves all of the partner's information from API serverand store 
   * the information into a HashMap.
   *
   * @param None
   * @return HashMap that contain all of the partner's information, with
   *         sourceUri as the key of the map.
   */
  public static HashMap<String, PartnerOutput> getAllPartnerInfo() {
    HashMap<String, ApiService.PartnerOutput> partnerMap = 
      new HashMap<String, ApiService.PartnerOutput>();
    String urn = partnerUrn+"/patterns/";
    try {
      String content = callApi(urn, RequestFactory.HttpMethod.GET);
      Gson gson = new Gson();
      Type type = new TypeToken<List<PartnerOutput>>(){}.getType();

      ArrayList<PartnerOutput> out  = gson.fromJson(content, type);
      for (PartnerOutput entry : out) {
        partnerMap.put(entry.sourceUri, entry);
      }
    } catch (IOException e) {
      logger.error("Get All Partner API Call Failure ", e);
      return null;
    }
    
    return partnerMap;
  }

  /**
   * Calls the API service and creates a page view entry
   *
   * @param None
   * @return None
   */
  public static void createPageView(String ip, String uri, String partyId, String sessionId) {
    String urn = pageViewsUrn+"/";
    Date curDate = new Date();
    SimpleDateFormat format = new SimpleDateFormat();
    format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ssZ");
    String pageViewDate = format.format(curDate);

    List<NameValuePair> params = new ArrayList<NameValuePair>(2);
    params.add(new BasicNameValuePair("pageViewDate", pageViewDate));
    params.add(new BasicNameValuePair("uri", uri));
    params.add(new BasicNameValuePair("sessionId", sessionId));
    params.add(new BasicNameValuePair("partyId", partyId));
    params.add(new BasicNameValuePair("ip", ip));

    try {
      String content = callApi(urn, RequestFactory.HttpMethod.POST, "", params);
      return;
    } catch (IOException e) {
      logger.debug("Session logging API Call Failure", e);
      return;
    }
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
  public static PartnerOutput getPartnerInfo(String url) {
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
          return entry;
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
  public static AccessOutput checkAccess(String path, String loginKey, String partnerId, String partyId, String remoteIp) {	
    try {
      path = URLEncoder.encode(path, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      logger.debug("Encoding faiure", e);
    }

    String urn = authorizationUrn+"/access/?partnerId="+partnerId+"&url="+path+"&ip="+remoteIp;
    try {
      String content = callApi(urn, RequestFactory.HttpMethod.GET, "secret_key="+loginKey+";partyId="+partyId+";");
	    Gson gson = new Gson();
	    return gson.fromJson(content, AccessOutput.class);
    } catch (IOException e) {
	    logger.debug("Check Access API Call Failure", e);
	    return null;
    }
  }

  /**
   * Retrieves the metering of the client based on the client's IP address.
   * @param ip                  client's IP address.
   * @return String indicating client's metering status. (OK, Warn, Blocked)
   */
  public static String checkMeteringLimit(String ip, String partnerId) {
    String urn = metersUrn+"/ip/"+ip+"/limit/?partnerId="+partnerId;
    
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
   * Increase metering count associated with the given ip address and partnerId by
   * one.
   * @param ip                  remote IP address
   * @param partnerId           partnerId that the client tries to access.
   * @return String indicating the access status. (example: OK, NeedSubscription, NeedLogin)
   */
  public static String incrementMeteringCount(String ip, String partnerId) {
    String urn = metersUrn+"/ip/"+ip+"/increment/?partnerId="+partnerId;
    
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
