/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.api;


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.phoenixbioinformatics.http.RequestFactory;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;


/**
 * Handles all requests to API services
 */
public class ApiService extends AbstractApiService {
  /** logger for this class */
  private static final Logger logger = LogManager.getLogger(ApiService.class);

  // error messages
  private static final String INCREMENT_METERING_COUNT_ERROR =
    "API call to increment metering count failed";
  private static final String METERING_LIMIT_ERROR =
    "API call to check metering limit failed";
  private static final String ACCESS_ERROR =
    "API call to check resource access failed";
  private static final String UNEXPECTED_ERROR =
    "API call failed with unexpected error";
  private static final String PARTNER_ID_ERROR =
    "API call to get partner id failed";
  private static final String MULTIPLE_PARTNER_ERROR =
    "Multiple partner IDs detected for URI: ";
  // string constants
  public static final String AUTHORIZATION_URN = "/authorizations";
  public static final String METERS_URN = "/meters";
  public static final String PARTNERS_URN = "/partners";
  public static final String PAGE_VIEWS_URN = "/session-logs/page-views";
  private static final String PATTERNS_URI = "/patterns/";

  // error messages
  private static final String ALL_PARTNER_ERROR =
    "Get All Partner API Call error";
  private static final String LOGGING_ERROR =
    "Page view logging API Call error on URI ";

  /**
   * Data transfer object for authorization API call
   */
  public class AccessOutput {
    public String status;
    public String userIdentifier;
  }

  /**
   * Data transfer object for increment API call
   */
  private class IncrementMeteringCountOutput {
    private String message;
  }

  /**
   * Data transfer object for meteringLimit API output data
   */
  private class CheckMeteringLimitOutput {
    private String status;
  }

  /**
   * Data transfer object for partner API output data
   */
  public static class PartnerOutput {
    public String partnerId;
    public String sourceUri;
    public String targetUri;
  }

  /**
   * Retrieves all partner information from the API
   *
   * @return HashMap that contains all of the partner's API output data keyed on
   *         sourceUri
   */
  public static HashMap<String, PartnerOutput> getAllPartnerInfo() {
    HashMap<String, ApiService.PartnerOutput> partnerMap =
      new HashMap<String, ApiService.PartnerOutput>();
    String urn = PARTNERS_URN + PATTERNS_URI;
    try {
      String content = callApi(urn, RequestFactory.HttpMethod.GET);
      Gson gson = new Gson();
      Type type = new TypeToken<List<PartnerOutput>>() {
      }.getType();

      ArrayList<PartnerOutput> out = gson.fromJson(content, type);
      for (PartnerOutput entry : out) {
        partnerMap.put(entry.sourceUri, entry);
      }
    } catch (IOException e) {
      logger.error(ALL_PARTNER_ERROR, e);
      return null;
    }

    return partnerMap;
  }

  /**
   * Creates a page view log entry
   */
  public static void createPageView(String ip, String uri, String partyId,
                                    String sessionId) {
    String urn = PAGE_VIEWS_URN + "/";
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
      callApi(urn, RequestFactory.HttpMethod.POST, "", params);
    } catch (Exception e) {
      logger.error(LOGGING_ERROR + urn);
      StringBuilder builder = new StringBuilder("[parameters: ");
      String sep = "";
      for (NameValuePair pair : params) {
        builder.append(sep);
        builder.append(pair.getName());
        builder.append("=");
        builder.append(pair.getValue());
        sep = ", ";
      }
      builder.append("]");
      logger.error(builder.toString(), e);
    }
  }

  /**
   * Retrieves partner pattern information based on a source URI by making a request to
   * partner app of the API server. Example: URI = "arabidopsis.org" request to
   * API server: https://testapi.arabidopsis.org/partners?sourceUri=arabidopsis.org
   * returns: partnerId = "tair", targetUri = "http://back-prod.arabidopsis.org"
   * 
   * @param uri URI of client's request
   * @return unique identifier for the partner corresponding to the request URI
   */
  public static PartnerOutput getPartnerInfo(String uri) {
    String urn = PARTNERS_URN + PATTERNS_URI + "?sourceUri=" + uri;
    try {
      String content = callApi(urn, RequestFactory.HttpMethod.GET);
      Gson gson = new Gson();
      Type type = new TypeToken<List<PartnerOutput>>() {
      }.getType();

      ArrayList<PartnerOutput> out = gson.fromJson(content, type);
      if (out.size() > 1) {
        logger.error(MULTIPLE_PARTNER_ERROR + uri);
        for (PartnerOutput entry : out) {
          logger.debug(entry.partnerId);
        }
      } else {
        for (PartnerOutput entry : out) {
          return entry;
        }
      }

      return null;
    } catch (IOException e) {
      logger.error(PARTNER_ID_ERROR, e);
      return null;
    }
  }

  /**
   * Retrieves the access status of the client for a resource request
   * 
   * @param url resource path that the client tries to access. (e.g:
   *          "/news/2015/07/01")
   * @param credentialId client's party ID if resource that the client tries to
   *          access is paid content
   * @param loginKey client's login key, if login is required to access the
   *          resource
   * @param partnerId unique identifier for the partner that owns the requested
   *          resource
   * @return String indicating the access status (OK, NeedSubscription,
   *         NeedLogin) or an error message
   */
  public static AccessOutput checkAccess(String url, String loginKey,
                                         String partnerId, String credentialId,
                                         String remoteIp) {
    try {
      url = URLEncoder.encode(url, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      logger.debug("Encoding faiure", e);
    }

    String urn =
      AUTHORIZATION_URN + "/access/?partnerId=" + partnerId + "&url=" + url
          + "&ip=" + remoteIp;
    try {
      String content =
        callApi(urn, RequestFactory.HttpMethod.GET, "secretKey=" + loginKey
                                                    + ";credentialId=" + credentialId
                                                    + ";");
      Gson gson = new Gson();
      return gson.fromJson(content, AccessOutput.class);
    } catch (IOException e) {
      logger.error(ACCESS_ERROR, e);
      throw new RuntimeException(ACCESS_ERROR + ": " + e.getMessage(), e);
    } catch (Exception e) {
      logger.error(UNEXPECTED_ERROR, e);
      throw new RuntimeException("Unexpected error making API call: " + e.getMessage(), e);
    }
  }

  /**
   * Retrieves the metering of the client based on the client's IP address.
   * 
   * @param ip client's IP address.
   * @return String indicating client's metering status. (OK, Warn, Blocked)
   */
  public static String checkMeteringLimit(String ip, String partnerId, String fullUri) {
    String urn = METERS_URN + "/ip/" + ip + "/limit/?partnerId=" + partnerId +"&uri="+fullUri;

    try {
      String content = callApi(urn, RequestFactory.HttpMethod.GET);
      Gson gson = new Gson();
      CheckMeteringLimitOutput out =
        gson.fromJson(content, CheckMeteringLimitOutput.class);

      return out.status;
    } catch (IOException e) {
      logger.debug(METERING_LIMIT_ERROR, e);
      return e.getMessage();
    }
  }

  /**
   * Increase metering count associated with the given IP address and partner ID
   * by one.
   * 
   * @param ip remote IP address
   * @param partnerId unique identifier for the partner
   * @return String indicating the access status (OK, NeedSubscription,
   *         NeedLogin)
   */
  public static String incrementMeteringCount(String ip, String partnerId) {
    String urn =
      METERS_URN + "/ip/" + ip + "/increment/?partnerId=" + partnerId;

    try {
      String content = callApi(urn, RequestFactory.HttpMethod.POST);
      Gson gson = new Gson();
      IncrementMeteringCountOutput out =
        gson.fromJson(content, IncrementMeteringCountOutput.class);
      String message = out.message;

      return message;
    } catch (IOException e) {
      logger.debug(INCREMENT_METERING_COUNT_ERROR, e);
      return e.getMessage();
    }
  }
}
