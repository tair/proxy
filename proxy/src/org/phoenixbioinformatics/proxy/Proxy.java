/*
 * Copyright (c) 2015 Phoenix Bioinformatics Corporation. All rights reserved.
 */

package org.phoenixbioinformatics.proxy;


import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;


import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.IOUtils;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.phoenixbioinformatics.api.ApiService;
import org.phoenixbioinformatics.http.ApiPartnerImpl;
import org.phoenixbioinformatics.http.ApiPartnerPatternImpl;
import org.phoenixbioinformatics.http.HttpHostFactory;
import org.phoenixbioinformatics.http.HttpPropertyImpl;
import org.phoenixbioinformatics.http.RequestFactory;
import org.phoenixbioinformatics.http.UnsupportedHttpMethodException;
import org.phoenixbioinformatics.properties.ProxyProperties;
import org.json.JSONObject;


/**
 * A servlet that proxies HTTP requests to another server and handles the
 * response.
 * 
 * @author Robert J. Muller
 */

// WebInitParam sets the default values; override in web.xml with an explicit
// servlet declaration with initParam elements.

@WebServlet(urlPatterns = { "/proxy/*" })
public class Proxy extends HttpServlet {
  private static final String NULL_VALUE = null;
  private static final String QUERY_PREFIX = "?";

  private static final String PARAM_PREFIX = "&";

  /** logger for this class */
  private static final Logger logger = LogManager.getLogger(Proxy.class);

  /** default serial version UID for serializable object */
  private static final long serialVersionUID = 1L;

  /** URI parameter for redirecting */
  private static final String REDIRECT_PARAM = "redirect=";

  // header-related constants

  /** Remote_Addr header name constant */
  private static final String REMOTE_ADDR = "Remote_Addr";
  /** x-forwarded-for header name constant */
  private static final String X_FORWARDED_FOR = "x-forwarded-for";
  /** x-forwarded-host header name constant */
  private static final String X_FORWARDED_SCHEME = "x-forwarded-proto";
  /** x-forwarded-host header name constant */
  private static final String X_FORWARDED_HOST = "x-forwarded-host";
  /** name of custom header indicating password update */
  private static final String PASSWORD_UPDATE_HEADER =
    "Phoenix-Proxy-PasswordUpdate";
  /** name of custom header indicating user logged out of partner */
  private static final String LOGOUT_HEADER = "Phoenix-Proxy-Logout";

  // cookie-related constants

  /** domain for cookies */
  private static final String COOKIE_DOMAIN = ".arabidopsis.org";
  /** session attribute for cookies */
  private static final String COOKIES_ATTRIBUTE = "cookies";
  /** name of the ptools web server session cookie */
  private static final String PTOOLS_SESSION_COOKIE = "PTools-session";
  /** name of the tomcat session cookie */
  private static final String TOMCAT_SESSION_COOKIE = "JSESSIONID";
  /** name of PHP session cookie, for MorphoBank integration */
  private static final String PHP_SESSION_COOKIE = "PHPSESSID";
  /** name of the Phoenix party id cookie */
  private static final String CREDENTIAL_ID_COOKIE = "credentialId";
  /** name of the Phoenix secret key cookie */
  private static final String SECRET_KEY_COOKIE = "secretKey";

  // miscellaneous constants

  /** IPv4 localhost address */
  private static final String LOCALHOST_V4 = "127.0.0.1";
  /** IPv6 localhost address */
  private static final String LOCALHOST_V6 = "0:0:0:0:0:0:0:1";
  /** code for UTF8 */
  private static final String UTF_8 = "UTF-8";
  /** placeholder for private ip */
  private static final String ELB_HEALTH_CHECKER_IP = "172.16.0.0";

  // API codes
  private static final String NEED_LOGIN_CODE = "NeedLogin";
  private static final String NEED_SUBSCRIPTION_CODE = "NeedSubscription";
  private static final String METER_WARNING_CODE = "Warning";
  private static final String METER_BLOCK_CODE = "Blocked"; // PW-646
  private static final String METER_BLACK_LIST_BLOCK_CODE = "BlackListBlock"; // PW-287
  private static final String OK_CODE = "OK";
  private static final String NOT_OK_CODE = "NOT OK";
  
  // Meter status codes
  private static final String METER_WARNING_STATUS_CODE = "W";
  private static final String METER_BLACK_LIST_STATUS_CODE = "M";
  private static final String METER_BLOCK_STATUS_CODE = "B";
  private static final String METER_NOT_METERED_STATUS_CODE = "N";
  
  // Paid content codes
  private static final String IS_PAID_CONTENT = "T";
  private static final String NOT_PAID_CONTENT = "F";

  // property-based constants
  // TAIR-2734
  private static final String ACCESS_CONTROL_ALLOW_ORIGIN_LIST =
    ProxyProperties.getProperty("proxy.access.control.allow.origin.list");

  // warning messages

  private static final String OUTPUT_STREAM_IO_WARN =
    "IO Error writing entity to output stream";
  private static final String LOCALHOST_REDIRECT_WARN =
    "Partner response redirected to localhost, redirecting to ";

  // error messages

  private static final String ENCODING_FAIURE_ERROR =
    "Encoding faiure for URI ";
  private static final String URI_SYNTAX_ERROR = "URI syntax error";
  private static final String RUNTIME_EXCEPTION_ERROR =
    "Runtime exception while handling proxy request";
  private static final String REQUEST_HANDLING_ERROR =
    "Error handling proxy request";
  private static final String CLOSE_DATA_SOURCE_ERROR =
    "Error closing data source in proxy server: ";
  private static final String REDIRECT_ERROR =
    "Redirect status code but no location header in response";
  private static final String HTTP_CODE_ERROR =
    "Error getting http status code from request";

  // PWL-625
  private static final int PROXY_REQUEST_THRESHOLD = 5;
  private static final int CONTENT_REQUEST_THRESHOLD = 5;
  private static final String LOG_MARKER = "@@@@@@@@";

  private static final String METHOD_OPTIONS = "OPTIONS";
  private static final String METHOD_GET = "GET";

  //sqs api url
  private static final String API_GATEWAY_SQS_LOGGING_URL =
    ProxyProperties.getProperty("sqs.uri");

  @Override
  protected void service(HttpServletRequest servletRequest,
                         HttpServletResponse servletResponse)
      throws ServletException, IOException {
    try {
      // logAllServletRequestHeaders(servletRequest);
      // PWL-625: Add measure to method duration
      long startTime = System.currentTimeMillis();
      handleProxyRequest(servletRequest, servletResponse);
      long stopTime = System.currentTimeMillis();
      long elapsedTime = stopTime - startTime;
      if (elapsedTime >= PROXY_REQUEST_THRESHOLD * 1000) {
        logger.debug(LOG_MARKER + " Request to proxy server " + servletRequest.getRequestURI().toString() + " takes " + elapsedTime + " ms to response " + LOG_MARKER);
      }
      // logAllServletResponseHeaders(servletResponse);
    } catch (RuntimeException e) {
      // Log unchecked exception here and don't propagate.
      logger.error(RUNTIME_EXCEPTION_ERROR, e);
    } catch (Exception e) {
      // Don't propagate checked exceptions out of servlet, already logged
    }
  }

  /**
   * Handle a request by configuring the request, authorizing it, then proxying
   * or refusing it.
   * 
   * @param servletRequest the HTTP servlet request
   * @param servletResponse the HTTP servlet response
   * @throws InvalidPartnerException when the API returns no partner
   */
  private void handleProxyRequest(HttpServletRequest servletRequest,
                                  HttpServletResponse servletResponse)
      throws InvalidPartnerException {

    // skips proxy if the request is a simple OPTIONS or set cookie request
    String action = servletRequest.getParameter("action");
    // TAIR-2734 refactoring to avoid null pointer exception if no origins
    // property,
    // and to centralize construction of list
    List<String> origins =
      ACCESS_CONTROL_ALLOW_ORIGIN_LIST != null ? Arrays.asList(ACCESS_CONTROL_ALLOW_ORIGIN_LIST.trim().split(";"))
          : new ArrayList<String>(1);
    HttpHostFactory hostFactory = getHostFactory(servletRequest);
    Boolean allowCredential = hostFactory.getAllowCredential();
    setCORSHeader(servletRequest, servletResponse, origins, allowCredential);
    if (servletRequest.getMethod().equals(METHOD_OPTIONS)) {
      // logger.debug("Getting options...");
      handleOptionsRequest(servletRequest, servletResponse, origins);
    } else if (action != null && action.equals("setCookies")) {
      // logger.debug("Setting cookies...");
      handleSetCookieRequest(servletRequest,
                             servletResponse,
                             origins,
                             hostFactory.getPartnerId());
    } else {
      // Get the complete URI including original domain and query string.
      String uri = servletRequest.getRequestURI().toString();
      String queryString = servletRequest.getQueryString();
      // logger.debug("\n==========\nIncoming URI: " + uri + " with query string "
      //              + queryString + "\n==========");
      try {
        HttpHost sourceHost = hostFactory.getSourceHost();

        HttpHost targetHost = hostFactory.getTargetHost();
        logHostAttributes(servletRequest,
                          sourceHost,
                          targetHost,
                          hostFactory.getPartnerId());

        // populate secret key and credential id from cookie if available
        // populate session id from supported session cookies if available to
        // support session logging
        String credentialId = null;
        String secretKey = null;
        String sessionId = null;
        Boolean allowRedirect = hostFactory.getAllowRedirect();
        Cookie cookies[] = servletRequest.getCookies();

        if (cookies != null) {
          for (Cookie c : Arrays.asList(cookies)) {
            String cookieName = c.getName();
            // logger.debug("Processing cookie " + cookieName + " with value "
            //              + c.getValue());
            // logger.debug("Processing cookie " + cookieName + " with value "
            //         + c.getValue());
            if (cookieName.equals(SECRET_KEY_COOKIE)) {
              secretKey = c.getValue();
            } else if (cookieName.equals(CREDENTIAL_ID_COOKIE)) {
              credentialId = c.getValue();
            } else if (cookieName.equals(TOMCAT_SESSION_COOKIE)) {
              // Tomcat/Apache session support
              sessionId = c.getValue();
            } else if (cookieName.equals(PTOOLS_SESSION_COOKIE)) {
              // PW-71 cdiff integration--ptools sessions support
              sessionId = c.getValue();
            }
          }
        }

        String fullRequestUri =
          buildFullUri(sourceHost.getSchemeName(),
                       sourceHost.getHostName(),
                       servletRequest.getPathInfo(),
                       servletRequest.getQueryString());
        ArrayList<String> remoteIpList = getIpAddressList(servletRequest);
        String ipListString = String.join(",", remoteIpList);
        //log all the ips that are detected for testing
        logger.debug("Ip Address Detected: " + ipListString);
        

        String remoteIp = remoteIpList.get(0);
        String orgId = null;
        String partnerId = hostFactory.getPartnerId();
        StringBuilder userIdentifier = new StringBuilder();
        	String auth = NOT_OK_CODE;
        	String isPaidContent = NOT_PAID_CONTENT;
          String redirectUri = null;

        logger.info("checkAccess API parameters: " + fullRequestUri + ", " + partnerId
                    + ", " + secretKey + ", " + credentialId + ", " + remoteIp);

        try {
          ApiService.AccessOutput accessOutput =
            ApiService.checkAccess(fullRequestUri,
                                   secretKey,
                                   partnerId,
                                   credentialId,
                                   ipListString);
          auth = accessOutput.status;
          // logger.debug("checkAccess " +auth);
          remoteIp = accessOutput.ip;
          orgId = accessOutput.orgId;
          userIdentifier.append(accessOutput.userIdentifier);
          isPaidContent = accessOutput.isPaidContent;
          redirectUri = accessOutput.redirectUri;
          // logger.debug("userIdentifier: " + userIdentifier.toString());
        } catch (Exception e) {
          // Problem making the API call, continue with "Not OK" default status
          // Problem already logged
          // PWL-556: userIdentifier has to be assigned to null for bypassing API check
          logger.info("Check access failed. Bypassing proxy/paywall - allowing free access to content. Set userIdentifier to null.");
          userIdentifier.append(NULL_VALUE);
        }

        // PWL-716: for non-GET request whose metered pattern has redirectUri value, use redirectUri to 
        // replace original request path if hits metering/blacklist/login request
        String targetRedirectUri = fullRequestUri;
        if (!servletRequest.getMethod().equals(METHOD_GET) && redirectUri != null && !redirectUri.isEmpty()) {
          try {
            URI targetUri = new URI(redirectUri);
            if (targetUri.isAbsolute()) {
              targetRedirectUri = redirectUri;
            } else {
              // this should replace the buildFullUri method
              targetUri = new URI(sourceHost.getSchemeName(),
                sourceHost.getHostName(),
                redirectUri,
                null,  // query
                null); // fragment
              targetRedirectUri = targetUri.toString();
            }
            // logger.debug("Redirect uri updated from " + fullRequestUri + " to " + targetRedirectUri);
          } catch (URISyntaxException e) {
            logger.warn("cannot parse redirectUri: " + redirectUri + ". ", e);
          }
        }

        // TODO use source or target host for HOST header based on partner
        // option
        authorizeAndProxy(servletRequest,
                          servletResponse,
                          uri,
                          hostFactory.getPartnerId(),
                          targetHost,
                          sourceHost, // hard-coded to source for now
                          fullRequestUri,
                          remoteIp,
                          orgId,
                          credentialId,
                          secretKey,
                          userIdentifier,
                          ipListString,
                          sessionId,
                          isPaidContent,
                          auth,
                          targetRedirectUri,
                          allowRedirect);
      } catch (ServletException | UnsupportedHttpMethodException | IOException e) {
        // Log checked exceptions here, then ignore.
        logger.error(REQUEST_HANDLING_ERROR, e);
      }
    }
  }

  /**
   * Get the fully initialized host factory.
   *
   * @param servletRequest the HTTP servlet request
   * @return the initialized host factory
   */
  public HttpHostFactory getHostFactory(HttpServletRequest servletRequest) {
    ApiPartnerPatternImpl partnerPattern = new ApiPartnerPatternImpl();
    HttpHostFactory hostFactory =
      new HttpHostFactory(partnerPattern,
                          new HttpPropertyImpl(),
                          servletRequest.getHeader(X_FORWARDED_SCHEME),
                          servletRequest.getServerName(),
                          servletRequest.getLocalPort(),
                          servletRequest.getHeader(X_FORWARDED_HOST));
    HttpHost sourceHost = hostFactory.getSourceHost();
    // Set source string before using host factory further.
    partnerPattern.setSourceUri(sourceHost.toHostString());
    partnerPattern.setUriPath(servletRequest.getRequestURI());
    return hostFactory;
  }

  /**
   * Build a log string containing server and host data from the request and
   * hosts.
   *
   * @param servletRequest the servlet request
   * @param sourceHost the derived source host
   * @param targetHost the derived target host
   * @param partnerId the unique identifier for the partner
   */
  private void logHostAttributes(HttpServletRequest servletRequest,
                                 HttpHost sourceHost, HttpHost targetHost,
                                 String partnerId) {
    StringBuilder builder = new StringBuilder("server name=");
    builder.append(servletRequest.getServerName());
    builder.append(", server scheme=");
    builder.append(servletRequest.getScheme());
    builder.append(", host name=");
    builder.append(servletRequest.getHeader(HttpHeaders.HOST));
    builder.append("forwarded scheme=");
    builder.append(servletRequest.getHeader(X_FORWARDED_SCHEME));
    builder.append(", forwarded host=");
    builder.append(servletRequest.getHeader(X_FORWARDED_HOST));
    builder.append(", source host=");
    builder.append(sourceHost.toHostString());
    builder.append(", target host=");
    builder.append(targetHost.toString());
    builder.append(", partner id=");
    builder.append(partnerId);
    // logger.debug(builder.toString());
  }

  /**
   * Log a request, but only if it is not an embedded request contained in a
   * full page (images, js, css, and so on).
   *
   * @param uri the URI to log
   * @param ip the IP address to log
   * @param credentialId the party ID of the user, if logged in
   * @param sessionId the session ID of the partner session, if any
   */
  private void logRequest(String uri, String ip, String ipListString, String credentialId,
                          String sessionId, String partnerId, String isPaidContent, String meterStatus) {
    // Log a page view for "real" URIs, exclude embedded images, js, etc.
    if (!isEmbeddedFile(uri)) {
      // logger.debug("Creating page view for URI " + uri);
      ApiService.createPageView(ip, ipListString, uri, credentialId, sessionId, partnerId, isPaidContent, meterStatus);
    }
  }

  /**
   * Log a request through aws sqs service
   *
   */
  private void sqsLogRequest(String uri, String ip, String orgId, String ipListString, String credentialId,
                          String sessionId, String partnerId, String isPaidContent, String meterStatus, String statusCode,
                          String responseHeaders, String contentType) throws IOException{
    // Log a page view for "real" URIs, exclude embedded images, js, etc.
    if (!isEmbeddedFile(uri)) {
      // logger.debug("Creating sqs page view for URI " + uri);
      CloseableHttpResponse response = null;
      HttpPost request = null;
      request = new HttpPost(API_GATEWAY_SQS_LOGGING_URL);

      // set params
      Date curDate = new Date();
      SimpleDateFormat format = new SimpleDateFormat();
      format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
      String pageViewDate = format.format(curDate);
      if (uri.length() >2000) {
        uri = uri.substring(0, 1950) + "__truncated_for_uri_longer_than_2000";
      }

      String jsonString = new JSONObject()
              .put("pageViewDate", pageViewDate)
              .put("uri", uri)
              .put("sessionId", sessionId)
              .put("partyId", credentialId)
              .put("ip", ip)
              .put("orgId", orgId)
              .put("ipList", ipListString)
              .put("partnerId", partnerId)
              .put("isPaidContent", isPaidContent)
              .put("meterStatus", meterStatus)
              .put("statusCode", statusCode)
              .put("responseHeaders", responseHeaders)
              .put("contentType", contentType)
              .toString();
      StringEntity requestEntity = new StringEntity(
              jsonString,
              ContentType.APPLICATION_JSON);
      request.setEntity(requestEntity);

      CloseableHttpClient client = HttpClientBuilder.create().build();
      response = client.execute(request);

      int status = response.getStatusLine().getStatusCode();
      if (status != HttpStatus.SC_OK && status != HttpStatus.SC_CREATED) {
        logger.debug("Status creating sqs page view is not OK: " + status);
        throw new IOException("Bad status code: " + String.valueOf(status));
      } else {
        // logger.debug("Status creating sqs page view is OK: " + status);
      }
    }
  }


  /**
   * Authorize the request, and if authorized, proxy it.
   *
   * @param servletRequest the HTTP servlet request to proxy
   * @param servletResponse the HTTP servlet response to set
   * @param uri the request URI
   * @param partnerId the API ID for the partner
   * @param targetHost the host to which to proxy
   * @param sourceHost the host being proxied
   * @param fullRequestUri the transformed URI for the proxy request
   * @param remoteIp the user's IP address
   * @param orgId the organization party id corresponding to the user's IP address
   * @param credentialId the user's party id if logged in
   * @param secretKey the user's secret key for authentication
   * @throws IOException when there is a URI problem
   * @throws UnsupportedHttpMethodException when the requested method is not
   *           GET, PUT, POST, DELETE, OPTIONS
   * @throws ServletException when proxying fails
   */
  private void authorizeAndProxy(HttpServletRequest servletRequest,
                                 HttpServletResponse servletResponse,
                                 String uri, String partnerId,
                                 HttpHost targetHost, HttpHost sourceHost,
                                 String fullRequestUri, String remoteIp, String orgId,
                                 String credentialId, String secretKey, 
                                 StringBuilder userIdentifier, String ipListString,
                                 String sessionId, String isPaidContent, String auth,
                                 String targetRedirectUri, Boolean allowRedirect)
      throws IOException, UnsupportedHttpMethodException, ServletException {
    // Determine whether to proxy the request.
    if (authorizeProxyRequest(secretKey,
                              partnerId,
                              credentialId,
                              fullRequestUri,
                              sourceHost,
                              remoteIp,
                              orgId,
                              servletResponse,
                              ipListString,
                              sessionId,
                              isPaidContent,
                              auth, 
                              targetRedirectUri,
                              allowRedirect)) {
      // Authorized by the API, so proceed.

      ProxyRequest proxyRequest =
        new ProxyRequest(servletRequest.getMethod(), uri, remoteIp);

      String targetUri =
        targetHost.getSchemeName() + "://" + targetHost.getHostName();

      HttpUriRequest uriRequest =
        RequestFactory.getUriRequest(servletRequest, targetUri);

      // logger.debug("Proxying request from " + proxyRequest.getIp() + "-->\""
      //              + uriRequest.getRequestLine().getUri() + "\"");

      // logger.debug("userIdentifier before configureProxyRequest(): "
      //              + userIdentifier.toString());
      configureProxyRequest(servletRequest,
                            proxyRequest,
                            uriRequest,
                            userIdentifier.toString());
      // logger.debug("userIdentifier after configureProxyRequest(): "
      //              + userIdentifier.toString());
      // Proxy, using the sourceHost as the "original" host.
      proxy(servletRequest.getSession(),
            servletResponse,
            proxyRequest,
            sourceHost,
            partnerId,
            userIdentifier.toString());
      try {
        sqsLogRequest(fullRequestUri, remoteIp, orgId, ipListString, credentialId, sessionId, partnerId, isPaidContent, "N", String.valueOf(servletResponse.getStatus()), getAllServletResponseHeaders(servletResponse), servletResponse.getContentType());
      }catch(Exception e){
        logger.debug("sqs logging error");
      }
      //logRequest(fullRequestUri, remoteIp, ipListString, credentialId, sessionId, partnerId, isPaidContent, "N");
      // logger.debug("userIdentifier after proxy(): " + userIdentifier.toString());
    }
  }

  /**
   * Build the full URI for proxying based on the transformed source host.
   *
   * @param scheme the scheme (http or https) for the URI
   * @param hostName the host name for the URI
   * @param path the URI path information
   * @param query the URI query parameters
   * @return the transformed URI
   */
  private String buildFullUri(String scheme, String hostName, String path,
                              String query) {
    StringBuilder builder = new StringBuilder(scheme);
    builder.append("://");
    builder.append(hostName);
    builder.append(path);
    if (query != null) {
      builder.append(QUERY_PREFIX);
      builder.append(query);
    }

    String fullRequestUri = builder.toString();
    return fullRequestUri;
  }

  /**
   * Detect whether a URI is an "embedded" file by comparing the end of the
   * string to a list of extensions like ".jpg" or ".js".
   *
   * @param fullRequestUri the full URI
   * @return true if the URI contains an "embedded" extension, otherwise false
   */
  private boolean isEmbeddedFile(String fullRequestUri) {
    boolean embedded =
      fullRequestUri.endsWith(".jpg") || fullRequestUri.endsWith(".png")
          || fullRequestUri.endsWith(".css") || fullRequestUri.endsWith(".js")
          || fullRequestUri.endsWith(".gif")
          || fullRequestUri.endsWith(".wsgi")
          || fullRequestUri.endsWith(".ico");
    if (embedded) {
      // logger.debug("URI " + fullRequestUri + " has embedded-file extension");
    }
    return embedded;
  }

  /**
   * Authorize the request based on the information in the HttpServletRequest.
   * Returns true if the servletRequest is allowed to access partner's server,
   * and false otherwise.
   *
   * Redirection path in servletResponse will be set if the client does not
   * allow to access partner's server.
   * 
   * @param secretKey client's password-based key to use for authentication
   * @param partnerId partner associated with client's request
   * @param credentialId client's partyId to use for authentication
   * @param fullUri client's full request path. example:
   *          https://test.arabidopsis.org/test/test.html
   * @param sourceHost client's source authority. example:
   *          https://test.arabidopsis.org
   * @param remoteIp client's IP address
   * @param orgId organization party id corresponding to the client's IP address
   * @param servletResponse client's response to be modified if ther request to
   *          partner's server is denied.
   * @param userIdentifier the by-reference object that will contain the output
   *          user identifier for the credentialed user
   * @return Boolean indicates if client has access to partner' server.
   */
  private Boolean authorizeProxyRequest(String secretKey, String partnerId,
                                        String credentialId, String fullUri,
                                        HttpHost sourceHost, String remoteIp, String orgId,
                                        HttpServletResponse servletResponse,
                                        String ipListString, String sessionId, 
                                        String isPaidContent, String auth,
                                        String targetRedirectUri, Boolean allowRedirect)
      throws IOException {

    if (isEmbeddedFile(fullUri)) {
      // Not a top-level page (CSS, JS, GIF for example), skip authorization
      return true;
    }

    // PW-373 PW-376
    // Get partner information
    ApiPartnerImpl partner = new ApiPartnerImpl();
    // Set partnerId before using partner further
    partner.setPartnerId(partnerId);
    // Get attributes from partner
    String uiUri = partner.getUiUri();

    if (uiUri == null || uiUri.isEmpty()) {
      // null database field, use the source host (scheme and authority of the
      // incoming full URI)
      StringBuilder builder = new StringBuilder(sourceHost.getSchemeName());
      builder.append("://");
      builder.append(sourceHost.getHostName());
      if (sourceHost.getPort() != 80 && sourceHost.getPort() != -1) {
        builder.append(":");
        builder.append(sourceHost.getPort());
      }
      uiUri = builder.toString();
      // logger.debug("Using source host as UI URI: " + sourceHost);
    }
    // BIOCYC-569 this is specifically for biocyc's brg-files.ai.sri.com
    // Generally we load uiUri from properties file
    // BIOCYC-581: Need to handle staging server as well
    String hostName = sourceHost.getHostName();
    if (hostName != null && (hostName.equals("brg-files.ai.sri.com") || hostName.equals("brg-files-staging.ai.sri.com"))) {
        uiUri = "https://" + hostName;
    }
    String loginUri = partner.getLoginUri();
    String meterWarningUri =
      partner.getUiMeterUri() + "?exceed=abouttoexceed&partnerId=" + partnerId;
    String meterBlockingUri =
      partner.getUiMeterUri() + "?exceed=exceeded&partnerId=" + partnerId;
    String meterBlacklistUri =
      partner.getUiMeterUri() + "?exceed=blacklisted&partnerId=" + partnerId;

    // logger.debug("UI URI set to: " + uiUri);
    // logger.debug("login URI set to: " + loginUri);
    // logger.debug("meter warning URI set to: " + meterWarningUri);
    // logger.debug("meter blocking URI set to: " + meterBlockingUri);
    // logger.debug("meter blacklist blocking URI set to: " +
    // meterBlacklistUri);

    // PWL-556: Set default authorized value to true to handle case when API server is down.
    // Otherwise it will run into infinite redirect
    Boolean authorized = true;
    String redirectUri = ""; // complete URI to which to redirect here
    String redirectQueryString = getRedirectQueryString(targetRedirectUri, uiUri);   
    String unauthorizedErrorMsg = "";
    String unauthorizedRedirectUri = "";

    // Handle the various status codes.
    String meterStatus = METER_NOT_METERED_STATUS_CODE;
    if (auth.equals(OK_CODE)) {
      // grant access
      authorized = true;
      logger.info("Party " + credentialId + " authorized for free content "
                  + fullUri + " at partner " + partnerId);
    } else if (auth.equals(NEED_SUBSCRIPTION_CODE)) {
      // check metering status and redirect or proxy as appropriate
      logger.info("Party " + credentialId
                  + " needs to subscribe to see paid content " + fullUri
                  + " at partner " + partnerId);
      StringBuilder uriBuilder = new StringBuilder(uiUri);

      try {
        // String meter =
        //   ApiService.checkMeteringLimit(remoteIp, partnerId, fullUri);
        if(credentialId == null) {
          unauthorizedErrorMsg = "Blocked from paid content due to no login";
          logger.info(unauthorizedErrorMsg);
          authorized = false;
          uriBuilder.append(meterBlockingUri);
          unauthorizedRedirectUri = uriBuilder.toString();
          uriBuilder.append(PARAM_PREFIX);
          uriBuilder.append(redirectQueryString);
          redirectUri = uriBuilder.toString();
          meterStatus = METER_BLOCK_STATUS_CODE;
        } else {
          String meter = ApiService.checkRemainingUnits(credentialId, partnerId);
          if (meter.equals(OK_CODE)) {
            logger.info("Allowed access to content by using bucket: " + fullUri);
            authorized = true;
            // ApiService.incrementMeteringCount(remoteIp, partnerId);
            ApiService.decrementUnits(credentialId, partnerId);

          } else if (meter.equals(METER_WARNING_CODE)) {
            unauthorizedErrorMsg = "Warned to subscribe by meter limit";
            logger.info(unauthorizedErrorMsg);
            authorized = false;
            uriBuilder.append(meterWarningUri);
            unauthorizedRedirectUri = uriBuilder.toString();
            uriBuilder.append(PARAM_PREFIX);
            uriBuilder.append(redirectQueryString);
            redirectUri = uriBuilder.toString();
            meterStatus = METER_WARNING_STATUS_CODE;
            // ApiService.incrementMeteringCount(remoteIp, partnerId);
            ApiService.decrementUnits(credentialId, partnerId);
          } else if (meter.equals(METER_BLACK_LIST_BLOCK_CODE)) {
            // PW-287
            unauthorizedErrorMsg = "Blocked from no-metered-access content";
            logger.info(unauthorizedErrorMsg);
            authorized = false;
            uriBuilder.append(meterBlacklistUri);
            unauthorizedRedirectUri = uriBuilder.toString();
            uriBuilder.append(PARAM_PREFIX);
            uriBuilder.append(redirectQueryString);
            redirectUri = uriBuilder.toString();
            meterStatus = METER_BLACK_LIST_STATUS_CODE;
          } else if (meter.equals(METER_BLOCK_CODE)) {
            unauthorizedErrorMsg = "Blocked from paid content by meter limit";
            logger.info(unauthorizedErrorMsg);
            authorized = false;
            uriBuilder.append(meterBlockingUri);
            unauthorizedRedirectUri = uriBuilder.toString();
            uriBuilder.append(PARAM_PREFIX);
            uriBuilder.append(redirectQueryString);
            redirectUri = uriBuilder.toString();
            meterStatus = METER_BLOCK_STATUS_CODE;
          } else {
            // PWL-646: Bypass and allow free access for unexpected status such as 404
            logger.info("Check meter limit returned with unexpected code: " + meter + ". Bypassing proxy/paywall - allowing free access to content.");
            authorized = true;
          }
          }
      } catch (Exception e) {
        // PWL-556: Bypass and allow free access
        logger.info("Check meter limit failed. Bypassing proxy/paywall - allowing free access to content.");
        authorized = true;
      }
    } else if (auth.equals(NEED_LOGIN_CODE)) {
      // force user to log in
      unauthorizedErrorMsg = "User required to login";
      logger.info(unauthorizedErrorMsg);
      authorized = false;
      redirectUri = getLoginRedirectUri(uiUri, loginUri, redirectQueryString);
      unauthorizedRedirectUri = redirectUri;
      logger.info("Party " + credentialId + " needs to login to access "
                  + fullUri + " at partner " + partnerId);
    }

    if (!authorized) {
      // One or another status requires a redirect.
      logger.info("Party " + credentialId + " not authorized for " + fullUri
                  + " at partner " + partnerId + ", redirecting to "
                  + redirectUri);
      try {
        sqsLogRequest(fullUri, remoteIp, orgId, ipListString, credentialId, sessionId, partnerId, isPaidContent, meterStatus, String.valueOf(servletResponse.getStatus()),getAllServletResponseHeaders(servletResponse), servletResponse.getContentType());
      }catch(Exception e){
        logger.debug("sqs logging error");
      }
      //logRequest(fullUri, remoteIp, ipListString, credentialId, sessionId, partnerId, isPaidContent, meterStatus);
      if (allowRedirect) {
        servletResponse.sendRedirect(redirectUri + "&remoteIp=" +remoteIp);
      } else {
        // send Access denied response if the host does not allow redirect such as API host
        // servletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, unauthorizedRedirectUri + "?&remoteIp=" +remoteIp);
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        JSONObject jsonResponse = new JSONObject();
        jsonResponse.put("statusCode", statusCode);
        jsonResponse.put("message", unauthorizedErrorMsg);
        jsonResponse.put("redirectUri", unauthorizedRedirectUri + "&remoteIp=" + remoteIp);
        jsonResponse.put("meterStatus", meterStatus);

        servletResponse.setContentType("application/json");
        servletResponse.setStatus(statusCode);
        servletResponse.getWriter().write(jsonResponse.toString());
      }
    }

    return authorized;
  }

  /**
   * Get the complete login-redirect path given the user-interface host, the
   * login path, and the redirect query string. This method builds the complete
   * string and prefixes the redirect query string with & or ? as appropriate.
   *
   * @param uiUri the user interface host
   * @param loginUri the login path
   * @param redirectQueryString the
   * @return
   */
  private String getLoginRedirectUri(String uiUri, String loginUri,
                                     String redirectQueryString) {
    if (uiUri == null) {
      throw new RuntimeException("Null user interface URI for partner");
    }
    String prefix = QUERY_PREFIX;
    if (loginUri.contains(QUERY_PREFIX)) {
      // ? already present, use & prefix instead
      prefix = PARAM_PREFIX;
    }
    StringBuilder builder = new StringBuilder(uiUri);
    builder.append(loginUri);
    builder.append(prefix);
    builder.append(redirectQueryString);
    return builder.toString();
  }

  /**
   * Get the URI to use for a redirect if authorization fails. The method
   * performs any transformations required by the redirect, such as converting
   * an http scheme to https when the main URI contains https.
   *
   * @param redirectUri the full URI to which to redirect
   * @param uiUri the URI containing the UI scheme and host
   * @return the transformed URI to which to redirect
   */
  public String getRedirectQueryString(String redirectUri, String uiUri) {

    // logger.debug("Full URI to use for redirect: " + redirectUri);

    String transformedUri = redirectUri;

    if (uiUri.toLowerCase().contains("https://")
        && redirectUri.toLowerCase().contains("http://")) {
      transformedUri = transformedUri.replaceFirst("http", "https");
      // logger.debug("Transformed URI to which to redirect:"
      //            + transformedUri);
    }

    try {
      transformedUri = URLEncoder.encode(transformedUri, UTF_8);

      // logger.debug("Transformed and encoded URI for redirect: " + transformedUri);

    } catch (UnsupportedEncodingException e) {
      // Log and ignore, use un-encoded redirect URI
      logger.warn(ENCODING_FAIURE_ERROR + transformedUri, e);
    }
    
    StringBuilder builder = new StringBuilder(REDIRECT_PARAM);
    builder.append(transformedUri);
    String redirectQueryString = builder.toString();
    
    return redirectQueryString;
  }

  /**
   * <p>
   * Send the HTTP request to the target server. Set the appropriate cookie for
   * session handling.
   * </p>
   * <p>
   * PB-128: The client must not do any redirect handling; it should leave that
   * to the actual client browser.
   * </p>
   * 
   * @param request the URI request to send to the server
   * @param session the HTTP session containing a possible cookie store
   * @param responseHandler the response handler for the request
   * @param userIdentifier the id string the partner uses to identify the user
   * 
   * @throws IOException when there is a problem handling the URI or redirecting
   * @throws ClientProtocolException when there is a syntax error in the URI
   */
  private void sendRequestToServer(HttpHost host, HttpUriRequest request,
                                   HttpSession session,
                                   ResponseHandler<String> responseHandler,
                                   String userIdentifier)
      throws ClientProtocolException, IOException {
    CloseableHttpClient client = null;
    // Get cookie store from session if it's there. This gets stored in the
    // proxy server session to maintain the session from the back-end server.
    CookieStore cookieStore =
      (CookieStore)session.getAttribute(COOKIES_ATTRIBUTE);
    HttpClientContext localContext =
      createLocalContextWithCookiesAndTarget(host,
                                             cookieStore,
                                             request.getURI().getHost());
    client = HttpClientBuilder.create().disableContentCompression().disableRedirectHandling().build();
    // Execute the request on the proxied server. Ignore returned string.
    // TODO: try adding host as first param, see if it does the right thing.
    // client.execute(host, request, responseHandler, localContext);
    // logAllUriRequestHeaders(request);

    // PWL-625: Add measure to method duration
    long startTime = System.currentTimeMillis();
    client.execute(request, responseHandler, localContext);
    long stopTime = System.currentTimeMillis();
    long elapsedTime = stopTime - startTime;
    if (elapsedTime >= CONTENT_REQUEST_THRESHOLD * 1000) {
      logger.debug(LOG_MARKER + "Request to content server " + request.getRequestLine().getUri() + " takes " + elapsedTime + " ms to response " + LOG_MARKER);
    }

    // Put the cookie store with any returned session cookie into the session.
    cookieStore = localContext.getCookieStore();
    try {
      // logger.debug("Cookie store after proxying: " + cookieStore.toString());
      session.setAttribute(COOKIES_ATTRIBUTE, localContext.getCookieStore());
    } catch (IllegalStateException e) {
      // invalid session after logout, ignore
    }
  }

  /**
   * Create an Apache HTTP Client local context object that contains the cookie
   * store from the previous request and a target host header set to a specified
   * host.
   *
   * @param host the host name to set as the target host
   * @param cookieStore the optional cookie store from a previous request
   * @param cookieDomain the domain to set for the cookie
   * @param userIdentifier the optional user identifier to set as the cookie
   *          value
   * @return a local HttpClient context
   */
  private HttpClientContext createLocalContextWithCookiesAndTarget(HttpHost host,
                                                                   CookieStore cookieStore,
                                                                   String cookieDomain) {
    // If no cookie store, create a basic store.
    if (cookieStore == null) {
      cookieStore = new BasicCookieStore();
    }

    // Create a local HTTP context to contain the cookie store.
    HttpClientContext localContext = HttpClientContext.create();

    // logAllCookiesInStore(cookieStore);

    // Bind custom cookie store to the local context
    localContext.setCookieStore(cookieStore);

    // Set the target host to the input HttpHost, allowing the caller
    // to specify the target Host header separately from the proxy URI.
    localContext.setTargetHost(host);

    return localContext;
  }

  /**
   * Configure the various settings in the proxy request: the proxy request
   * itself, the redirect context, the request headers, and the forwarded
   * header.
   * 
   * @param servletRequest the HTTP servlet request
   * @param proxyRequest the proxy request to configure
   * @param requestToProxy the HTTP request to proxy to the target
   */
  private void configureProxyRequest(HttpServletRequest servletRequest,
                                     ProxyRequest proxyRequest,
                                     HttpUriRequest requestToProxy,
                                     String userIdentifier) {
    // Set the actual request before setting its options.
    proxyRequest.setRequestToProxy(requestToProxy);

    // Set the context path for redirects. This information tells the
    // server to redirect to the proxy server rather than the target server
    // or to localhost.
    proxyRequest.setRedirectContext(servletRequest.getContextPath());

    // Set up the request headers based on the current request.
    proxyRequest.copyRequestHeaders(servletRequest, userIdentifier);
    proxyRequest.setXForwardedForHeader(servletRequest);
  }

  /**
   * Proxy the request.
   * 
   * @param session the HTTP session, for setting the cookie store
   * @param servletResponse the servlet response to send to the client
   * @param proxyRequest the proxy request
   * @param host the host to which to set the HOST header, the target host
   * @param partnerId the identifier for the partner
   * @param userIdentifier the partner identifier for the user
   * @throws ServletException when there is a servlet problem, including URI
   *           syntax or handling issues
   */
  private void proxy(final HttpSession session,
                     final HttpServletResponse servletResponse,
                     final ProxyRequest proxyRequest, final HttpHost host,
                     final String partnerId, final String userIdentifier)
      throws ServletException {
    // logger.info("Proxying " + proxyRequest.getMethod()
    //             + " URI from IP address " + proxyRequest.getIp() + ": "
    //             + proxyRequest.getCurrentUri() + "-->"
    //             + proxyRequest.getRequestToProxy().getRequestLine().getUri()
    //             + " with host " + host.toString() + " and user identifier "
    //             + userIdentifier);

    // Create a custom response handler to ensure all resources get freed.
    // Note: ignore the returned response, it is always null.
    ResponseHandler<String> responseHandler = new ResponseHandler<String>() {

      @Override
      public String handleResponse(final HttpResponse proxyResponse)
          throws ClientProtocolException, IOException {
        int statusCode = proxyResponse.getStatusLine().getStatusCode();
        // logger.debug("Proxy returned status " + statusCode + " for URI "
        //              + proxyRequest.getCurrentUri());

        handleResponseHeaders(servletResponse,
                              proxyResponse,
                              partnerId,
                              session);

        // Sends response to caller based on partner server's response.
        if (statusCode >= HttpServletResponse.SC_MULTIPLE_CHOICES
            && statusCode < HttpServletResponse.SC_NOT_MODIFIED) {

          try {
            Header locationHeader =
              proxyResponse.getLastHeader(HttpHeaders.LOCATION);
            if (locationHeader == null) {
              throw new ClientProtocolException(REDIRECT_ERROR);
            }
            String uriString = locationHeader.getValue();
            URI uri = new URI(uriString);

            // Does a proxy rewrite if target host is redirecting
            // to localhost. See issue PW-110 for detail. -SC
            String originalPrefix =
              host.getSchemeName() + "://" + host.getHostName();
            if (uri.getHost() != null && !originalPrefix.equals(uri.getHost())
                && uri.getHost().matches(".*localhost.*")) {
              // Rewrite the location header URI to go to the proxy server.
              String rewrittenUri = rewriteUriFromString(uri, originalPrefix);
              logger.warn(LOCALHOST_REDIRECT_WARN + rewrittenUri);
              servletResponse.sendRedirect(rewrittenUri);

              // Ensure entity content is fully consumed and any stream is
              // closed.
              EntityUtils.consume(proxyResponse.getEntity());
            } else {
              respond(proxyResponse, statusCode);
            }
          } catch (URISyntaxException e) {
            logger.error(URI_SYNTAX_ERROR, e);
            throw new ClientProtocolException(URI_SYNTAX_ERROR, e);
          }
        } else {
          respond(proxyResponse, statusCode);
        }
        // Return a null string instead of the response string, not used here;
        // instead the content gets copied into the servlet response.
        return null;
      }

      /**
       * Rewrite a URI in string format to go to a specific host. The returned
       * string preserves the path, query, and fragment of the original URI,
       * just changing the host to the specified host.
       * 
       * @param uri the original URI
       * @param host the host to which to rewrite the URI
       * @return the rewritten URI
       * @throws URISyntaxException if the original URI has a syntax problem
       */
      private String rewriteUriFromString(URI uri, String host)
          throws URISyntaxException {
        StringBuilder builder = new StringBuilder();
        if (host != null) {
          builder.append(host);
        }

        if (uri.getPath() != null) {
          builder.append(uri.getPath());
        }

        if (uri.getQuery() != null) {
          builder.append(QUERY_PREFIX);
          builder.append(uri.getQuery());
        }

        if (uri.getFragment() != null) {
          builder.append("#");
          builder.append(uri.getFragment());
        }

        return builder.toString();
      }

      /**
       * Respond to the request normally, setting the response status and
       * copying the proxy response to the servlet response. Log the request.
       * 
       * @param proxyResponse the response from the proxied server
       * @param statusCode the status code of the response
       * @return always returns null, ignoring actual response copied to the
       *         servlet response
       * @throws IOException when there is a problem copying the headers or
       *           entity
       */
      private void respond(final HttpResponse proxyResponse, int statusCode)
          throws IOException {
        servletResponse.setStatus(statusCode);
        copyProxyResponseToServletResponse(servletResponse, proxyResponse);
      }
    };

    // Proxy the request.
    try {
      // Send the request to the server, specifying the target host as
      // the original scheme and authority. This permits the back-end
      // partner server to use a virtual host based on the original
      // URI schemes while the proxy request goes to the appropriate
      // back-end host. This is the same as the mod_proxy ProxyPreserveHost
      // directive in Apache. See JIRA PW-288 for details.

      sendRequestToServer(host,
                          proxyRequest.getRequestToProxy(),
                          session,
                          responseHandler,
                          userIdentifier);
    } catch (IOException e) {
      // Syntax error or other problem handling the URI, package into servlet
      // exception
      throw new ServletException(REQUEST_HANDLING_ERROR, e);
    } catch (Exception e) {
      throw new ServletException(e);
    }

    // Don't do anything here, possible redirect already sent
  }

  /**
   * Copy the response headers and entity to the servlet response.
   * 
   * @param response the HTTP servlet response to return to the client
   * @param proxyResponse the response from the proxy target
   * @throws IOException when there is a problem copying the headers or entity
   */
  private void copyProxyResponseToServletResponse(HttpServletResponse response,
                                                  HttpResponse proxyResponse)
      throws IOException {
    // Copy the headers from the proxy to the servlet response.
    copyResponseHeaders(proxyResponse, response);
    // Copy the HTTP Entity (content) to the servlet response.
    copyResponseEntity(proxyResponse, response);
  }

  /**
   * Close a closeable without throwing any IO exceptions.
   * 
   * @param closeable the closeable to close.
   */
  private void closeQuietly(Closeable closeable) {
    if (closeable != null) {
      try {
        closeable.close();
      } catch (IOException e) {
        // Don't propagate the exception.
        logger.warn(CLOSE_DATA_SOURCE_ERROR + e.getMessage(), e);
      }
    }
  }

  /**
   * Create credentialId and secretKey cookies and add them to the response, and
   * set the headers for access control
   *
   * @param servletRequest the HTTP request
   * @param servletResponse the HTTP response
   * @param origins: a list of allowed origins for access control
   */
  private void handleSetCookieRequest(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse,
                                      List<String> origins, String partnerId) {

    Cookie credentialIdCookie =
      new Cookie(CREDENTIAL_ID_COOKIE,
                 servletRequest.getParameter(CREDENTIAL_ID_COOKIE));
    credentialIdCookie.setPath("/");
    // use default domain (current host)
    servletResponse.addCookie(credentialIdCookie);
    // PW-165, add ".arabidopsis.org" domain cookie
    addCookie(servletResponse, credentialIdCookie, partnerId, null);
    setAllowCredentialHeader(servletResponse);

    Cookie secretKeyCookie =
      new Cookie(SECRET_KEY_COOKIE,
                 servletRequest.getParameter(SECRET_KEY_COOKIE));
    secretKeyCookie.setPath("/");
    // use default domain (current host)
    servletResponse.addCookie(secretKeyCookie);
    // PW-165, add ".arabidopsis.org" domain cookie
    addCookie(servletResponse, secretKeyCookie, partnerId, null);

    // logger.debug("Setting cookies: credentialId = "
    //              + credentialIdCookie.getValue() + "; secretKey = "
    //              + secretKeyCookie.getValue());
    // logAllServletResponseHeaders(servletResponse);
  }

  /**
   * Set the headers appropriate to responding to an OPTIONS request.
   *
   * @param servletRequest the HTTP request
   * @param servletResponse the HTTP response
   * @param origins: a list of allowed origins for access control
   */
  private void handleOptionsRequest(HttpServletRequest servletRequest,
                                    HttpServletResponse servletResponse,
                                    List<String> origins) {
    setAllowCredentialHeader(servletResponse);
    servletResponse.setHeader("Access-Control-Allow-Headers",
                              "x-requested-with, content-type, accept, origin, authorization, x-csrftoken");
    servletResponse.setHeader("Access-Control-Allow-Methods",
                              "GET, POST, PUT, DELETE");
  }

  /**
   * Set the CORS header
   *
   * @param servletRequest the HTTP request
   * @param servletResponse the HTTP response
   * @param origins: a list of allowed origins for access control
   */
  private void setCORSHeader(HttpServletRequest servletRequest,
                            HttpServletResponse servletResponse,
                            List<String> origins,
                            Boolean allowCredential) {
    String origin = servletRequest.getHeader("Origin");

    if (origins.contains(origin)) {
      servletResponse.setHeader("Access-Control-Allow-Origin", origin);
      if (allowCredential) {
        setAllowCredentialHeader(servletResponse);
      }
    } else {
      // TAIR3-374: Always allow CORS for API type request
      if (allowCredential) {
        if (isValidOrigin(origin)) {
          logger.debug(LOG_MARKER + "Bypassing attempted API access from non-allowed origin: " + origin);
          servletResponse.setHeader("Access-Control-Allow-Origin", origin);
          setAllowCredentialHeader(servletResponse);
        } else if (origin == null) {
          // a common case for users accesing via their proxy
          // logger.debug("Attempted API access from non-allowed origin: null");
          servletResponse.setHeader("Access-Control-Allow-Origin",
                                  "*");
          // not setting allow credential header since it conflicts with
          // Access-Control-Allow-Origin == *
          // assuming users from such origin is using institutional subscription
        } else {
          // for anything else, deny it
          // logger.debug("Attempted API access from non-allowed origin: " + origin);
          servletResponse.setHeader("Access-Control-Allow-Origin",
                                  origins.iterator().next());
        }
      } else {
        // logger.debug("Attempted access from non-allowed origin: {}", origin);
        // Include an origin to provide a clear browser error
        servletResponse.setHeader("Access-Control-Allow-Origin",
                                  origins.iterator().next());
      }
    }
  }

  private void setAllowCredentialHeader(HttpServletResponse servletResponse) {
    servletResponse.setHeader("Access-Control-Allow-Credentials", "true");
  }

  private boolean isValidOrigin(String urlString) {
    try {
        URL url = new URL(urlString);

        // Check if the protocol is HTTP or HTTPS
        if (!url.getProtocol().equals("http") && !url.getProtocol().equals("https")) {
          return false;
        }

        // Check if the host is valid and not empty
        if (url.getHost() == null || url.getHost().isEmpty()) {
          return false;
        }

        return true;
    } catch (Exception e) {
        return false;
    }
  }

  /**
   * Copy proxied response headers back to the servlet client. Skip any
   * hop-by-hop headers or cookies. Stripping cookies ensures that no cookies
   * set between the Proxy and Target servers affects the cookies sent from
   * Proxy to Client.
   * 
   * @param proxyResponse the proxied server response
   * @param response the servlet response
   */
  private void copyResponseHeaders(HttpResponse proxyResponse,
                                   HttpServletResponse response) {
    for (Header header : proxyResponse.getAllHeaders()) {
      String name = header.getName();
      String value = header.getValue();
      if (ProxyRequest.hopByHopHeaders.containsHeader(name)) {
        continue;
      } else if (name.equals("Set-Cookie")) {
        // MBANK-20: Set PHP session ID for MorphoBank
        if (value != null) {
          int startIndex = value.indexOf(PHP_SESSION_COOKIE);
          if (startIndex != -1) {
            response.addHeader(name, value);
          }
        }
        continue;
      } else if (name.equals("Access-Control-Allow-Origin")) {
        // PWL-898: skip partner CORS header when the partner site allow all access
        if (value.equals("*")) {
          continue;
        }
      }
      response.addHeader(name, value);
    }
  }

  /**
   * Copy response body data (the entity) from the proxy to the servlet client.
   * Ignore any errors. PB-191: rewrote to use stream approach.
   * 
   * @param proxyResponse the response from the proxied server
   * @param response the servlet response
   */
  private void copyResponseEntity(HttpResponse proxyResponse,
                                  HttpServletResponse response) {
    InputStream input = null;
    OutputStream output = null;
    try {
      if (proxyResponse != null && proxyResponse.getEntity() != null
          && proxyResponse.getEntity().getContent() != null) {
        input = proxyResponse.getEntity().getContent();
        output = response.getOutputStream();
        IOUtils.copy(input, output);
      }
    } catch (IOException e) {
      // warn and ignore, probably the client has closed or something
      logger.warn(OUTPUT_STREAM_IO_WARN, e);
    } finally {
      closeQuietly(input);
      closeQuietly(output);
    }
  }

  /**
   * Get the remote IP address of the requester from the request. This method
   * gets, in order, the Remote_Addr header value, the x-forwarded-for header
   * value, or the HTTP request remote address. If the resulting string is a
   * list of comma-separated IP addresses, take the last one in the list.
   * 
   * @param request the HTTP servlet request containing the IP address
   * @return the remote IP address
   */
  @Deprecated
  private static String getIpAddress(HttpServletRequest request) {
    String ipAddress = request.getHeader(REMOTE_ADDR);

    if (ipAddress == null || ipAddress.equalsIgnoreCase(LOCALHOST_V4)
        || ipAddress.equalsIgnoreCase(LOCALHOST_V6)) {
      // no address or localhost, use IP from which forwarded
      ipAddress = request.getHeader(X_FORWARDED_FOR);
      if (ipAddress == null) {
        ipAddress = request.getRemoteAddr();
      }
    }

    //ipAddress = canonicalizeIpAddress(ipAddress);

    return ipAddress;
  }

  /**
   * Produce a list of standard IP addresses with no leading or trailing blanks. If the
   * input string is a comma-delimited list of addresses, the result will be all the 
   * list of addresses.
   *
   * @param ipAddress an IP address or list of IP addresses
   * @return list of IP address with no leading or trailing blanks
   */
  static ArrayList<String> canonicalizeIpAddress(String ipAddress) {
	ArrayList<String> result= new ArrayList<String>();
    if (ipAddress.contains(",")) {
      String[] list = ipAddress.split(",");
      for (String item: list){
    	  result.add(item.trim());
      }
    }else{
    	result.add(ipAddress.trim());
    }
    return result;
  }
  
  /**
   * Validate if a string is a valid ip address. Checks both ipv4 and ipv6.
   *
   * @param an input string
   * @return a boolean value which indicates if the string is a valid ip address
   */
  static Boolean validateIp(String headerValue) {
		if (InetAddressValidator.getInstance().isValid(headerValue)) {
			try {
				InetAddress address = InetAddress.getByName(headerValue);
				return !address.isSiteLocalAddress();
			} catch (UnknownHostException e) {
				return false;
			}
		}
	  return false;
  }
  
  /**
   * Get a list of addresses of the requester from the request. This method
   * gets the Remote_Addr header value, the x-forwarded-for header
   * value, the HTTP request remote address or any other possible header values. 
   * If the resulting string is a list of comma-separated IP addresses, add each
   * one into the final list.
   * @param request the HTTP servlet request containing the IP address
   * @return the remote IP address list
   */
  private static ArrayList<String> getIpAddressList(HttpServletRequest request) {
    ArrayList<String> result = new ArrayList<String>();
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      Enumeration<String> headers = request.getHeaders(headerName);
      while (headers.hasMoreElements()) {
        String headerValue = headers.nextElement();
        for (String canonicalizeIp : canonicalizeIpAddress(headerValue)){
        	if(validateIp(canonicalizeIp)){
        		result.add(canonicalizeIp);
        	}
        }
      }
    }
    // PWL-868: Add private IP for ELB health checker
    if (result.size() == 0) {
      result.add(ELB_HEALTH_CHECKER_IP);
    }

    return result;
  }

  /**
   * Log the cookies in a cookie store.
   *
   * @param cookieStore the cookie store containing the cookies to display
   */
  private void logAllCookiesInStore(CookieStore cookieStore) {
    for (org.apache.http.cookie.Cookie cookie : cookieStore.getCookies()) {
      logger.debug("Cookie " + cookie.getName() + ": " + cookie.getValue()
                   + "[" + cookie.getDomain() + "][" + cookie.getPath() + "]");
    }
  }

  /**
   * Logs all the servlet request headers.
   * 
   * @param request an HTTP servlet request
   */
  private static void logAllServletRequestHeaders(HttpServletRequest request) {
    Enumeration<String> headerNames = request.getHeaderNames();
    logger.debug("------------------ Servlet Request Headers ------------------");
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      Enumeration<String> headers = request.getHeaders(headerName);
      while (headers.hasMoreElements()) {
        String headerValue = headers.nextElement();
        logger.debug("\t" + headerName + ": " + headerValue);
      }
    }
    logger.debug("-------------------------------------------------------------");
  }

  private void logAllUriRequestHeaders(HttpUriRequest request) {
    logger.debug("------------------ URI Request Headers ------------------");

    for (Header header : request.getAllHeaders()) {
      logger.debug("\t" + header.getName() + ": " + header.getValue());
    }
    logger.debug("---------------------------------------------------------");
  }

  /**
   * Logs all the servlet response headers
   *
   * @param response the HTTP servlet response whose header is to print out
   */
  private static void logAllServletResponseHeaders(HttpServletResponse response) {
    Collection<String> names = response.getHeaderNames();
    logger.debug("------------------ Servlet Response Headers ------------------");
    for (String headerName : names) {
      for (String header : response.getHeaders(headerName)) {
        logger.debug("\t" + headerName + ": " + header);
      }
    }
    logger.debug("--------------------------------------------------------------");
  }

  /**
   * Get all the servlet response headers
   *
   * @param response the HTTP servlet response whose header is to obtain
   */
  private static String getAllServletResponseHeaders(HttpServletResponse response) {
    JSONObject headers = new JSONObject();
    Collection<String> names = response.getHeaderNames();
    for (String headerName : names) {
      if (response.getHeaders(headerName).size()>1){
        headers.put(headerName,response.getHeaders(headerName));
      }else if (response.getHeaders(headerName).size() == 1){
        headers.put(headerName,response.getHeaders(headerName).iterator().next());
      }
    }
    return headers.toString();
  }

  /**
   * Checks for special authentication-related headers in a partner's response
   * and adjusts authentication-related cookies appropriately.
   *
   * @param clientResponse the HTTP servlet response being set
   * @param proxyResponse the HTTP response from the proxying
   * @param partnerId the identifier for the partner
   * @param session the HTTP session
   */
  private static void handleResponseHeaders(HttpServletResponse clientResponse,
                                            HttpResponse proxyResponse,
                                            String partnerId,
                                            HttpSession session) {

    Header[] headers = proxyResponse.getAllHeaders();

    for (int i = 0; i < headers.length; i++) {

      Header header = headers[i];
      String name = header.getName();

      // Check for the logout signal from the partner
      // (the value of the special header doesn't matter).
      if (name.equals(LOGOUT_HEADER)) {

        // Remove the authentication-related cookies.
        Cookie credentialIdCookie = new Cookie(CREDENTIAL_ID_COOKIE, null);
        credentialIdCookie.setPath("/");
        credentialIdCookie.setMaxAge(0);
        clientResponse.addCookie(credentialIdCookie);
        // PW-165, remove ".arabidopsis.org" domain cookie
        addCookie(clientResponse, credentialIdCookie, partnerId, 0);

        Cookie secretKeyCookie = new Cookie(SECRET_KEY_COOKIE, null);
        secretKeyCookie.setPath("/");
        secretKeyCookie.setMaxAge(0);
        clientResponse.addCookie(secretKeyCookie);
        // PW-165, add ".arabidopsis.org" domain cookie
        addCookie(clientResponse, secretKeyCookie, partnerId, 0);

        // Close the proxy server session to clear all state.
        session.invalidate();
      } else if (name.equals(PASSWORD_UPDATE_HEADER)) {
        // Check for the password change signal from the partner (the value of
        // the
        // special header carries the new secret key).
        // logger.debug("Request to reset secret key: " + header.getValue());

        Cookie secretKeyCookie =
          new Cookie(SECRET_KEY_COOKIE, header.getValue());
        secretKeyCookie.setPath("/");
        clientResponse.addCookie(secretKeyCookie);
        // PW-165
        addCookie(clientResponse, secretKeyCookie, partnerId, null);
      }
    }
  }

  /**
   * Add a cookie to a servlet response, setting the cookie domain for TAIR
   * partner cookies.
   *
   * @param response the servlet response
   * @param cookie the cookie to add
   * @param partnerId the identifier for the partner
   * @param expiry the maximum age in seconds of the cookie; set to 0 to expire
   *          the cookie
   */
  private static void addCookie(HttpServletResponse response, Cookie cookie,
                                String partnerId, Integer expiry) {
    if (partnerId.equalsIgnoreCase("tair")) {
      cookie.setDomain(COOKIE_DOMAIN);
      if (expiry != null) {
        cookie.setMaxAge(expiry);
      }
      response.addCookie(cookie);
    }
  }
}
