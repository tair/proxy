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
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CookieStore;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.phoenixbioinformatics.api.ApiService;
import org.phoenixbioinformatics.http.RequestFactory;
import org.phoenixbioinformatics.http.UnsupportedHttpMethodException;
import org.phoenixbioinformatics.properties.ProxyProperties;


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
  /** logger for this class */
  private static final Logger logger = LogManager.getLogger(Proxy.class);

  /** default serial version UID for serializable object */
  private static final long serialVersionUID = 1L;

  /** URI parameter for redirecting */
  private static final String REDIRECT_PARAM = "&redirect=";
  /** Remote_Addr header name constant */
  private static final String REMOTE_ADDR = "Remote_Addr";
  /** x-forwarded-fo header name constant */
  private static final String X_FORWARDED_FOR = "x-forwarded-for";
  /** session attribute for cookies */
  private static final String COOKIES_ATTRIBUTE = "cookies";
  /** name of the partner user id cookie */
  private static final String USER_IDENTIFIER_COOKIE = "userIdentifier";
  /** name of the ptools web server session cookie */
  private static final String PTOOLS_SESSION_COOKIE = "PTools-session";
  /** name of the tomcat session cookie */
  private static final String TOMCAT_SESSION_COOKIE = "JSESSIONID";
  /** name of the Phoenix party id cookie */
  private static final String PARTY_ID_COOKIE = "partyId";
  /** name of the Phoenix secret key cookie */
  private static final String SECRET_KEY_COOKIE = "secret_key";
  /** IPv4 localhost address */
  private static final String LOCALHOST_V4 = "127.0.0.1";
  /** IPv6 localhost address */
  private static final String LOCALHOST_V6 = "0:0:0:0:0:0:0:1";
  /** code for UTF8 */
  private static final String UTF_8 = "UTF-8";
  
  // API codes
  private static final String NEED_LOGIN_CODE = "NeedLogin";
  private static final String METER_WARNING_CODE = "Warning";
  private static final String OK_CODE = "OK";
  private static final String NOT_OK_CODE = "NOT OK";

  /** URI for UI server */
  private static final String UIURI = ProxyProperties.getProperty("ui.uri");
  /** UI URI for login page */
  private static final String LOGIN_URI = ProxyProperties.getProperty("ui.login");
  /** UI URI for meter warning page */
  private static final String METER_WARNING_URI = ProxyProperties.getProperty("ui.meter.warning");
  /** UI URI for meter blocking page */
  private static final String METER_BLOCKING_URI = ProxyProperties.getProperty("ui.meter.blocking");

  /** HashMap that contains partner's information, with sourceUri as the key */
  protected Map<String, ApiService.PartnerOutput> partnerMap =
    new HashMap<String, ApiService.PartnerOutput>();

  // warning messages
  private static final String OUTPUT_STREAM_IO_WARN =
      "IO Error writing entity to output stream";
  private static final String LOCALHOST_REDIRECT_WARN = "Partner response redirected to localhost, redirecting to ";
  private static final String NO_AUTH_CODE_WARN = "checkAccess API returned no authorization code";

  // error messages
  private static final String ENCODING_FAIURE_ERROR = "Encoding faiure for URI ";
  private static final String NO_PARTNER_ERROR =
    "No partner information for URI ";
  private static final String URI_SYNTAX_ERROR = "URI syntax error";
  private static final String RUNTIME_EXCEPTION_ERROR =
    "Runtime exception while handling proxy request";
  private static final String REQUEST_HANDLING_ERROR =
    "Error handling proxy request";
  private static final String CLOSE_DATA_SOURCE_ERROR =
    "Error closing data source in proxy server: ";
  private static final String REDIRECT_ERROR =
    "Redirect status code but no location header in response";

  @Override
  public void init(ServletConfig servletConfig) throws ServletException {
    super.init(servletConfig);
    // Initialize the partnerMap static variable.
    // TODO: synchronize partner cache with database
    partnerMap = ApiService.getAllPartnerInfo();
  }

  @Override
  protected void service(HttpServletRequest servletRequest,
                         HttpServletResponse servletResponse)
      throws ServletException, IOException {
    try {
      handleProxyRequest(servletRequest, servletResponse);
    } catch (RuntimeException e) {
      // Log runtime exception here and don't propagate.
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
    if (servletRequest.getMethod().equals("OPTIONS")) {
      handleOptionsRequest(servletResponse);
      return;
    } else if (action != null && action.equals("setCookies")) {
      handleSetCookieRequest(servletRequest, servletResponse);
      return;
    }

    // Get the complete URI including original domain and query string.
    String uri = servletRequest.getRequestURI().toString();
    logger.debug("Incoming URI: " + uri);
    try {
      String protocol = getProtocol(servletRequest);
      String queryString = servletRequest.getQueryString();
      String requestPath = servletRequest.getPathInfo();
      if (queryString != null) {
        requestPath = requestPath + "?" + queryString;
      }
      String requestUri = getHostUrl(servletRequest);
      String fullRequestUri = protocol + "://" + requestUri + requestPath;

      ApiService.PartnerOutput partnerInfo = partnerMap.get(requestUri);
      if (partnerInfo == null) {
        logger.error(NO_PARTNER_ERROR + requestUri);
        logPartnerMap();
        throw new InvalidPartnerException(NO_PARTNER_ERROR + requestUri);
      }
      String partnerId = partnerInfo.partnerId;
      String targetUri = partnerInfo.targetUri;
      String remoteIp = getIpAddress(servletRequest);

      // populate loginKey and partyId from cookie if available
      String partyId = null;
      String loginKey = null;
      String sessionId = null;
      Cookie cookies[] = servletRequest.getCookies();
      if (cookies != null) {
        for (Cookie c : Arrays.asList(cookies)) {
          String cookieName = c.getName();
          if (cookieName.equals(SECRET_KEY_COOKIE)) {
            loginKey = c.getValue();
          } else if (cookieName.equals(PARTY_ID_COOKIE)) {
            partyId = c.getValue();
          } else if (cookieName.equals(TOMCAT_SESSION_COOKIE)) {
            // Tomcat/Apache session support
            sessionId = c.getValue();
          } else if (cookieName.equals(PTOOLS_SESSION_COOKIE)) {
            // PW-71 cdiff integration--ptools sessions support
            sessionId = c.getValue();
          }
        }
      }

      ApiService.createPageView(remoteIp, fullRequestUri, partyId, sessionId);
      StringBuilder userIdentifier = new StringBuilder();

      // Determine whether to proxy the request.
      if (authorizeProxyRequest(requestPath,
                                loginKey,
                                partnerId,
                                partyId,
                                fullRequestUri,
                                remoteIp,
                                servletResponse,
                                userIdentifier)) {

        // Initialize the proxy request.
        // TODO null for target URI object, check whether and how used in Proxy
        // Request
        ProxyRequest proxyRequest =
          new ProxyRequest(null, servletRequest.getMethod(), uri, remoteIp);

        HttpUriRequest requestToProxy =
          RequestFactory.getUriRequest(servletRequest, targetUri);

        logger.debug("Proxying request from " + proxyRequest.getIp() + "-->"
                     + requestToProxy.getRequestLine().getUri() + "\"");

        configureProxyRequest(servletRequest,
                              proxyRequest,
                              requestToProxy,
                              userIdentifier.toString());
        if (proxyRequest != null) {
          // request approved, proxy to the target server
          proxy(servletRequest.getSession(),
                servletResponse,
                proxyRequest,
                protocol + "://" + requestUri,
                userIdentifier.toString());
        }
      } // end of if(authorizeProxyRequest()){}
    } catch (ServletException | UnsupportedHttpMethodException | IOException e) {
      // Log checked exceptions here, then ignore.
      logger.error(REQUEST_HANDLING_ERROR, e);
    }
  }

  /**
   *
   *
   */
  private void logPartnerMap() {
    StringBuilder builder = new StringBuilder();
    String sep = "";
    for (String mapUri : partnerMap.keySet()) {
      builder.append(sep);
      builder.append(mapUri);
      sep = ", ";
    }
    logger.debug(builder.toString());
  }

  /**
   * Authorize the request based on the information in the HttpServletRequest.
   * Returns true if the servletRequest is allowed to access partner's server,
   * and false otherwise.
   *
   * Redirection path in servletResponse will be set if the client does not
   * allow to access partner's server.
   * 
   * @param requestPath client's request path. example: /news/news.html
   * @param loginKey client's login key to be used for authentication service
   * @param partnerId partner associated with client's request
   * @param partyId client's partyId to be used for authentication service
   * @param fullUri client's full request path. example:
   *          https://test.arabidopsis.org/test/test.html
   * @param remoteIp client's IP address
   * @param servletResponse client's response to be modified if ther request to
   *          partner's server is denied.
   * @return Boolean indicates if client has access to partner' server.
   */
  private Boolean authorizeProxyRequest(String requestPath, String loginKey, String partnerId,
                                        String partyId, String fullUri, String remoteIp,
                                        HttpServletResponse servletResponse, StringBuilder userIdentifier) throws IOException{

    // Skip authorization check and metering incrementation for following static file
    // types. 
    // TODO: This is just a temporary solution similar to how Proxy 1.0 skipping checks 
    // for these file types. Need a permanent solution for this -SC
    if (requestPath.endsWith(".jpg") || requestPath.endsWith(".png") || requestPath.endsWith(".css") ||
        requestPath.endsWith(".js") || requestPath.endsWith(".gif") || requestPath.endsWith(".wsgi") ||
	requestPath.endsWith(".ico")) {
      return true;
    }

    Boolean authorized = false;
    String redirectPath = "";

    logger.debug("checkAccess API parameters: " + fullUri + ", " + requestPath
                 + ", " + partnerId + ", " + loginKey + ", " + partyId + ", "
                 + remoteIp);

    ApiService.AccessOutput accessOutput =
      ApiService.checkAccess(requestPath,
                             loginKey,
                             partnerId,
                             partyId,
                             remoteIp);
    String auth = NOT_OK_CODE;
    if (accessOutput != null) {
      auth = accessOutput.status;
      userIdentifier.append(accessOutput.userIdentifier);
    } else {
      // Log and continue
      logger.warn(NO_AUTH_CODE_WARN);
    }

    String redirectUri = "";
    try {
      redirectUri = URLEncoder.encode(fullUri, UTF_8);
    } catch (UnsupportedEncodingException e) {
      // Log and ignore, use un-encoded redirect URI
      logger.warn(ENCODING_FAIURE_ERROR + redirectUri, e);
    }

    if (auth.equals(OK_CODE)) {
      // grant access
      authorized = true;
      logger.debug("Party " + partyId + " authorized for free content " + fullUri
                   + " at partner " + partnerId);
    } else if (auth.equals("NeedSubscription")) {
      logger.debug("Party " + partyId
                   + " needs to subscribe to see paid content " + fullUri
                   + " at partner " + partnerId);
      String meter = ApiService.checkMeteringLimit(remoteIp, partnerId);
      if (meter.equals(OK_CODE)) {
        logger.debug("Allowed free access to content by metering");
        authorized = true;
        ApiService.incrementMeteringCount(remoteIp, partnerId);
      } else if (meter.equals(METER_WARNING_CODE)) {
        logger.debug("Warned to subscribe by meter limit");
        authorized = false;
        redirectPath =
          UIURI + METER_WARNING_URI + partnerId + REDIRECT_PARAM + redirectUri;
        ApiService.incrementMeteringCount(remoteIp, partnerId);
      } else {
        logger.debug("Blocked from paid content by meter block");
        authorized = false;
        redirectPath =
          UIURI + METER_BLOCKING_URI + partnerId + REDIRECT_PARAM + redirectUri;
      }
    } else if (auth.equals(NEED_LOGIN_CODE)) {
      logger.debug("Party " + partyId + " needs to login to access " + fullUri
                   + " at partner " + partnerId);
      authorized = false;
      redirectPath =
        UIURI + LOGIN_URI + partnerId + REDIRECT_PARAM + redirectUri;
    }

    if (!authorized) {
      logger.debug("Party " + partyId + " not authorized for " + fullUri
                   + " at partner " + partnerId + ", redirecting to "
                   + redirectPath);
      servletResponse.sendRedirect(redirectPath);
    }

    return authorized;
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
  private void sendRequestToServer(HttpUriRequest request, HttpSession session,
                                   ResponseHandler<String> responseHandler,
                                   String userIdentifier)
      throws ClientProtocolException, IOException {
    CloseableHttpClient client = null;
    // Get cookie store from session if it's there.
    CookieStore cookieStore =
      (CookieStore)session.getAttribute(COOKIES_ATTRIBUTE);
    
    // Otherwise, create a basic store.
    if (cookieStore == null) {
      cookieStore = new BasicCookieStore();
    }
    
    org.apache.http.impl.cookie.BasicClientCookie cookie =
      new org.apache.http.impl.cookie.BasicClientCookie(USER_IDENTIFIER_COOKIE,
                                                        userIdentifier);
    cookie.setPath("");
    cookie.setDomain("");
    cookieStore.addCookie(cookie);
    // Create a local HTTP context to contain the cookie store.
    HttpClientContext localContext = HttpClientContext.create();
    logger.debug(cookieStore.toString());
    // Bind custom cookie store to the local context
    localContext.setCookieStore(cookieStore);
    client = HttpClientBuilder.create().disableRedirectHandling().build();
    // Execute the request on the proxied server. Ignore returned string.
    client.execute(request, responseHandler, localContext);

    // Put the cookie store with any returned session cookie into the session.
    cookieStore = localContext.getCookieStore();
    session.setAttribute(COOKIES_ATTRIBUTE, localContext.getCookieStore());
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
    proxyRequest.copyRequestHeaders(servletRequest);
    proxyRequest.setXForwardedForHeader(servletRequest);
    
    // Set up the partner user identifier cookie.
    proxyRequest.setUserIdentifier(userIdentifier);
  }

  /**
   * Proxy the request.
   * 
   * @param session the HTTP session, for setting the cookie store
   * @param servletResponse the servlet response to send to the client
   * @param proxyRequest the proxy request
   * @throws ServletException when there is a servlet problem, including URI
   *           syntax or handling issues
   */
  private void proxy(final HttpSession session,
                     final HttpServletResponse servletResponse,
                     final ProxyRequest proxyRequest,
                     final String originalHost, final String userIdentifier)
      throws ServletException {
    logger.info("Proxying " + proxyRequest.getMethod()
                + " URI from IP address " + proxyRequest.getIp() + ": "
                + proxyRequest.getCurrentUri() + " -- "
                + proxyRequest.getRequestToProxy().getRequestLine().getUri()
                + " ... " + originalHost + " ... " + userIdentifier);

    // Create a custom response handler to ensure all resources get freed.
    // Note: ignore the returned response, it is always null.
    ResponseHandler<String> responseHandler = new ResponseHandler<String>() {

      @Override
      public String handleResponse(final HttpResponse proxyResponse)
          throws ClientProtocolException, IOException {
        int statusCode = proxyResponse.getStatusLine().getStatusCode();
        logger.debug("Proxy returned status " + statusCode + " for URI "
                     + proxyRequest.getCurrentUri());

        // printAllResponseHeaders(proxyResponse);
        handleLogoutHeader(servletResponse, proxyResponse);

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
            if (uri.getHost() != null && !originalHost.equals(uri.getHost())
                && uri.getHost().matches(".*localhost.*")) {
              // Rewrite the location header URI to go to the proxy server.
              String rewrittenUri = rewriteUriFromString(uri, originalHost);
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
          builder.append("?");
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
      sendRequestToServer(proxyRequest.getRequestToProxy(),
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
  protected void closeQuietly(Closeable closeable) {
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
   * Create partyId and secret_key cookies and add them to the response,
   * and set the headers for access control
   *
   * @param servletRequest the HTTP request
   * @param servletResponse the HTTP response
   */
  private void handleSetCookieRequest(HttpServletRequest servletRequest,
                                       HttpServletResponse servletResponse) {
    Cookie partyIdCookie =
      new Cookie(PARTY_ID_COOKIE, servletRequest.getParameter(PARTY_ID_COOKIE));
    Cookie secret_keyCookie =
      new Cookie(SECRET_KEY_COOKIE, servletRequest.getParameter(SECRET_KEY_COOKIE));
    servletResponse.addCookie(partyIdCookie);
    servletResponse.addCookie(secret_keyCookie);
    servletResponse.setHeader("Access-Control-Allow-Origin", UIURI);
    servletResponse.setHeader("Access-Control-Allow-Credentials", "true");
    logger.debug("Setting Cookies for partyId=" + partyIdCookie.getValue()
                 + " and secret_key=" + secret_keyCookie.getValue());
  }

  /**
   * Set the headers appropriate to responding to an OPTIONS request.
   *
   * @param servletResponse the HTTP response
   */
  private void handleOptionsRequest(HttpServletResponse servletResponse) {
    servletResponse.setHeader("Access-Control-Allow-Origin", UIURI);
    servletResponse.setHeader("Access-Control-Allow-Credentials", "true");
    servletResponse.setHeader("Access-Control-Allow-Headers",
                              "x-requested-with, content-type, accept, origin, authorization, x-csrftoken");
    servletResponse.setHeader("Access-Control-Allow-Methods",
                              "GET, POST, PUT, DELETE");
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
  protected void copyResponseHeaders(HttpResponse proxyResponse,
                                     HttpServletResponse response) {
    for (Header header : proxyResponse.getAllHeaders()) {
      if (ProxyRequest.hopByHopHeaders.containsHeader(header.getName())
          || header.getName().equals("Set-Cookie")) {
        continue;
      }
      response.addHeader(header.getName(), header.getValue());
    }
  }

  /**
   * Copy response body data (the entity) from the proxy to the servlet client.
   * Ignore any errors. PB-191: rewrote to use stream approach.
   * 
   * @param proxyResponse the response from the proxied server
   * @param response the servlet response
   */
  protected void copyResponseEntity(HttpResponse proxyResponse,
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
   * Get the host URI from the x-forwarded-host header.
   *
   * @param request the HTTP request
   * @return
   */
  public static String getHostUrl(HttpServletRequest request) {
    return request.getHeader("x-forwarded-host");
  }

  /**
   * Get the protocol; this is always https so that the proxy server remains as
   * secure as possible.
   *
   * @param request the request
   * @return "https"
   */
  public static String getProtocol(HttpServletRequest request) {
    return "https";
    // return request.getHeader("X-Forwarded-Proto");
  }

  /**
   * Get the remote IP address of the requester from the request. This method
   * gets, in order, the Remote_Addr header value, the x-forwarded-for header
   * value, or the HTTP request remote address.
   * 
   * @param request the HTTP servlet request containing the IP address
   * @return the remote IP address
   */
  public static String getIpAddress(HttpServletRequest request) {
    String ipAddress = request.getHeader(REMOTE_ADDR);

    if (ipAddress == null || ipAddress.equalsIgnoreCase(LOCALHOST_V4)
        || ipAddress.equalsIgnoreCase(LOCALHOST_V6)) {
      // no address or localhost, use IP from which forwarded
      ipAddress = request.getHeader(X_FORWARDED_FOR);
      if (ipAddress == null) {
        ipAddress = request.getRemoteAddr();
      }
    }

    return ipAddress;
  }

  /**
   * Prints out all headers of a HttpServletRequest object
   *
   * @param request the HTTP servlet request whose header is to print out
   * @return none
   */
  public static void printAllRequestHeaders(HttpServletRequest request) {
    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName = headerNames.nextElement();
      logger.debug(headerName);
      Enumeration<String> headers = request.getHeaders(headerName);
      logger.debug("----");
      while (headers.hasMoreElements()) {
        String headerValue = headers.nextElement();
        logger.debug(headerValue);
      }
      logger.debug("------------------");
    }
  }

  /**
   * Prints out all headers of a HttpResponse object
   *
   * @param request the HTTP response whose header is to print out
   * @return none
   */
  public static void printAllResponseHeaders(HttpResponse response) {
    Header[] headers = response.getAllHeaders();
    Header header = null;
    for (int i = 0; i < headers.length; i++) {
      header = headers[i];
      logger.debug(header.getName());
      logger.debug(header.getValue());
      logger.debug("----");
    }
    logger.debug("------------------");
  }

  /**
   * This function loops through all headers of an response object from a
   * partner server, and identify if a "Phoenix-Proxy-Logout" object exists. If
   * so, then logs out a user by resetting the login related cookies.
   *
   * @param request the HTTP response whose header is to print out
   * @return none
   */
  public static void handleLogoutHeader(HttpServletResponse clientResponse,
                                        HttpResponse proxyResponse) {
    Header[] headers = proxyResponse.getAllHeaders();
    for (int i = 0; i < headers.length; i++) {
      if (headers[i].getName().equals("Phoenix-Proxy-Logout")) {
        Cookie partyCookie = new Cookie(PARTY_ID_COOKIE, null);
        partyCookie.setPath("/");
        Cookie secret_keyCookie = new Cookie(SECRET_KEY_COOKIE, null);
        secret_keyCookie.setPath("/");
        clientResponse.addCookie(partyCookie);
        clientResponse.addCookie(secret_keyCookie);
      }
    }
  }
}
