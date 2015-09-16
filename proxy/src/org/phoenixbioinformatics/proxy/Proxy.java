/*
 * Copyright (c) 2015 Phoenix Bioinformatics Corporation. All rights reserved.
 */

package org.phoenixbioinformatics.proxy;

import java.util.Arrays;

import java.util.Enumeration;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
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
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.phoenixbioinformatics.http.RequestFactory;
import org.phoenixbioinformatics.http.UnsupportedHttpMethodException;

import org.phoenixbioinformatics.api.ApiService;

import java.io.PrintWriter;
import javax.servlet.http.Cookie;
import java.lang.StringBuilder;

import java.net.URLEncoder;
import java.io.UnsupportedEncodingException;

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

  private static final String OUTPUT_STREAM_IO_WARNING =
    "IO Error writing entity to output stream";

  private static final String RESPONSE_HANDLING_ERROR =
    "Error in handling response";

  private static final String URI_SYNTAX_ERROR = "URI syntax error";

  /** logger for this class */
  private static final Logger logger = LogManager.getLogger(Proxy.class);

  /** default serial version UID for serializable object */
  private static final long serialVersionUID = 1L;

  /** Remote_Addr header name constant */
  private static final String REMOTE_ADDR = "Remote_Addr";
  /** x-forwarded-fo header name constant */
  private static final String X_FORWARDED_FOR = "x-forwarded-for";
  /** IPv4 localhost address */
  private static final String LOCALHOST_V4 = "127.0.0.1";
  /** IPv6 localhost address */
  private static final String LOCALHOST_V6 = "0:0:0:0:0:0:0:1";

  /** URI for UI server */
  private static final String UIURI = "https://demoui.arabidopsis.org";

  /** HashMap that contains partner's information, with sourceUri as the key */
  protected Map<String, ApiService.PartnerOutput> partnerMap =
    new HashMap<String, ApiService.PartnerOutput>();

  /** proxy server property name */
  private static final String PROXY_SERVER_PROPERTY = "proxy.server";

  /** error constant for top-level runtime exception */
  private static final String RUNTIME_EXCEPTION_ERROR =
    "Runtime exception while handling proxy request";
  /** error constant for request handler checked exceptions */
  private static final String REQUEST_HANDLING_ERROR =
    "Error handling proxy request";
  /** error constant for no URI for redirect */
  private static final String REDIRECT_NO_URI_FOUND_ERROR =
    "Redirect requested but no URI found";
  /** error constant for closing data source */
  private static final String CLOSE_DATA_SOURCE_ERROR =
    "Error closing data source in proxy server: ";
  /** error constant for redirect response, no location header */
  private static final String REDIRECT_ERROR =
    "Redirect status code but no location header in response";
  /** the session attribute for the cookie store */
  public static final String COOKIES_ATTRIBUTE = "cookies";

  @Override
  public void init(ServletConfig servletConfig) throws ServletException {
    super.init(servletConfig);
    // Initialize the partnerMap static variable.
    // TODO: Add codes to periodically sync the map with database.
    partnerMap = ApiService.getAllPartnerInfo();
  }

  @Override
  protected void service(HttpServletRequest servletRequest,
                         HttpServletResponse servletResponse)
      throws ServletException, IOException {
    URI targetObject = getTargetUri();

    try {
      handleProxyRequest(servletRequest, servletResponse, targetObject);
    } catch (RuntimeException e) {
      // Log runtime exception here and don't propagate.
      logger.error(RUNTIME_EXCEPTION_ERROR, e);
    } catch (Exception e) {
      // Don't propagate checked exceptions out of servlet, already logged
    }
  }

  /**
   * Get the target URI.
   * 
   * @return the target URI
   */
  private URI getTargetUri() {
    // TODO add multiple-partner handling here to get target object URI; add
    // parameters to the method as necessary.
    return null;
  }

  /**
   * This function checks if the request is intended solely for setting cookies.
   * If so, then set the cookie with the given partyId and secret_key, and 
   * set the appropriate cross origin parameters.
   *
   * @param servletRequest the HTTP servlet request
   * @param servletResponse the HTTP servlet response
   *
   * @return Boolean to indicate if this is a set cookie request
   */
  private Boolean handleSetCookieRequest(HttpServletRequest servletRequest, 
                                      HttpServletResponse servletResponse) {
    String action = servletRequest.getParameter("action");

    if (action != null && action.equals("setCookies")) {
      Cookie partyIdCookie = new Cookie("partyId", servletRequest.getParameter("partyId"));
      Cookie secret_keyCookie = new Cookie("secret_key", servletRequest.getParameter("secret_key"));
      servletResponse.addCookie(partyIdCookie);
      servletResponse.addCookie(secret_keyCookie);
      servletResponse.setHeader("Access-Control-Allow-Origin", UIURI);
      servletResponse.setHeader("Access-Control-Allow-Credentials", "true");
      logger.debug("Setting Cookies for partyId="+partyIdCookie.getValue()+" and secret_key="+secret_keyCookie.getValue());
      return true;
    }
    return false;
  }

  /**
   * Handle a request by configuring the request, authorizing it, then proxying
   * or refusing it.
   * 
   * @param servletRequest the HTTP servlet request
   * @param servletResponse the HTTP servlet response
   * @param targetObject the target URI object
   */
  private void handleProxyRequest(HttpServletRequest servletRequest,
                                  HttpServletResponse servletResponse,
                                  URI targetObject) {

    // skips proxying if the request is a simple set cookie request
    if (handleSetCookieRequest(servletRequest, servletResponse)) {
      return;
    }

    // Get the complete URI including original domain and query string.
    String uri = servletRequest.getRequestURI().toString();
    logger.debug("Incoming URI: " + uri);
    //printAllRequestHeaders(servletRequest);
    try {
      String protocol = getProtocol(servletRequest);
      String queryString = servletRequest.getQueryString();
      String requestPath = servletRequest.getPathInfo();
      if (queryString != null) {
        requestPath = requestPath + "?"+queryString;
      }
      String requestUrl = getHostUrl(servletRequest);
      String fullRequestUri = protocol+"://"+requestUrl+requestPath;
      
      ApiService.PartnerOutput partnerInfo = partnerMap.get(requestUrl);
      if (partnerInfo == null) {
        // Invalid partnerInfo based on the url, return false for now.
        // TODO: redirect to error page.
        logger.error("invalid partnerInfo from requestUrl="+requestUrl);
        return;
      }
      String partnerId = partnerInfo.partnerId;
      String targetUri = partnerInfo.targetUri;
      String remoteIp = getIpAddress(servletRequest);

      // populate loginKey and partyId from cookie if available
      String partyId = null;
      String loginKey = null;
      String jSessionId = null;
      Cookie cookies[] = servletRequest.getCookies();
      if (cookies != null) {
        for (Cookie c : Arrays.asList(cookies)) {
          String cookieName = c.getName();
          if (cookieName.equals("secret_key")) {
            loginKey = c.getValue();
          } else if (cookieName.equals("partyId")) {
            partyId = c.getValue();
          } else if (cookieName.equals("JSESSIONID")) {
            jSessionId = c.getValue();
          }
        }
      }

      ApiService.createPageView(remoteIp, fullRequestUri, partyId, jSessionId);
      StringBuilder userIdentifier = new StringBuilder();

      // Determine whether to proxy the request.
      if (authorizeProxyRequest(requestPath, loginKey, partnerId, partyId,
                                fullRequestUri, remoteIp, servletResponse, userIdentifier)) {

        // Initialize the proxy request.
        ProxyRequest proxyRequest =
          new ProxyRequest(targetObject,
                           servletRequest.getMethod(),
                           uri,
                           remoteIp);
        
        HttpUriRequest requestToProxy =
          RequestFactory.getUriRequest(servletRequest, targetUri);
        
        // TODO reenable printing targetObject.toString() when targetObject is not null.
        logger.debug("Proxying request from " + proxyRequest.getIp() + "-->"
                     //                   + targetObject.toString() + " as \""
                     + requestToProxy.getRequestLine().getUri() + "\"");
        
        configureProxyRequest(servletRequest, proxyRequest, requestToProxy, userIdentifier.toString());
        if (proxyRequest != null) {
          // request approved, proxy to the target server
          proxy(servletRequest.getSession(), servletResponse, proxyRequest, protocol+"://"+requestUrl, userIdentifier.toString());
        } else {
          // request refused, redirect to another page
          redirectToRefusedUri(servletResponse,
                               proxyRequest,
                               servletRequest.getSession());
        }
      } // end of if(authorizeProxyRequest()){}
    } catch (ServletException | UnsupportedHttpMethodException | IOException e) {
      // Log checked exceptions here, then ignore.
      logger.error(REQUEST_HANDLING_ERROR, e);
    }
  }
  
  /**
   * Authorize the request based on the information in the HttpServletRequest.
   * Returns true if the servletRequest is allowed to access partner's server, and 
   * false otherwise.
   *
   * Redirection path in servletResponse will be set if the client does not
   * allow to access partner's server.
   * 
   * @param requestPath        client's request path. example: /news/news.html
   * @param loginKey           client's login key to be used for authentication service
   * @param partnerId          partner associated with client's request
   * @param partyId            client's partyId to be used for authentication service
   * @param fullUri            client's full request path. example: https://test.arabidopsis.org/test/test.html
   * @param remoteIp           client's IP address
   * @param servletResponse    client's response to be modified if ther request to
   *                           partner's server is denied.
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
        requestPath.endsWith("js") || requestPath.endsWith(".gif") || requestPath.endsWith(".wsgi")) {
      return true;
    }

    Boolean authorized = false;
    String redirectPath = "";
    
    // debugging string
    logger.debug("parameters used to call API services are "+fullUri+
                 ", "+requestPath+", "+partnerId+", "+loginKey+", "+
                 partyId+", "+remoteIp);

    ApiService.AccessOutput accessOutput = ApiService.checkAccess(requestPath, loginKey, partnerId, partyId, remoteIp);
    String auth = accessOutput.status;
    userIdentifier.append(accessOutput.userIdentifier);
    String redirectUri = "";
    try {
	redirectUri = URLEncoder.encode(fullUri, "UTF-8");
    } catch (UnsupportedEncodingException e) {
	logger.debug("Encoding faiure", e);
    }

    if (auth.equals("OK")) {
      // grant access
      authorized = true;
    } else if (auth.equals("NeedSubscription")) {
      String meter = ApiService.checkMeteringLimit(remoteIp, partnerId);
      if (meter.equals("OK")) {
        authorized = true;
        String meteringResponse = ApiService.incrementMeteringCount(remoteIp, partnerId);
      } else if (meter.equals("Warning")) {
        authorized = false;
        redirectPath = UIURI+"/#/metering?partnerId="+partnerId+"&redirect="+redirectUri;
        String meteringResponse = ApiService.incrementMeteringCount(remoteIp, partnerId);
      } else {
        authorized = false;
        redirectPath = UIURI+"/#/metering?exceed=true&partnerId="+partnerId+"&redirect="+redirectUri;
      }
    } else if (auth.equals("NeedLogin")) {
      authorized = false;
      redirectPath = UIURI+"/#/login?partnerId="+partnerId+"&redirect="+redirectUri;
    }
    
    if (!authorized) {
      logger.debug("Partner server access denied, redirecting to: "+redirectPath);
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
    if (cookieStore == null) {
      cookieStore = new BasicCookieStore();
    }
    org.apache.http.impl.cookie.BasicClientCookie cookie = new org.apache.http.impl.cookie.BasicClientCookie("userIdentifier", userIdentifier);
    cookie.setPath("");
    cookie.setDomain("");
    cookieStore.addCookie(cookie);
    // Create a local HTTP context to contain the cookie store.
    HttpClientContext localContext = HttpClientContext.create();
    if (cookieStore == null) {
      client = HttpClientBuilder.create().disableRedirectHandling().build();
      client.execute(request, responseHandler, localContext);
    } else {
      logger.debug(cookieStore.toString());
      // Bind custom cookie store to the local context
      localContext.setCookieStore(cookieStore);
      client = HttpClientBuilder.create().disableRedirectHandling().build();
      // Execute the request on the proxied server. Ignore returned string.
      client.execute(request, responseHandler, localContext);
    }

    //    Put the cookie store with any returned session cookie into the session.
    cookieStore = localContext.getCookieStore();
    session.setAttribute(COOKIES_ATTRIBUTE, localContext.getCookieStore());
  }

  /**
   * Redirect to the redirect URI previously set.
   * 
   * @param response the HTTP servlet response
   * @param proxyRequest the current proxy request
   * @param session HTTP session
   * @throws ServletException when there is a problem setting the response or no
   *           redirect URI was found
   */
  private void redirectToRefusedUri(HttpServletResponse response,
                                    ProxyRequest proxyRequest,
                                    HttpSession session)
      throws ServletException {
    String uri = proxyRequest.getRedirectUri();
    if (uri != null) {
      logger.debug("Redirecting to URI " + uri);
      try {
        response.sendRedirect(uri);
      } catch (IOException e) {
        // re-throw as servlet exception;
        throw new ServletException(REQUEST_HANDLING_ERROR, e);
      }
    } else {
      // no URI
      throw new ServletException(REDIRECT_NO_URI_FOUND_ERROR);
    }
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
    proxyRequest.setUserIdentifier(userIdentifier);
  }

  /**
   * Get the host to which to proxy.
   * 
   * @return the host name as a string
   */
  private String getHost() {
    // TODO get host for multiple-partner implementation; add arguments as
    // necessary.
    return null;
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
                     final String originalHost,
                     final String userIdentifier) throws ServletException {
    logger.info("Proxying " + proxyRequest.getMethod()
                + " URI from IP address " + proxyRequest.getIp() + ": "
                + proxyRequest.getCurrentUri() + " -- "
                + proxyRequest.getRequestToProxy().getRequestLine().getUri() + " ... "
                + originalHost + " ... " + userIdentifier);

    // Create a custom response handler to ensure all resources get freed.
    // Note: ignore the returned response, it is always null.
    ResponseHandler<String> responseHandler = new ResponseHandler<String>() {

      @Override
      public String handleResponse(final HttpResponse proxyResponse)
          throws ClientProtocolException, IOException {
        int statusCode = proxyResponse.getStatusLine().getStatusCode();
        logger.debug("Proxy returned status " + statusCode);

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
		if (uri.getHost() != null &&
		  !originalHost.equals(uri.getHost()) &&
		  uri.getHost().matches(".*localhost.*")) {
		    // Rewrite the location header URI to go to the proxy server.
		    String rewrittenUri = rewriteUriFromString(uri, originalHost);
		    logger.debug("Based on proxy target response, redirecting to "
				 + rewrittenUri);
		    servletResponse.sendRedirect(rewrittenUri);

		    // Ensure entity content is fully consumed and any stream is closed.
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
       * string preserves the path, query, and fragment of the original URI, just
       * changing the host to the specified host.
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
      if (proxyResponse != null &&
	proxyResponse.getEntity() != null &&
	proxyResponse.getEntity().getContent() != null) {
	input = proxyResponse.getEntity().getContent();
        output = response.getOutputStream();
        IOUtils.copy(input, output);
      }
    } catch (IOException e) {
      // warn and ignore, probably the client has closed or something
      logger.warn(OUTPUT_STREAM_IO_WARNING, e);
    } finally {
      closeQuietly(input);
      closeQuietly(output);
    }
  }

  public static String getHostUrl(HttpServletRequest request) {
    return request.getHeader("x-forwarded-host");
  }

  public static String getProtocol(HttpServletRequest request) {
    return request.getHeader("X-Forwarded-Proto");
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
    for (int i=0; i<headers.length; i++) {
      header = headers[i];
      logger.debug(header.getName());
      logger.debug(header.getValue());
      logger.debug("----");
    }
    logger.debug("------------------");
  }

  /**
   * This function loops thorugh all headers of an response 
   * object from a partner server, and identify if a "Phoenix-Proxy-Logout" 
   * object exists. If so, then logs out a user by resetting the 
   * login related cookies.
   *
   * @param request the HTTP response whose header is to print out
   * @return none
   */
  public static void handleLogoutHeader(HttpServletResponse clientResponse, HttpResponse proxyResponse) {
    Header[] headers = proxyResponse.getAllHeaders();
    Header header = null;
    for (int i=0; i<headers.length; i++) {
      header = headers[i];
      if (headers[i].getName().equals("Phoenix-Proxy-Logout")){
        Cookie partyCookie = new Cookie("partyId", null);
        partyCookie.setPath("/");
        Cookie secret_keyCookie = new Cookie("secret_key", null);
        secret_keyCookie.setPath("/");
        clientResponse.addCookie(partyCookie);
        clientResponse.addCookie(secret_keyCookie);
      }
    }
  }
}
