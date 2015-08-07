/*
 * Copyright (c) 2014 Phoenix Bioinformatics Corporation. All rights reserved.
 */

package org.phoenixbioinformatics.proxy;


import java.io.Serializable;
import java.net.URI;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.HeaderGroup;


/**
 * A DTO class that contains the proxy request information; you use this object
 * to save an entire proxy request in the session for later execution, and this
 * object allows for the decomposition of the processing methods. This includes
 * information from the HTTP Request required to rewrite the response from the
 * proxied server. Items like the URI, and query string are convenience items
 * for use by the proxy server in messages and the like.
 * 
 * @author Robert J. Muller
 */
public class ProxyRequest implements Serializable {
  /** serial version UI for serializable class */
  private static final long serialVersionUID = 1L;
  /** the proxied host as a URI object */
  private URI targetObject;
  /** HTTP method, GET or POST */
  private String method = null;
  /** rewritten original request */
  private HttpUriRequest requestToProxy = null;
  /**
   * the original URI, the part of this request's URL from the protocol name up
   * to the query string
   */
  private String currentUri = null;
  /** the URI to which to redirect rather than proxying */
  private String redirectUri = null;
  /** the protocol and domain for a redirect request */
  private String redirectContext = null;
  /** the Entity containing the POST or PUT body content */
  public static HttpEntity entity;
  /** the IP address making the request */
  private String ip = null;

  /** session attribute name for proxy request object */
  private static final String PROXY_REQUEST = "proxyRequest";

  /** These are the "hop-by-hop" headers that the proxy server should not copy. */
  public static final HeaderGroup hopByHopHeaders;

  static {
    hopByHopHeaders = new HeaderGroup();
    String[] headers =
      new String[] { "Connection", "Keep-Alive", "Proxy-Authenticate",
                    "Proxy-Authorization", "TE", "Trailers",
                    "Transfer-Encoding", "Upgrade" };
    for (String header : headers) {
      hopByHopHeaders.addHeader(new BasicHeader(header, null));
    }
  }

  /**
   * Create a ProxyRequest object. This keeps the actual request to proxy null,
   * the client must set that later.
   * 
   * @param targetUriObj the target URI
   * @param method the HTTP method as a string
   * @param currentUri the URI of the request, the part of this request's URL
   *          from the protocol name up to the query string
   * @param ip the IP address making the request
   */
  public ProxyRequest(URI targetUriObj,
                      String method,
                      String currentUri,
                      String ip) {
    this.targetObject = targetUriObj;
    this.method = method;
    this.currentUri = currentUri;
    this.ip = ip;
  }

  /**
   * Get the saved request from the user's HTTP session, or null if there is no
   * saved request.
   * 
   * @param session the HTTP session
   * @return the saved request or null if there is none
   */
  public static ProxyRequest getSavedRequest(HttpSession session) {
    return (ProxyRequest)session.getAttribute(PROXY_REQUEST);
  }

  /**
   * Copy request headers from the servlet client to the proxy request. The
   * method rewrites the HOST header with the proxy host, if there is a HOST
   * header.
   * 
   * @param request the incoming HTTP request
   */
  public void copyRequestHeaders(HttpServletRequest request) {
    // Get an Enumeration of all of the header names sent by the client
    Enumeration<String> enumerationOfHeaderNames = request.getHeaderNames();
    while (enumerationOfHeaderNames.hasMoreElements()) {
      String headerName = enumerationOfHeaderNames.nextElement();
      // Ignore content length (set by InputStreamEntity) and hop-by-hop hdrs.
      if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
        continue;
      if (hopByHopHeaders.containsHeader(headerName))
        continue;

      Enumeration<String> headers = request.getHeaders(headerName);
      while (headers.hasMoreElements()) {
        String headerValue = headers.nextElement();
        // In case the proxy host is running multiple virtual servers,
        // rewrite the Host header to ensure that we get content from
        // the correct virtual server.
        if (headerName.equalsIgnoreCase(HttpHeaders.HOST)) {
          HttpHost host = URIUtils.extractHost(targetObject);
          if (host != null) {
            headerValue = host.getHostName();
            if (host.getPort() != -1) {
              headerValue += ":" + host.getPort();
            }
          }
        }
        requestToProxy.addHeader(headerName, headerValue);
      }
    }
  }

  /**
   * Set the X-Forwarded-For header on the proxy request. This will attach a
   * "remote address" to any existing x-forwarded-for header or will create such
   * a header if it doesn't already exist. The proxy server always allows this
   * forwarding.
   * 
   * @param request the servlet request containing the header
   */
  public void setXForwardedForHeader(HttpServletRequest request) {
    String headerName = "X-Forwarded-For";
    String newHeader = request.getRemoteAddr();
    String existingHeader = request.getHeader(headerName);
    if (existingHeader != null) {
      newHeader = existingHeader + ", " + newHeader;
    }
    requestToProxy.setHeader(headerName, newHeader);
  }

  public void setUserIdentifier(String userIdentifier) {
    requestToProxy.addHeader("Cookie", "userIdentifier="+userIdentifier);
  }

  /**
   * Get the method.
   * 
   * @return a method
   */
  public String getMethod() {
    return method;
  }

  /**
   * Set the method.
   * 
   * @param method a method
   */
  public void setMethod(String method) {
    this.method = method;
  }

  /**
   * Get the proxyRequest.
   * 
   * @return a proxyRequest
   */
  public HttpUriRequest getRequestToProxy() {
    return requestToProxy;
  }

  /**
   * Set the proxyRequest.
   * 
   * @param proxyRequest a proxyRequest
   */
  public void setRequestToProxy(HttpUriRequest proxyRequest) {
    this.requestToProxy = proxyRequest;
  }

  /**
   * Get the current URI.
   * 
   * @return the current URI string
   */
  public String getCurrentUri() {
    return currentUri;
  }

  /**
   * Set the current URI.
   * 
   * @param currentUri a URI string
   */
  public void setCurrentUri(String currentUri) {
    this.currentUri = currentUri;
  }

  /**
   * Get the IP address.
   * 
   * @return an IP address as a string
   */
  public String getIp() {
    return ip;
  }

  /**
   * Set the IP address.
   * 
   * @param ip an IP address as a string
   */
  public void setIp(String ip) {
    this.ip = ip;
  }

  /**
   * Get the redirect context string.
   * 
   * @return a redirect context string
   */
  public String getRedirectContext() {
    return redirectContext;
  }

  /**
   * Set the redirect context string.
   * 
   * @param redirectContext the redirect context string
   */
  public void setRedirectContext(String redirectContext) {
    this.redirectContext = redirectContext;
  }

  /**
   * Get the redirect URI, if any.
   * 
   * @return a URI to which to redirect
   */
  public String getRedirectUri() {
    return redirectContext + redirectUri;
  }

  /**
   * Set the redirect URI.
   * 
   * @param redirectUri a URI to which to redirect
   */
  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }
}
