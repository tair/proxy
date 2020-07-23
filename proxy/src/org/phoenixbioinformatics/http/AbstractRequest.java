/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Formatter;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * An abstract superclass with shared implementation methods for the individual
 * HTTP method subclasses
 * 
 * @author Robert J. Muller
 */
public abstract class AbstractRequest implements IRequest {

  /** logger for this class */
  private static final Logger logger =
    LogManager.getLogger(AbstractRequest.class);

  /** proxy server property name */
  // private static final String PROXY_TARGET_PROPERTY = "proxy.target";
  /** the string corresponding to the target host */
  // protected static String TARGET =
  // ProxyProperties.getProperty(PROXY_TARGET_PROPERTY);

  /** query-encoding characters */
  private static final BitSet asciiQueryChars;

  // Initialize the query-encoding character BitSet
  static {
    char[] notReserved = "_-!.~'()*".toCharArray();
    char[] punctuation = ",;:$&+=".toCharArray();
    char[] reserved = "?/[]@".toCharArray();

    asciiQueryChars = new BitSet(128);
    for (char c = 'a'; c <= 'z'; c++)
      asciiQueryChars.set((int)c);
    for (char c = 'A'; c <= 'Z'; c++)
      asciiQueryChars.set((int)c);
    for (char c = '0'; c <= '9'; c++)
      asciiQueryChars.set((int)c);
    for (char c : notReserved)
      asciiQueryChars.set((int)c);
    for (char c : punctuation)
      asciiQueryChars.set((int)c);
    for (char c : reserved)
      asciiQueryChars.set((int)c);

    asciiQueryChars.set((int)'%');
  }

  @Override
  abstract public HttpUriRequest getUriRequest(HttpServletRequest servletRequest,
                                               String partnerHostUri)
      throws IOException;

  /**
   * Encodes characters in the query or fragment part of the URI.
   * 
   * <p>
   * An incoming URI sometimes has characters disallowed by the specification.
   * HttpClient insists that the outgoing proxied server request have a valid
   * URI, because it uses the Java {@link URI}. To be more forgiving, we must
   * escape the problematic characters. See the URI class for the specification.
   * 
   * @param in example: name=value&foo=bar#fragment
   * 
   * @return the character sequence with invalid characters escaped
   */
  private CharSequence encodeUriQuery(CharSequence in) {
    // Note that I can't simply use URI.java to encode because it will escape
    // pre-existing escaped things.
    StringBuilder outBuf = null;
    Formatter formatter = null;
    try {
      for (int i = 0; i < in.length(); i++) {
        char c = in.charAt(i);
        boolean escape = true;
        if (c < 128) {
          if (asciiQueryChars.get((int)c)) {
            escape = false;
          }
        } else if (!Character.isISOControl(c) && !Character.isSpaceChar(c)) {// not-ascii
          escape = false;
        }
        if (!escape) {
          if (outBuf != null)
            outBuf.append(c);
        } else {
          // escape
          if (outBuf == null) {
            outBuf = new StringBuilder(in.length() + 5 * 3);
            outBuf.append(in, 0, i);
            formatter = new Formatter(outBuf);
          }
          // leading %, 0 padded, width 2, capital hex
          formatter.format("%%%02X", (int)c);
        }
      }
    } finally {
      if (formatter != null) {
        formatter.close();
      }
    }
    return outBuf != null ? outBuf : in;
  }

  /**
   * Extract the URI from a servlet request and rewrite it using the target
   * server URI scheme and authority, with URI encoding for security. The method
   * handles a query string and/or URI fragments
   * (?name=value&name2=value#fragment).
   * 
   * @param servletRequest the incoming HTTP request
   * @param targetPrefix the scheme and authority of the target URI
   *          (https://domain.arabidopsis.org, for example)
   * @return the URI composed from the request
   */
  protected String rewriteUriFromRequest(HttpServletRequest servletRequest,
                                         String targetPrefix) {
    // Check inputs.
    if (servletRequest == null) {
      throw new RuntimeException("Null servlet request");
    }
    if (targetPrefix == null) {
      throw new RuntimeException("Null target prefix for proxy target URI");
    }

    StringBuilder uri = new StringBuilder(targetPrefix);

    String pathInfo = servletRequest.getPathInfo();
    if (pathInfo != null) {
      logger.debug("Path info: " + pathInfo);
      uri.append(encodeUriQuery(pathInfo));
    }

    // Handle the query string & fragment
    String queryString = servletRequest.getQueryString();
    logger.debug("Query string: " + queryString);
    String fragment = null;
    // split off fragment from queryString, updating queryString if found
    if (queryString != null) {
      int fragIdx = queryString.indexOf('#');
      if (fragIdx >= 0) {
        fragment = queryString.substring(fragIdx + 1);
        queryString = queryString.substring(0, fragIdx);
      }
    }

    if (queryString != null && !queryString.isEmpty()) {
      uri.append('?');
      uri.append(encodeUriQuery(queryString));
    }

    if (fragment != null) {
      uri.append('#');
      uri.append(encodeUriQuery(fragment));
    }

    String rewrittenUri = uri.toString();
    logger.debug("Rewrote servlet URI as " + rewrittenUri);
    return rewrittenUri;
  }

  /**
   * Does an HTTP request have an entity? In the Apache HttpClient world, this
   * seems to be limited to POST. The CONTENT_LENGTH header gives the length of
   * the entity body if it is known in advance; the TRANSFER_ENCODING tells you
   * whether the body is chunked and lets you figure out the length.
   * 
   * @param servletRequest the servlet request containing the headers
   * @return true if headers indicate an entity, false if not
   */
  private boolean hasEntity(HttpServletRequest servletRequest) {
    return servletRequest.getHeader(HttpHeaders.CONTENT_LENGTH) != null
           || servletRequest.getHeader(HttpHeaders.TRANSFER_ENCODING) != null;
  }

  /**
   * Get an encoded form entity or a copied entity (not a form) from a servlet
   * request.
   * 
   * @param servletRequest the servlet request containing the entity
   * @return the entity (encoded if a form)
   * @throws IOException if there is a problem streaming the entity or if the
   *           form entity character set is not supported
   */
  protected HttpEntity getEntity(HttpServletRequest servletRequest)
      throws IOException {
    HttpEntity entity = null;
    // Content length and Transfer encoding indicate request has a body.
    if (hasEntity(servletRequest)) {
      // Content type is either form or non-form
      String contentType = servletRequest.getContentType();
      if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
        entity = encodeFormEntity(servletRequest);
      } else {
        logger.debug("Creating entity by copying");
        // Copy the entity from the request body directly.
        entity =
          new InputStreamEntity(servletRequest.getInputStream(),
                                servletRequest.getContentLength());
      }
    }
    return entity;
  }

  /**
   * Encode a form entity from a servlet request.
   * 
   * @param servletRequest
   * @throws UnsupportedEncodingException
   */
  private UrlEncodedFormEntity encodeFormEntity(HttpServletRequest servletRequest)
      throws UnsupportedEncodingException {
    logger.debug("Creating encoded form entity");
    // Extract the parameter map and create a new form entity.
    Map<String, String[]> map = servletRequest.getParameterMap();
    List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
    for (String name : map.keySet()) {
      String[] array = map.get(name);
      // Use last value found
      for (int i = 0; i < array.length; i++) {
        nameValuePairs.add(new BasicNameValuePair(name, array[i]));
      }
    }
    logger.debug("Encoded " + nameValuePairs.size() + " form parameters");
    return new UrlEncodedFormEntity(nameValuePairs);
  }
}
