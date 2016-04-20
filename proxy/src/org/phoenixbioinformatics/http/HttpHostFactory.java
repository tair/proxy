/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.HttpHost;
import org.phoenixbioinformatics.properties.ProxyProperties;


/**
 * A factory method class that builds an HTTP host from a servlet request and a
 * set of options
 * 
 * @author Robert J. Muller
 */
public class HttpHostFactory {
  private final IPartnerPattern partnerPattern;
  private final String scheme;
  private final String serverName;
  private final String forwardedHost;
  private final Integer port;
  private final Boolean hostPreserved;

  /** the regular expression for parsing a scheme and authority */
  private static final Pattern URI_PATTERN =
    Pattern.compile("(\\w+)://(.*):{0,1}(\\d*)$");

  private static final int DEFAULT_PORT = 80;
  private static final int DEFAULT_SECURE_PORT = 443;

  private static final String NO_PARTNER_ERROR =
    "No partner registered with source URI ";

  /**
   * Create a HttpHostFactory object.
   * 
   * @param partnerPattern the partner-pattern interface for getting partner
   *          information
   * @param scheme the HTTP scheme
   * @param serverName the request server name ("host")
   * @param port the port accessed by the servlet request
   * @param forwardedHost the x-forwarded-for server name
   */
  public HttpHostFactory(IPartnerPattern partnerPattern,
                         IProperty property,
                         String scheme,
                         String serverName,
                         int port,
                         String forwardedHost) {
    this.partnerPattern = partnerPattern;
    this.scheme = scheme;
    this.serverName = serverName;
    this.forwardedHost = forwardedHost;
    this.port = port;
    this.hostPreserved = property.getHostPreserved();
  }

  /**
   * Get the "source" host from the servlet request data. This is the scheme and
   * authority originally directed at the proxy server. If the server has a
   * proxy front end, the method takes into account whether that proxy changes
   * the Host header or not (ProxyPreserveHost directive in Apache).
   *
   * @return an HTTP host object
   */
  public HttpHost getSourceHost() {
    String hostname;
    if (hostPreserved) {
      // Proxy preserved original host, use direct server name
      hostname = serverName;
    } else {
      // Proxy replaced host, get host from forwarded host
      hostname = forwardedHost;
    }

    int hostPort = -1;

    if (port == DEFAULT_PORT || port == DEFAULT_SECURE_PORT) {
      // set port to non-default port
      hostPort = port;
    }

    HttpHost host = new HttpHost(hostname, hostPort, scheme);

    return host;
  }

  /**
   * Get the target host URI for the factory's source URI. If there is no
   * partner corresponding to the source URI, the return will be null.
   *
   * @return a target HTTP host, or null if there is no partner for the source
   *         URI
   */
  public HttpHost getTargetHost() {
    HttpHost sourceHost = getSourceHost();
    HttpHost targetHost = null;

    if (partnerPattern != null) {
      // Parse out the elements needed to create the host.
      Matcher matcher = URI_PATTERN.matcher(partnerPattern.getTargetUri());
      if (matcher.matches()) {
        String scheme = matcher.group(1);
        String hostname = matcher.group(2);
        String portString = matcher.group(3);
        int port = -1;
        if (!portString.isEmpty()) {
          port = new Integer(portString);
        }
        targetHost = new HttpHost(hostname, port, scheme);
      }
    } else {
      throw new RuntimeException(NO_PARTNER_ERROR + sourceHost.getHostName());
    }
    return targetHost;
  }

  /**
   * Get the partner id of the partner identified by the source URI.
   *
   * @return a string partner id
   */
  public String getPartnerId() {
    String id = null;
    if (partnerPattern != null) {
      id = partnerPattern.getPartnerId();
    }
    return id;
  }

  // Unit test getters

  /**
   * Get the scheme.
   * 
   * @return a scheme
   */
  String getScheme() {
    return scheme;
  }

  /**
   * Get the serverName.
   * 
   * @return a serverName
   */
  String getServerName() {
    return serverName;
  }

  /**
   * Get the forwardedHost.
   * 
   * @return a forwardedHost
   */
  String getForwardedHost() {
    return forwardedHost;
  }

  /**
   * Get the port.
   * 
   * @return a port
   */
  Integer getPort() {
    return port;
  }

  /**
   * Get the hostPreserved.
   * 
   * @return a hostPreserved
   */
  Boolean getHostPreserved() {
    return hostPreserved;
  }
}
