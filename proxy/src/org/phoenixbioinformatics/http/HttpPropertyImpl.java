/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import org.phoenixbioinformatics.properties.ProxyProperties;


/**
 * The real implementation of the IProperty interface that gets a property from
 * the proxy server property file.
 * 
 * @author Robert J. Muller
 */
public class HttpPropertyImpl implements IProperty {
  /**
   * the property name for the setting to indicate the host is preserved in the
   * HTTP request, such as by Apache mod_proxy ProxyPreserveHost
   */
  private static final String HOST_PRESERVED_PROPERTY = "host.preserved";

  @Override
  public Boolean getHostPreserved() {
    return new Boolean(ProxyProperties.getProperty(HOST_PRESERVED_PROPERTY,
                                                   "true"));
  }
}
