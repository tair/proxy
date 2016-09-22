/**
 * Copyright Phoenix Bioinformatics Corporation 2016. All rights reserved.
 */
package org.phoenixbioinformatics.http;

/**
 * An interface that provides a way for unit tests to get partner
 * information without calling the API
 * 
 * @author Robert J. Muller
 */
public interface IPartner {

  /**
   * Get the partner's login URI
   *
   * @return the login URI
   */
  String getLoginUri();
  
  /**
   * Get the partner's default login redirect URI
   *
   * @return the default login redirect URI 
   */
  String getDefaultLoginRedirect();
}
