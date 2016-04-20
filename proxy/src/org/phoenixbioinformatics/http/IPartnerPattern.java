/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;

/**
 * An interface that provides a way for unit tests to get partner pattern
 * information without calling the API
 * 
 * @author Robert J. Muller
 */
public interface IPartnerPattern {
  /**
   * Get the partner identifier for the partner
   *
   * @return the partner identifier, a string
   */
  String getPartnerId();

  /**
   * Get the partner's target URI, which corresponds to the source URI with
   * which the partner implementation was created.
   *
   * @return the target URI (scheme and authority)
   */
  String getTargetUri();
}
