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

  /**
   * Get whether the partner's site allows redirect, which corresponds to the source URI 
   * with which the partner implementation was created.
   *
   * @return the boolean for whether the domain allow redirect
   */
  Boolean getAllowRedirect();

  /**
   * Get whether the partner's site allows other site to set credential/cookie for it, applicable
   * for APIs
   *
   * @return the boolean for whether the domain allow set credential
   */
  Boolean getAllowCredential();

   /**
   * Get whether the partner's site allows metering using the bucket system instead of IP-based subscriptions
   *
   * @return the boolean for whether the bucket system is allowed
   */
  Boolean getAllowBucket();
}
