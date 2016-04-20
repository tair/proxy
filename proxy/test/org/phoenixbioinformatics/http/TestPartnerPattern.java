/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;

/**
 * An implementation of the IPartnerPattern interface that provides test data
 * instead of going to the API for data
 * 
 * @author Robert J. Muller
 */
public class TestPartnerPattern implements IPartnerPattern {

  /**
   * Create a TestPartnerPattern object.
   */
  public TestPartnerPattern(String sourceUri) {
  }

  @Override
  public String getPartnerId() {
    return "tair";
  }

  @Override
  public String getTargetUri() {
    return "http://back-prod.arabidopsis.org";
  }
}
