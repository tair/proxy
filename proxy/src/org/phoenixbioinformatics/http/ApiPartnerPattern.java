/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import org.phoenixbioinformatics.api.ApiService;


/**
 * An implementation of the IPartnerPattern interface that accesses the Phoenix
 * API to get partner pattern information; the implementation retrieves the
 * partner ID and the target URI and keeps it in a data member for access.
 * 
 * @author Robert J. Muller
 */
public class ApiPartnerPattern implements IPartnerPattern {
  private static final String NO_SOURCE_URI_ERROR = "Source URI not set";
  /** the partner pattern information from the API database */
  private ApiService.PartnerOutput partnerPattern;
  private String sourceUri;

  public ApiPartnerPattern() {
  }
  
  /**
   * Create a ApiPartner object given a source URI.
   * 
   * @param sourceUri the URI that serves to map to a partner in the API
   *          database
   */
  public ApiPartnerPattern(String sourceUri) {
    this.sourceUri = sourceUri;
  }

  /**
   * Make the API call to get the partner pattern information.
   */
  private void getPartnerPattern() {
    if (sourceUri == null) {
      throw new RuntimeException(NO_SOURCE_URI_ERROR);
    }
    if (partnerPattern == null) {
      partnerPattern = ApiService.getPartnerInfo(sourceUri);
    }
    if (partnerPattern == null) {
      throw new RuntimeException("Could not get partner information from API");
    }
  }

  public void setSourceUri(String sourceUri) {
    this.sourceUri = sourceUri;
  }

  @Override
  public String getPartnerId() {
    getPartnerPattern();
    return partnerPattern.partnerId;
  }

  @Override
  public String getTargetUri() {
    getPartnerPattern();
    return partnerPattern.targetUri;
  }

}
