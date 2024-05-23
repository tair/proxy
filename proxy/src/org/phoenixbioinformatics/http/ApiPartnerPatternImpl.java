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
public class ApiPartnerPatternImpl implements IPartnerPattern {
  /** the partner pattern information from the API database */
  private ApiService.PartnerOutput partnerPattern;
  /** the source URI for the partner lookup */
  private String sourceUri;
  private String uriPath;

  private static final String API_ERROR =
    "Could not get partner information from API due to API error";
  private static final String NO_PARTNER_ERROR =
    "Could not get partner information from API";
  private static final String NO_SOURCE_URI_ERROR = "Source URI not set";

  /**
   * Create a ApiPartnerPattern object with a null source URI. You must set the
   * source URI before calling any methods on the class.
   */
  public ApiPartnerPatternImpl() {
    sourceUri = null;
  }

  /**
   * Create a ApiPartner object given a source URI.
   * 
   * @param sourceUri the URI that serves to map to a partner in the API
   *          database
   */
  public ApiPartnerPatternImpl(String sourceUri) {
    this.sourceUri = sourceUri;
  }

  /**
   * Make the API call to get the partner pattern information. If there is any
   * API problem, the method will throw an unchecked exception.
   */
  private void getPartnerPattern() {
    if (sourceUri == null) {
      throw new RuntimeException(NO_SOURCE_URI_ERROR);
    }
    if (partnerPattern == null) {
      try {
        partnerPattern = ApiService.getPartnerInfo(sourceUri, uriPath);
      } catch (Exception e) {
        throw new RuntimeException(API_ERROR, e);
      }
      if (partnerPattern == null) {
        throw new RuntimeException(NO_PARTNER_ERROR);
      }
    }
  }

  /**
   * Sets the source URI after construction, allowing you to construct the
   * implementation, then supply the source URI at a later time before calling
   * the interface methods.
   *
   * @param sourceUri the source URI to match through the API
   */
  public void setSourceUri(String sourceUri) {
    this.sourceUri = sourceUri;
  }

  public void setUriPath(String uriPath) {
    this.uriPath = uriPath;
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

  @Override
  public Boolean getAllowRedirect() {
    getPartnerPattern();
    return partnerPattern.allowRedirect;
  }

  @Override
  public Boolean getAllowCredential() {
    getPartnerPattern();
    return partnerPattern.allowCredential;
  }
}
