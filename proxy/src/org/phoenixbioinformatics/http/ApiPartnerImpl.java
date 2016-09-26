/**
 * Copyright Phoenix Bioinformatics Corporation 2016. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import org.phoenixbioinformatics.api.ApiService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * An implementation of the IPartner interface that accesses the Phoenix
 * API to get partner information; the implementation retrieves the
 * partner login URI and the default login redirect URI and keeps it in a data member for access.
 * 
 * @author Qian Li
 */
public class ApiPartnerImpl implements IPartner {
	
	private static final Logger logger = LogManager.getLogger(ApiPartnerImpl.class);
  /** the partner information from the API database */
  private ApiService.PartnerDetailOutput partner;
  /** the source URI for the partner lookup */
  private String partnerId;

  private static final String API_ERROR =
    "Could not get partner information from API due to API error";
  private static final String NO_PARTNER_ERROR =
    "Could not get partner information from API";
  private static final String NO_PARTNER_ID_ERROR = "PartnerId not set";

  /**
   * Create a ApiPartner object with a null partnerId. You must set the
   * partnerId before calling any methods on the class.
   */
  public ApiPartnerImpl() {
    partnerId = null;
  }

  /**
   * Create a ApiPartner object given a partnerId.
   * 
   * @param partnerId that serves to map to a partner in the API
   *          database
   */
  public ApiPartnerImpl(String partnerId) {
    this.partnerId = partnerId;
  }

  /**
   * Make the API call to get the partner information. If there is any
   * API problem, the method will throw an unchecked exception.
   */
  private void getPartner() {
    if (partnerId == null) {
      throw new RuntimeException(NO_PARTNER_ID_ERROR);
    }
    if (partner == null) {
      try {
        partner = ApiService.getPartnerDetailInfo(partnerId);
      } catch (Exception e) {
        throw new RuntimeException(API_ERROR, e);
      }
      if (partner == null) {
        throw new RuntimeException(NO_PARTNER_ERROR);
      }
    }
  }

  /**
   * Sets the partnerId after construction, allowing you to construct the
   * implementation, then supply the partnerId at a later time before calling
   * the interface methods.
   *
   * @param partnerId the partnerId to match through the API
   */
  public void setPartnerId(String partnerId) {
    this.partnerId = partnerId;
  }

  @Override
  public String getLoginUri() {
    getPartner();
    logger.debug("get loginUri from partner: "+partner.loginUri);
    return partner.loginUri;
  }

  @Override
  public String getDefaultLoginRedirect() {
    getPartner();
    logger.debug("get defaultLoginRedirect from partner: "+partner.defaultLoginRedirect);
    return partner.defaultLoginRedirect;
  }
  
  @Override
  public String getUiUri() {
    getPartner();
    logger.debug("get uiUri from partner: "+partner.uiUri);
    return partner.uiUri;
  }
  
  @Override
  public String getUiMeterUri() {
    getPartner();
    logger.debug("get uiMeterUri from partner: "+partner.uiMeterUri);
    return partner.uiMeterUri;
  }
}
