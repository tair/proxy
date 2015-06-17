/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpUriRequest;


/**
 * A factory method object that generates an HTTP URI request for an OPTIONS
 * method request
 * 
 * @author Robert J. Muller
 */
public class OptionsRequest extends AbstractRequest {

  @Override
    public HttpUriRequest getUriRequest(HttpServletRequest servletRequest, String partnerHostUri) {
    // Check method for servlet request
    if (!RequestFactory.HttpMethod.valueOf(servletRequest.getMethod()).equals(RequestFactory.HttpMethod.OPTIONS)) {
      throw new RuntimeException("Wrong HTTP method for OPTIONS class: "
                                 + servletRequest.getMethod());
    }

    return new HttpOptions(rewriteUriFromRequest(servletRequest, partnerHostUri));
  }
}
