/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;


/**
 * A factory method object that generates an HTTP URI request for a GET method
 * request
 * 
 * @author Robert J. Muller
 */
public class GetRequest extends AbstractRequest {
  @Override
    public HttpUriRequest getUriRequest(HttpServletRequest servletRequest, String partnerHostUri) {
    // TODO: The original serveletRequest.getMethod().equals(RequestFactory.HttpMethod.GET) 
    // is incorrect; it compares a string with an integer. Will need to propagate this
    // change to other methods (POST, PUT... etc.)
    // Check method for servlet request
    if (RequestFactory.HttpMethod.valueOf(servletRequest.getMethod()) != RequestFactory.HttpMethod.GET) {
      throw new RuntimeException("Wrong HTTP method for GET class: "
                                 + servletRequest.getMethod());
    }
    
    return new HttpGet(rewriteUriFromRequest(servletRequest, partnerHostUri));
  }
}
