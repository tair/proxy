/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;


/**
 * A factory method object that generates an HTTP URI request for a POST method
 * request, including any enclosed entity
 * 
 * @author Robert J. Muller
 */
public class PostRequest extends AbstractRequest {

  @Override
    public HttpUriRequest getUriRequest(HttpServletRequest servletRequest, String partnerHostUri)
    throws IOException {
    // Check method for servlet request
    if (!RequestFactory.HttpMethod.valueOf(servletRequest.getMethod()).equals(RequestFactory.HttpMethod.POST)) {
      throw new RuntimeException("Wrong HTTP method for POST class: "
                                 + servletRequest.getMethod());
    }

    // Create the POST request from the rewritten servlet request URI.
    HttpPost request =
      new HttpPost(rewriteUriFromRequest(servletRequest, partnerHostUri));
    
    // Set the request entity from the entity in the servlet request.
    request.setEntity(getEntity(servletRequest));
    
    return request;
  }
}
