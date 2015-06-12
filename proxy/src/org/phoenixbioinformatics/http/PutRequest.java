/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;


/**
 * A factory method object that generates an HTTP URI request for a PUT method
 * request, including any enclosed entity
 * 
 * @author Robert J. Muller
 */
public class PutRequest extends AbstractRequest {

  @Override
  public HttpUriRequest getUriRequest(HttpServletRequest servletRequest)
      throws IOException {
    // Check method for servlet request
    if (!RequestFactory.HttpMethod.valueOf(servletRequest.getMethod()).equals(RequestFactory.HttpMethod.PUT)) {
      throw new RuntimeException("Wrong HTTP method for PUT class: "
                                 + servletRequest.getMethod());
    }

    // Create the PUT request from the rewritten servlet request URI.
    HttpPut request =
      new HttpPut(rewriteUriFromRequest(servletRequest, TARGET));

    // Set the request entity from the entity in the servlet request.
    request.setEntity(getEntity(servletRequest));

    return request;
  }
}
