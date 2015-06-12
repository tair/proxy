/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpUriRequest;


/**
 * A factory method object that generates an HTTP URI request for a DELETE
 * method request
 * 
 * @author Robert J. Muller
 */
public class DeleteRequest extends AbstractRequest {

  @Override
  public HttpUriRequest getUriRequest(HttpServletRequest servletRequest) {
    // Check method for servlet request
    if (!RequestFactory.HttpMethod.valueOf(servletRequest.getMethod()).equals(RequestFactory.HttpMethod.DELETE)) {
      throw new RuntimeException("Wrong HTTP method for DELETE class: "
                                 + servletRequest.getMethod());
    }

    return new HttpDelete(rewriteUriFromRequest(servletRequest, TARGET));
  }
}
