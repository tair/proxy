package org.phoenixbioinformatics.http;


import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpUriRequest;


/**
 * An API interface for proxy request implementation objects that represent
 * a factory for HttpUriRequest objects to proxy to a target server
 * 
 * @author Robert J. Muller
 */
public interface IRequest {

  /**
   * Get the HTTP URI request object based on details in the servlet request.
   * 
   * @param servletRequest the HTTP servlet request containing the request
   *          details
   * @return an HTTP URI request suitable for proxying
   * @throws IOException when there is a problem streaming an entity or the
   *           entity character set is not a supported character set
   */
  HttpUriRequest getUriRequest(HttpServletRequest servletRequest, String partnerHostUri)
      throws IOException;
}
