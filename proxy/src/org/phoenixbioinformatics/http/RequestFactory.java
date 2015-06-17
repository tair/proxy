/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;


import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.HttpUriRequest;


/**
 * A factory method class that generates an HTTP URI request of an appropriate
 * type given a servlet request, rewritten to proxy to the target server;
 * supports only the following methods:
 * <ul>
 * <li>GET</li>
 * <li>POST</li>
 * <li>PUT</li>
 * <li>DELETE</li>
 * <li>OPTIONS</li>
 * </ul>
 * 
 * @author Robert J. Muller
 */
public class RequestFactory {
  public enum HttpMethod {
    GET, PUT, POST, DELETE, OPTIONS;
  }

  /**
   * Returns the enum representation of a HttpMethod for a given string
   *
   * @param methodString      String representation of a HttpMethod
   * @return Enum representation of a HttpMethod
   */
  public static HttpMethod getMethodByString(String methodString) 
    throws UnsupportedHttpMethodException {
    
    HttpMethod method = HttpMethod.GET;
    switch (methodString) {
    case "GET":
	    method=HttpMethod.GET;
	    break;
    case "PUT":
	    method=HttpMethod.PUT;
	    break;
    case "POST":
	    method=HttpMethod.POST;
	    break;
    case "DELETE":
	    method=HttpMethod.DELETE;
	    break;
    case "OPTIONS":
	    method=HttpMethod.OPTIONS;
	    break;
    default:
	    throw new UnsupportedHttpMethodException("Unsupported HTTP method: "
                                               + method);
    }
    return method;
  }

  /**
   * Generate a rewritten HTTP URI request object based on the content of a
   * servlet request. The method handles all supported HTTP request methods.
   * 
   * @param servletRequest the HTTP servlet request containing the URI to proxy
   * @return the rewritten URI to proxy
   * @throws UnsupportedHttpMethodException
   * @throws IOException
   */
  public static HttpUriRequest getUriRequest(HttpServletRequest servletRequest, String partnerHostUri)
      throws UnsupportedHttpMethodException, IOException {
    IRequest proxyRequest = null;
    HttpMethod method = HttpMethod.valueOf(servletRequest.getMethod());

    switch (method) {
    case GET:
      proxyRequest = new GetRequest();
      break;
    case POST:
      proxyRequest = new PostRequest();
      break;
    case PUT:
      proxyRequest = new PutRequest();
      break;
    case DELETE:
      proxyRequest = new DeleteRequest();
      break;
    case OPTIONS:
      proxyRequest = new OptionsRequest();
      break;
    default:
      throw new UnsupportedHttpMethodException("Unsupported HTTP method for proxying: "
                                               + method);
    }
    return proxyRequest.getUriRequest(servletRequest, partnerHostUri);
  }
}
