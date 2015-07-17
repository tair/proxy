package org.phoenixbioinformatics.api;

import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import java.io.IOException;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;
import org.phoenixbioinformatics.http.RequestFactory;

import org.apache.http.HttpEntity;
import org.apache.http.util.EntityUtils;

/**
 * An abstract superclass with shared implementation methods for the individual
 * API service subclasses
 */
public abstract class AbstractApiService {
  public static final String apiUrl = "https://testapi.arabidopsis.org";
  public static final String apiKey = "test123"; //test api key
  
  /** logger for this class */
  public static final Logger logger = LogManager.getLogger(AbstractApiService.class);


  public static String callApi(String urn, RequestFactory.HttpMethod method) throws IOException {
    return AbstractApiService.callApi(urn, method, "");
  }

  /**
   * This method handles the actual call to API services. 
   * @param urn                 path to the resource to be retrieved. example: (/access?partyId=5)
   * @param method              request method based on RequestFactory.HttpMethod
   * @return CloseableHttpResponse that clients can extract.
   */
  public static String callApi(String urn, RequestFactory.HttpMethod method, String cookieString) throws IOException {
    CloseableHttpResponse response = null;
    HttpUriRequest request = null;
    String methodString = null;
    if (method == RequestFactory.HttpMethod.GET) {
	    request = new HttpGet(apiUrl+urn);
      methodString = "GET";
    } else if (method == RequestFactory.HttpMethod.POST) {
      request = new HttpPost(apiUrl+urn);
      methodString = "POST";
    }

    request.addHeader("Cookie", "apiKey="+apiKey+";"+cookieString);
    CloseableHttpClient client = HttpClientBuilder.create().build();
    // debug statement. TODO: remove in final produce to reduce spam
    logger.debug("Making "+methodString+" request: "+apiUrl+urn);
    response = client.execute(request);
    
    int status = response.getStatusLine().getStatusCode();
    if (status != HttpStatus.SC_OK) {
      logger.debug("Status code is not OK: "+status);
      throw new IOException("Bad status code: "+String.valueOf(status));
    }
    String content = EntityUtils.toString(response.getEntity());
    
    return content;
  }
}

