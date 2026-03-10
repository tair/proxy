package org.phoenixbioinformatics.api;


import java.io.IOException;
import java.util.List;

import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.phoenixbioinformatics.http.RequestFactory;
import org.phoenixbioinformatics.properties.ProxyProperties;


/**
 * An abstract superclass with shared implementation methods for the individual
 * API service subclasses
 */
public abstract class AbstractApiService {
  /** the URI for the Phoenix API server */
  private static final String API_URL =
    ProxyProperties.getProperty("api.uri", "https://pwapi.arabidopsis.org");
  /** the key that authenticates this server to the API */
  private static final String API_KEY = ProxyProperties.getProperty("api.key");

  /** logger for this class */
  private static final Logger logger =
    LogManager.getLogger(AbstractApiService.class);

  private static final PoolingHttpClientConnectionManager API_CONN_MANAGER =
    new PoolingHttpClientConnectionManager();
  static {
    API_CONN_MANAGER.setMaxTotal(200);
    API_CONN_MANAGER.setDefaultMaxPerRoute(50);
    API_CONN_MANAGER.setValidateAfterInactivity(5000);
  }
  private static final RequestConfig API_REQUEST_CONFIG = RequestConfig.custom()
    .setConnectTimeout(10000)
    .setSocketTimeout(30000)
    .setConnectionRequestTimeout(5000)
    .build();
  private static final CloseableHttpClient API_CLIENT = HttpClientBuilder.create()
    .setConnectionManager(API_CONN_MANAGER)
    .setDefaultRequestConfig(API_REQUEST_CONFIG)
    .build();

  /**
   * This method handles the call to API service without using cookie and a form
   * for post params
   */
  public static String callApi(String urn, RequestFactory.HttpMethod method)
      throws IOException {
    return AbstractApiService.callApi(urn, method, "", null);
  }

  /**
   * This method handles the call to API service without using a form for post
   * params
   */
  public static String callApi(String urn, RequestFactory.HttpMethod method,
                               String cookieString) throws IOException {
    return AbstractApiService.callApi(urn, method, cookieString, null);
  }

  /**
   * This method handles the actual call to API services.
   * 
   * @param urn path to the resource to be retrieved. example:
   *          (/access?partyId=5)
   * @param method request method based on RequestFactory.HttpMethod
   * @param cookieString string containing the cookie used for the request.
   * @param params form data for a POST request.
   * @return String response content string
   */
  public static String callApi(String urn, RequestFactory.HttpMethod method,
                               String cookieString, List<NameValuePair> params)
      throws IOException {
    CloseableHttpResponse response = null;
    HttpUriRequest request = null;
    String methodString = null;
    if (method == RequestFactory.HttpMethod.GET) {
      request = new HttpGet(API_URL + urn);
      methodString = "GET";
    } else if (method == RequestFactory.HttpMethod.POST) {
      request = new HttpPost(API_URL + urn);
      methodString = "POST";
      if (params != null) {
        ((HttpPost)request).setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
      }
    }

    request.addHeader("Cookie", "apiKey=" + API_KEY + ";" + cookieString);

    try {
      response = API_CLIENT.execute(request);
      int status = response.getStatusLine().getStatusCode();
      if (status != HttpStatus.SC_OK && status != HttpStatus.SC_CREATED) {
        logger.debug("Status code is not OK: " + status);
        logger.debug("API Url: " + API_URL);
        EntityUtils.consumeQuietly(response.getEntity());
        throw new IOException("Bad status code: " + String.valueOf(status));
      }
      String content = EntityUtils.toString(response.getEntity());
      return content;
    } finally {
      if (response != null) {
        response.close();
      }
    }
  }

  /**
   * Shuts down the API client and connection manager.
   * Should be called during application shutdown.
   */
  public static void shutdown() {
    try {
      API_CLIENT.close();
    } catch (IOException e) {
      logger.warn("Error closing API_CLIENT", e);
    }
  }
}
