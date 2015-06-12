/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;

/**
 * A checked exception indicating an attempt to proxy an unsupported HTTP method
 * 
 * @author Robert J. Muller
 */
public class UnsupportedHttpMethodException extends Exception {

  /** serial version UID for serializable class */
  private static final long serialVersionUID = 1L;

  /** the default message for the exception */
  private static final String DEFAULT_MESSAGE = "Unsupported HTTP method";

  /**
   * Create an UnsupportedHttpMethodException object with a default message.
   */
  public UnsupportedHttpMethodException() {
    super(DEFAULT_MESSAGE);
  }

  /**
   * Create an UnsupportedHttpMethodException object passing through to the
   * superclass constructor.
   */
  public UnsupportedHttpMethodException(String message,
                                        Throwable cause,
                                        boolean enableSuppression,
                                        boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  /**
   * Create an UnsupportedHttpMethodException object passing through to the
   * superclass constructor.
   */
  public UnsupportedHttpMethodException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Create an UnsupportedHttpMethodException object passing through to the
   * superclass constructor.
   */
  public UnsupportedHttpMethodException(String message) {
    super(message);
  }

  /**
   * Create an UnsupportedHttpMethodException object passing through to the
   * superclass constructor.
   */
  public UnsupportedHttpMethodException(Throwable cause) {
    super(cause);
  }
}
