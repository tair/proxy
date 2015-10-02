/**
 * Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.proxy;

/**
 * The program encountered a problem with partner identification or handling
 * 
 * @author Robert J. Muller
 */
public class InvalidPartnerException extends Exception {

  /** serial version UI */
  private static final long serialVersionUID = 1L;

  private static final String DEFAULT = "Invalid partner";

  /**
   * Create a InvalidPartnerException object.
   */
  public InvalidPartnerException() {
    super(DEFAULT);
  }

  /**
   * Create an InvalidPartnerException object.
   * 
   * @param message the message for the error condition
   */
  public InvalidPartnerException(String message) {
    super(message);
  }

  /**
   * Create am InvalidPartnerException object.
   * 
   * @param cause the causing exception
   */
  public InvalidPartnerException(Throwable cause) {
    super(DEFAULT, cause);
  }

  /**
   * Create an InvalidPartnerException object.
   * 
   * @param message the message for the error condition
   * @param cause the causing exception
   */
  public InvalidPartnerException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Create an InvalidPartnerException object.
   * 
   * @param message the message for the error condition
   * @param cause the causing exception
   * @param enableSuppression enables suppression
   * @param writableStackTrace produce a writable stack trace
   */
  public InvalidPartnerException(String message,
                                 Throwable cause,
                                 boolean enableSuppression,
                                 boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
