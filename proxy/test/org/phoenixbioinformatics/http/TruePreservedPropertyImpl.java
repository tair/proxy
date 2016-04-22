/**
* Copyright Phoenix Bioinformatics Corporation 2015. All rights reserved.
 */
package org.phoenixbioinformatics.http;

/**
 * Implementation of the IProperty interface to set host.preserved to false in unit tests
 * @author Robert J. Muller
 */
public class TruePreservedPropertyImpl implements IProperty {
  @Override
  public Boolean getHostPreserved() {
    return Boolean.TRUE;
  }
}
