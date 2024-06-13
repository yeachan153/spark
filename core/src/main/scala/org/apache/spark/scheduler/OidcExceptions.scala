package org.apache.spark.scheduler

class TokenFetchException(message: String) extends Exception(message) {}

class DeviceAuthorizationException(message: String) extends Exception(message) {}

class InvalidRefreshTokenException(message: String) extends Exception(message) {}
