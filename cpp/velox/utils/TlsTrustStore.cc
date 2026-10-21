/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "utils/TlsTrustStore.h"

#include <glog/logging.h>
#include <cctype>
#include <cstdlib>
#include <filesystem>

namespace gluten {

namespace {

namespace fs = std::filesystem;

// Bundles of the common distribution families, in the order they are tried.
constexpr const char* kWellKnownCaBundles[] = {
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt", // RHEL, CentOS, Rocky, Alma, Fedora
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL family, what the link above points to
    "/etc/ssl/ca-bundle.pem", // openSUSE
};

constexpr const char* kOpenSslDefaultCaFile = "/etc/ssl/cert.pem";
constexpr const char* kOpenSslDefaultCaDir = "/etc/ssl/certs";

bool isRegularFile(const std::string& path) {
  std::error_code ec;
  return fs::is_regular_file(path, ec) && !ec;
}

// OpenSSL finds certificates in a directory only through files named <8 hex digits>.<digit>, created by
// `openssl rehash`.
bool hasHashedCertificate(const std::string& dir) {
  std::error_code ec;
  fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
  if (ec) {
    return false;
  }
  for (const auto& entry : it) {
    const auto name = entry.path().filename().string();
    if (name.size() < 10 || name[8] != '.') {
      continue;
    }
    bool hex = true;
    for (size_t i = 0; i < 8; ++i) {
      hex = hex && std::isxdigit(static_cast<unsigned char>(name[i]));
    }
    bool digits = true;
    for (size_t i = 9; i < name.size(); ++i) {
      digits = digits && std::isdigit(static_cast<unsigned char>(name[i]));
    }
    if (hex && digits) {
      return true;
    }
  }
  return false;
}

} // namespace

std::optional<std::string> findFallbackCaBundle() {
  const char* certFile = std::getenv("SSL_CERT_FILE");
  const char* certDir = std::getenv("SSL_CERT_DIR");

  // OpenSSL does not fall back to its default file when SSL_CERT_FILE is set but unusable.
  const bool fileUsable = certFile != nullptr ? isRegularFile(certFile) : isRegularFile(kOpenSslDefaultCaFile);
  if (fileUsable) {
    return std::nullopt;
  }
  if (hasHashedCertificate(certDir != nullptr ? certDir : kOpenSslDefaultCaDir)) {
    return std::nullopt;
  }

  for (const char* candidate : kWellKnownCaBundles) {
    if (isRegularFile(candidate)) {
      return std::string(candidate);
    }
  }
  return std::nullopt;
}

void ensureTlsTrustStore() {
  const auto bundle = findFallbackCaBundle();
  if (!bundle.has_value()) {
    return;
  }
  const char* previous = std::getenv("SSL_CERT_FILE");
  if (previous != nullptr) {
    LOG(WARNING) << "SSL_CERT_FILE='" << previous << "' is not an existing file; using '" << bundle.value()
                 << "' instead.";
  } else {
    LOG(INFO) << "No trusted certificates found at the OpenSSL default locations; using '" << bundle.value()
              << "' as SSL_CERT_FILE.";
  }
  ::setenv("SSL_CERT_FILE", bundle->c_str(), 1);
}

} // namespace gluten
