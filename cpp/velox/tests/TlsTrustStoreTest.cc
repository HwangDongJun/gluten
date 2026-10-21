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

#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace gluten {

namespace {

namespace fs = std::filesystem;

class TlsTrustStoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    saveEnv("SSL_CERT_FILE", savedFile_);
    saveEnv("SSL_CERT_DIR", savedDir_);
    ::unsetenv("SSL_CERT_FILE");
    ::unsetenv("SSL_CERT_DIR");
    dir_ = fs::temp_directory_path() / ("gluten_tls_trust_store_test_" + std::to_string(::getpid()));
    fs::remove_all(dir_);
    fs::create_directories(dir_);
  }

  void TearDown() override {
    restoreEnv("SSL_CERT_FILE", savedFile_);
    restoreEnv("SSL_CERT_DIR", savedDir_);
    fs::remove_all(dir_);
  }

  std::string touch(const std::string& name) {
    const auto path = dir_ / name;
    std::ofstream(path) << "x";
    return path.string();
  }

  fs::path dir_;

 private:
  static void saveEnv(const char* name, std::optional<std::string>& out) {
    const char* value = std::getenv(name);
    out = value != nullptr ? std::optional<std::string>(value) : std::nullopt;
  }

  static void restoreEnv(const char* name, const std::optional<std::string>& value) {
    if (value.has_value()) {
      ::setenv(name, value->c_str(), 1);
    } else {
      ::unsetenv(name);
    }
  }

  std::optional<std::string> savedFile_;
  std::optional<std::string> savedDir_;
};

TEST_F(TlsTrustStoreTest, existingSslCertFileIsKept) {
  ::setenv("SSL_CERT_FILE", touch("bundle.pem").c_str(), 1);
  EXPECT_EQ(findFallbackCaBundle(), std::nullopt);

  const std::string before = std::getenv("SSL_CERT_FILE");
  ensureTlsTrustStore();
  EXPECT_EQ(std::string(std::getenv("SSL_CERT_FILE")), before);
}

TEST_F(TlsTrustStoreTest, hashedCertificateDirectoryIsEnough) {
  // A missing SSL_CERT_FILE is not replaced when the hashed directory already provides certificates.
  ::setenv("SSL_CERT_FILE", (dir_ / "missing.pem").c_str(), 1);
  const auto certs = dir_ / "certs";
  fs::create_directories(certs);
  std::ofstream(certs / "0a1b2c3d.0") << "x";
  ::setenv("SSL_CERT_DIR", certs.c_str(), 1);
  EXPECT_EQ(findFallbackCaBundle(), std::nullopt);
}

TEST_F(TlsTrustStoreTest, nonHashedFilesDoNotCount) {
  // Files that OpenSSL would not pick up from a directory (not <8 hex>.<digit>) are not trusted certificates.
  ::setenv("SSL_CERT_FILE", (dir_ / "missing.pem").c_str(), 1);
  const auto certs = dir_ / "certs";
  fs::create_directories(certs);
  std::ofstream(certs / "ca-certificates.crt") << "x";
  std::ofstream(certs / "0a1b2c3z.0") << "x";
  std::ofstream(certs / "0a1b2c3d.pem") << "x";
  ::setenv("SSL_CERT_DIR", certs.c_str(), 1);

  const auto bundle = findFallbackCaBundle();
  // The result depends on the host: either one of the well-known system bundles, or nothing when the host has none
  // (or already has a usable /etc/ssl/cert.pem, which cannot be seen here because SSL_CERT_FILE is set).
  if (bundle.has_value()) {
    EXPECT_TRUE(fs::is_regular_file(bundle.value()));
  }
}

TEST_F(TlsTrustStoreTest, unusableSslCertFileIsReplacedWhenSystemBundleExists) {
  ::setenv("SSL_CERT_FILE", (dir_ / "missing.pem").c_str(), 1);
  ::setenv("SSL_CERT_DIR", (dir_ / "empty").c_str(), 1);

  const auto bundle = findFallbackCaBundle();
  ensureTlsTrustStore();
  const std::string now = std::getenv("SSL_CERT_FILE");
  if (bundle.has_value()) {
    EXPECT_EQ(now, bundle.value());
    EXPECT_TRUE(fs::is_regular_file(now));
  } else {
    // No well-known bundle on this host: the value is left untouched.
    EXPECT_EQ(now, (dir_ / "missing.pem").string());
  }
}

} // namespace

} // namespace gluten
