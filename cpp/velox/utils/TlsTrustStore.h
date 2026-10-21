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

#pragma once

#include <optional>
#include <string>

namespace gluten {

/// The native HTTP clients (libcurl + OpenSSL, statically linked) no longer compile in a CA bundle path and look for
/// trusted certificates at runtime, in this order: the file named by SSL_CERT_FILE (or /etc/ssl/cert.pem when it is not
/// set), plus the hashed certificate directory named by SSL_CERT_DIR (or /etc/ssl/certs). Some distributions provide
/// neither (e.g. RHEL 8 family, which keeps its bundle under /etc/pki), which makes every TLS handshake fail.
///
/// Returns the path of a well-known system CA bundle that should be used through SSL_CERT_FILE, or std::nullopt when
/// nothing needs to be done: either OpenSSL already finds trusted certificates, or no well-known bundle exists.
std::optional<std::string> findFallbackCaBundle();

/// Calls findFallbackCaBundle() and, if it returns a path, exports it as SSL_CERT_FILE. A user-provided SSL_CERT_FILE
/// that points to an existing file is never changed.
void ensureTlsTrustStore();

} // namespace gluten
