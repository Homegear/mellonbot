//
// Created by SLaufer on 19.08.20.
//

#ifndef MELLONBOT_SRC_GNUTLS_H_
#define MELLONBOT_SRC_GNUTLS_H_

#include <homegear-base/HelperFunctions/HelperFunctions.h>
#include <homegear-base/Security/SecureVector.h>
#include <homegear-base/HelperFunctions/Io.h>
#include <homegear-base/Variable.h>
#include <homegear-base/Encoding/JsonDecoder.h>
#include <homegear-base/HelperFunctions/Base64.h>

#include <iostream>
#include <mutex>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gpgme.h>

class GnuTls {
 private:
  static std::once_flag initFlag;
 public:
  struct CertificateInfo {
    std::string dn;
    std::string issuerCn;
    std::string ibsCertificateType;
    int64_t expirationTime = -1;
  };

  GnuTls();
  ~GnuTls();

  BaseLib::PVariable getDataFromDn(const std::string &dn);
  int createPrivateKeyAndCsr(const std::string &privateKeyPath, const std::string &dn, std::string &csr, unsigned int bits);
  int createPrivateKeyAndCsrInMemory(const std::string &dn, std::string &private_key, std::string &csr, unsigned int bits);
  int createCsr(const std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>> &keyFile, const std::string &dn, std::string &csr);
  std::string getDnFromCertificate(const std::string &certificatePem);
  int getInfoFromCertificateFile(const std::string &certificateFile, CertificateInfo &info);
  std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>> readKeyFile(const std::string &keyFilePath, bool &wasEncrypted);
};

#endif //MELLONBOT_SRC_GNUTLA_H_
