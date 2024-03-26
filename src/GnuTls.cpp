//
// Created by SLaufer on 19.08.20.
//

#include "GnuTls.h"

GnuTls::GnuTls() {
  gnutls_global_init();
}

GnuTls::~GnuTls() {
  gnutls_global_deinit();
}

BaseLib::PVariable GnuTls::getDataFromDn(const std::string &dn) {
  try {
    //The DN looks like this: CN=<Base64-encoded JSON>
    std::string cn;
    auto dnParts = BaseLib::HelperFunctions::splitAll(dn, ',');
    for (auto &dnPart : dnParts) {
      auto dnPair = BaseLib::HelperFunctions::splitFirst(dnPart, '=');
      BaseLib::HelperFunctions::toLower(dnPair.first);
      if (dnPair.first == "cn") {
        BaseLib::Base64::decode(dnPair.second, cn);
        break;
      }
    }

    if (!cn.empty()) return BaseLib::Rpc::JsonDecoder::decode(cn);
  }
  catch (const std::exception &ex) {
  }
  return BaseLib::PVariable();
}

int GnuTls::createPrivateKeyAndCsr(const std::string &privateKeyPath, const std::string &dn, std::string &csr, unsigned int bits) {
  csr.clear();

  gnutls_x509_privkey_t key;
  gnutls_x509_privkey_init(&key);
  if (gnutls_x509_privkey_generate(key, GNUTLS_PK_ECDSA, bits, 0) != GNUTLS_E_SUCCESS) {
    gnutls_x509_privkey_deinit(key);
    std::cerr << "Error generating private key." << std::endl;
    return -1;
  }
  std::array<char, 16384> buffer{};
  size_t bufferSize = buffer.size();
  if (gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_PEM, buffer.data(), &bufferSize) != GNUTLS_E_SUCCESS) {
    gnutls_x509_privkey_deinit(key);
    std::cerr << "Could not export private key." << std::endl;
    return -1;
  }

  if (bufferSize > buffer.size()) bufferSize = buffer.size();
  std::string privateKey;
  privateKey.reserve(bufferSize + 1);
  privateKey.insert(privateKey.end(), buffer.begin(), buffer.begin() + bufferSize);
  if (privateKey.back() != '\0') privateKey.push_back('\0');
  BaseLib::Io::writeFile(privateKeyPath, privateKey);
  std::fill(buffer.begin(), buffer.end(), 0);
  std::fill(privateKey.begin(), privateKey.end(), 0);

  gnutls_x509_crq_t crq;
  gnutls_x509_crq_init(&crq);
  const char *errorPosition = nullptr;
  if (gnutls_x509_crq_set_dn(crq, dn.data(), &errorPosition) != GNUTLS_E_SUCCESS) {
    gnutls_x509_crq_deinit(crq);
    gnutls_x509_privkey_deinit(key);
    std::cerr << "Error setting DN of certificate." << std::endl;
    return -1;
  }
  gnutls_x509_crq_set_version(crq, 1);
  gnutls_x509_crq_set_key(crq, key);
  gnutls_x509_crq_sign2(crq, key, GNUTLS_DIG_SHA512, 0);
  bufferSize = buffer.size();
  gnutls_x509_crq_export(crq, GNUTLS_X509_FMT_PEM, buffer.data(), &bufferSize);
  csr = std::string(buffer.begin(), buffer.begin() + bufferSize);

  gnutls_x509_crq_deinit(crq);
  gnutls_x509_privkey_deinit(key);

  return 0;
}

int GnuTls::createPrivateKeyAndCsrInMemory(const std::string &dn, std::string &private_key, std::string &csr, unsigned int bits) {
  csr.clear();

  gnutls_x509_privkey_t key;
  gnutls_x509_privkey_init(&key);
  if (gnutls_x509_privkey_generate(key, GNUTLS_PK_ECDSA, bits, 0) != GNUTLS_E_SUCCESS) {
    gnutls_x509_privkey_deinit(key);
    std::cerr << "Error generating private key." << std::endl;
    return -1;
  }
  std::array<char, 16384> buffer{};
  size_t bufferSize = buffer.size();
  if (gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_PEM, buffer.data(), &bufferSize) != GNUTLS_E_SUCCESS) {
    gnutls_x509_privkey_deinit(key);
    std::cerr << "Could not export private key." << std::endl;
    return -1;
  }

  if (bufferSize > buffer.size()) bufferSize = buffer.size();
  private_key.reserve(bufferSize + 1);
  private_key.insert(private_key.end(), buffer.begin(), buffer.begin() + bufferSize);
  std::fill(buffer.begin(), buffer.end(), 0);

  gnutls_x509_crq_t crq;
  gnutls_x509_crq_init(&crq);
  const char *errorPosition = nullptr;
  if (gnutls_x509_crq_set_dn(crq, dn.data(), &errorPosition) != GNUTLS_E_SUCCESS) {
    gnutls_x509_crq_deinit(crq);
    gnutls_x509_privkey_deinit(key);
    std::cerr << "Error setting DN of certificate." << std::endl;
    return -1;
  }
  gnutls_x509_crq_set_version(crq, 1);
  gnutls_x509_crq_set_key(crq, key);
  gnutls_x509_crq_sign2(crq, key, GNUTLS_DIG_SHA512, 0);
  bufferSize = buffer.size();
  gnutls_x509_crq_export(crq, GNUTLS_X509_FMT_PEM, buffer.data(), &bufferSize);
  csr = std::string(buffer.begin(), buffer.begin() + bufferSize);

  gnutls_x509_crq_deinit(crq);
  gnutls_x509_privkey_deinit(key);

  return 0;
}

int GnuTls::createCsr(const std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>> &keyFile, const std::string &dn, std::string &csr) {
  if (!keyFile) return -1;

  gnutls_x509_privkey_t key;
  gnutls_x509_privkey_init(&key);
  gnutls_datum_t data;
  data.data = (unsigned char *) keyFile->data();
  data.size = keyFile->size();
  if (gnutls_x509_privkey_import2(key, &data, GNUTLS_X509_FMT_PEM, nullptr, 0) != GNUTLS_E_SUCCESS) {
    std::cerr << "Error importing private key" << std::endl;
    return -1;
  }
  data.data = nullptr;
  data.size = 0;

  gnutls_x509_crq_t crq;
  gnutls_x509_crq_init(&crq);

  const char *errorPosition = nullptr;
  if (gnutls_x509_crq_set_dn(crq, dn.data(), &errorPosition) != GNUTLS_E_SUCCESS) {
    gnutls_x509_privkey_deinit(key);
    std::cerr << "Error setting DN of certificate" << std::endl;
    return -1;
  }
  gnutls_x509_crq_set_version(crq, 1);
  gnutls_x509_crq_set_key(crq, key);
  gnutls_x509_crq_sign2(crq, key, GNUTLS_DIG_SHA512, 0);
  std::array<char, 16384> buffer{};
  size_t bufferSize = buffer.size();
  gnutls_x509_crq_export(crq, GNUTLS_X509_FMT_PEM, buffer.data(), &bufferSize);
  csr = std::string(buffer.begin(), buffer.begin() + bufferSize);

  gnutls_x509_crq_deinit(crq);
  gnutls_x509_privkey_deinit(key);

  return 0;
}

std::string GnuTls::getDnFromCertificate(const std::string &certificatePem) {
  gnutls_datum_t data;
  data.data = (unsigned char *) certificatePem.data();
  data.size = certificatePem.size();

  gnutls_x509_crt_t certificate;
  gnutls_x509_crt_init(&certificate);
  if (gnutls_x509_crt_import(certificate, &data, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
    std::cerr << "Error importing certificate (2)." << std::endl;
    exit(1);
  }
  std::array<char, 16384> buffer{};
  size_t bufferSize = buffer.size();
  if (gnutls_x509_crt_get_dn(certificate, buffer.data(), &bufferSize) != GNUTLS_E_SUCCESS) {
    gnutls_x509_crt_deinit(certificate);
    std::cerr << "Error reading DN of certificate." << std::endl;
    exit(1);
  }

  auto dn = std::string(buffer.begin(), buffer.begin() + bufferSize);
  gnutls_x509_crt_deinit(certificate);
  return dn;
}

int GnuTls::getInfoFromCertificateFile(const std::string &certificateFile, CertificateInfo &info) {
  info.dn.clear();
  info.issuerCn.clear();
  info.ibsCertificateType.clear();
  info.expirationTime = -1;

  gnutls_datum_t data;

  gnutls_x509_crt_t certificate;
  if (gnutls_load_file(certificateFile.c_str(), &data) != GNUTLS_E_SUCCESS) {
    std::cerr << certificateFile << ": Error loading certificate" << std::endl;
    gnutls_x509_crt_deinit(certificate);
    return -1;
  }
  gnutls_x509_crt_init(&certificate);
  if (gnutls_x509_crt_import(certificate, &data, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
    std::cerr << certificateFile << ": Error importing certificate" << std::endl;
    gnutls_x509_crt_deinit(certificate);
    return -1;
  }
  gnutls_free(data.data);

  std::array<char, 16384> buffer{};
  size_t bufferSize = buffer.size();
  if (gnutls_x509_crt_get_dn(certificate, buffer.data(), &bufferSize) != GNUTLS_E_SUCCESS) {
    std::cerr << certificateFile << ": Error reading DN of certificate" << std::endl;
    gnutls_x509_crt_deinit(certificate);
    return -1;
  }
  info.dn = std::string(buffer.begin(), buffer.begin() + bufferSize);
  auto signedInfo = getDataFromDn(info.dn);
  if (signedInfo) {
    auto typeIterator = signedInfo->structValue->find("type");
    if (typeIterator != signedInfo->structValue->end()) {
      info.ibsCertificateType = typeIterator->second->stringValue;
    }
  }

  bufferSize = buffer.size();
  if (gnutls_x509_crt_get_issuer_dn_by_oid(certificate, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buffer.data(), &bufferSize) != GNUTLS_E_SUCCESS) {
    std::cerr << certificateFile << ": Error reading issuer DN of certificate" << std::endl;
    gnutls_x509_crt_deinit(certificate);
    return -1;
  }
  info.issuerCn = std::string(buffer.begin(), buffer.begin() + bufferSize);
  info.expirationTime = gnutls_x509_crt_get_expiration_time(certificate);
  gnutls_x509_crt_deinit(certificate);

  return 0;
}

std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>> GnuTls::readKeyFile(const std::string &keyFilePath, bool &wasEncrypted) {
  wasEncrypted = false;

  auto keyFileContent = BaseLib::Io::getFileContent(keyFilePath);
  if (keyFileContent.compare(0, sizeof("-----BEGIN PGP MESSAGE-----") - 1, "-----BEGIN PGP MESSAGE-----") == 0) {
    if (!gpgme_check_version(nullptr)) {
      std::cerr << "GPG is not available." << std::endl;
      return std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>>();
    }

    gpgme_ctx_t gpgContext = nullptr;
    auto result = gpgme_new(&gpgContext);
    if (result != GPG_ERR_NO_ERROR) {
      std::cerr << "Could not create GPG context." << std::endl;
      return std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>>();
    }
    gpgme_data_t gpgCipher = nullptr;
    result = gpgme_data_new_from_mem(&gpgCipher, keyFileContent.data(), keyFileContent.size(), 1);
    std::fill(keyFileContent.begin(), keyFileContent.end(), 0);
    keyFileContent.clear();
    if (result != GPG_ERR_NO_ERROR) {
      std::cerr << "Could not create GPG data." << std::endl;
      gpgme_release(gpgContext);
      return std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>>();
    }
    gpgme_data_t gpgPlain = nullptr;
    result = gpgme_data_new(&gpgPlain);
    if (result != GPG_ERR_NO_ERROR) {
      std::cerr << "Could not create GPG data." << std::endl;
      gpgme_data_release(gpgCipher);
      gpgme_release(gpgContext);
      return std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>>();
    }

    result = gpgme_op_decrypt(gpgContext, gpgCipher, gpgPlain);
    if (result != GPG_ERR_NO_ERROR) {
      std::cerr << "Could not decrypt private key." << std::endl;
      gpgme_data_release(gpgCipher);
      gpgme_data_release(gpgPlain);
      gpgme_release(gpgContext);
      return std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>>();
    }

    std::shared_ptr<BaseLib::Security::SecureVector<uint8_t>> privateKey;
    std::array<char, 16384> buffer{};
    size_t bufferSize = buffer.size();
    gpgme_data_seek(gpgPlain, 0, SEEK_SET);
    bufferSize = gpgme_data_read(gpgPlain, buffer.data(), buffer.size());
    if (bufferSize > buffer.size()) bufferSize = buffer.size();
    if (bufferSize > 0) {
      privateKey = std::make_shared<BaseLib::Security::SecureVector<uint8_t>>(buffer.begin(), buffer.begin() + bufferSize);
      if (privateKey->back() != 0) privateKey->secureResize(privateKey->size() + 1, 0);
      std::fill(buffer.begin(), buffer.end(), 0);
      wasEncrypted = true;
    }

    gpgme_data_release(gpgCipher);
    gpgme_data_release(gpgPlain);
    gpgme_release(gpgContext);

    return privateKey;
  } else {
    auto result = std::make_shared<BaseLib::Security::SecureVector<uint8_t>>(keyFileContent.begin(), keyFileContent.end());
    std::fill(keyFileContent.begin(), keyFileContent.end(), 0);
    return result;
  }
}
