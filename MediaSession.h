/*
 * Copyright (c) 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "Module.h"
#include <cdm.h>
#include <cdmi.h>
#ifdef USE_SVP
#include "gst_svp_meta.h"
#endif

namespace CDMi
{

const int kHttpOk = 200;
constexpr size_t kMaxFetchAttempts = 5;
void FetchCertificate(const std::string& , std::string*);
bool Fetch(const std::string& , const std::string& , std::string* , int*);

class MediaKeySession : public IMediaKeySession
{
public:
    MediaKeySession(widevine::Cdm*, int32_t);
    virtual ~MediaKeySession(void);

    virtual void Run(
        const IMediaKeySessionCallback *f_piMediaKeySessionCallback);

    void* RunThread(int i);

    virtual CDMi_RESULT Load();

    virtual void Update(
        const uint8_t *f_pbKeyMessageResponse,
        uint32_t f_cbKeyMessageResponse);

    virtual CDMi_RESULT Remove();

    virtual CDMi_RESULT Close(void);

    virtual CDMi_RESULT SetParameter(const std::string& name, const std::string& value);

    virtual const char* GetSessionId(void) const;

    virtual const char* GetKeySystem(void) const;

    CDMi_RESULT Init(
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData,
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData);

    virtual CDMi_RESULT Decrypt(
        uint8_t*                 inData,          // Incoming encrypted data
        const uint32_t           inDataLength,    // Incoming encrypted data length
        uint8_t**                outData,         // Outgoing decrypted data
        uint32_t*                outDataLength,   // Outgoing decrypted data length
        const SampleInfo*        sampleInfo,      // Information required to decrypt Sample
        const IStreamProperties* properties);

    virtual CDMi_RESULT ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque );

    // Callback Interfaces from widevine::IClientNotification
    // -------------------------------------------------------
    void onMessageUrl(const std::string& f_serverUrl) {}
    void onMessage(widevine::Cdm::MessageType f_messageType, const std::string& f_message);
    void onKeyStatusChange();
    void onRemoveComplete();
    void onDeferredComplete(widevine::Cdm::Status);
    void onDirectIndividualizationRequest(const std::string&);

private:
    void onKeyStatusError(widevine::Cdm::Status status);

private:
    widevine::Cdm *m_cdm;
    std::string m_CDMData;
    std::string m_initData;
    widevine::Cdm::InitDataType m_initDataType;
    widevine::Cdm::SessionType m_licenseType;
    std::string m_sessionId;
    IMediaKeySessionCallback *m_piCallback;
    // Stream Types
    enum StreamType {
        Unknown     = 0,
        Video       = 1,
        Audio       = 2,
        Data        = 3
    };
    StreamType m_StreamType;
    uint8_t m_IV[16];
    widevine::Cdm::Pattern pattern;
    widevine::Cdm::EncryptionScheme encryption_scheme;
#if defined(USE_SVP)
    void* m_pSVPContext;
    unsigned int m_rpcID;
    SecureBufferInfo m_stSecureBuffInfo = {0};
#endif
};

}  // namespace CDMi
