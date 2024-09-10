/*
 * (C) Copyright 2017 Fuzhou Rockchip Electronics Co., Ltd
 * Seth Liu 2017.03.01
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include "inc/RKBoot.h"

extern unsigned int CRC_32(PBYTE pData, unsigned int ulSize);

bool CRKBoot::GetRc4DisableFlag() { return m_bRc4Disable; }

bool CRKBoot::GetSignFlag() { return m_bSignFlag; }

unsigned int CRKBoot::GetVersion() { return m_version; }

unsigned int CRKBoot::GetMergeVersion() { return m_mergeVersion; }

STRUCT_RKTIME CRKBoot::GetReleaseTime() { return m_releaseTime; }

ENUM_RKDEVICE_TYPE CRKBoot::GetSupportDevice() { return m_supportDevice; }

unsigned char CRKBoot::GetEntry471Count() { return m_471Count; }

unsigned char CRKBoot::GetEntry472Count() { return m_472Count; }

unsigned char CRKBoot::GetEntryLoaderCount() { return m_loaderCount; }

bool CRKBoot::CrcCheck() {
  const unsigned int *pOldCrc = reinterpret_cast<unsigned int *>(m_BootData + (m_BootSize - 4));
  const unsigned int ulNewCrc = CRC_32(m_BootData, m_BootSize - 4);
  return *pOldCrc == ulNewCrc;
}

bool CRKBoot::SaveEntryFile(ENUM_RKBOOTENTRY type, unsigned char ucIndex,
                            const std::string &fileName) {
  unsigned int dwOffset;
  unsigned char ucCount, ucSize;
  switch (type) {
  case ENTRY471:
    dwOffset = m_471Offset;
    ucCount = m_471Count;
    ucSize = m_471Size;
    break;
  case ENTRY472:
    dwOffset = m_472Offset;
    ucCount = m_472Count;
    ucSize = m_472Size;
    break;
  case ENTRYLOADER:
    dwOffset = m_loaderOffset;
    ucCount = m_loaderCount;
    ucSize = m_loaderSize;
    break;
  default:
    return false;
  }
  if (ucIndex >= ucCount) {
    return false;
  }
  const auto pEntry = reinterpret_cast<PSTRUCT_RKBOOT_ENTRY>(
      m_BootData + dwOffset + ucSize * ucIndex);
  auto *file = fopen(fileName.c_str(), "wb+");
  if (!file) {
    return false;
  }
  fwrite(m_BootData + pEntry->dwDataOffset, 1, pEntry->dwDataSize, file);
  fclose(file);
  return true;
}

bool CRKBoot::GetEntryProperty(ENUM_RKBOOTENTRY type, unsigned char ucIndex,
                               unsigned int &dwSize, unsigned int &dwDelay, char *pName) {
  unsigned int dwOffset;
  unsigned char ucCount, ucSize;
  switch (type) {
  case ENTRY471:
    dwOffset = m_471Offset;
    ucCount = m_471Count;
    ucSize = m_471Size;
    break;
  case ENTRY472:
    dwOffset = m_472Offset;
    ucCount = m_472Count;
    ucSize = m_472Size;
    break;
  case ENTRYLOADER:
    dwOffset = m_loaderOffset;
    ucCount = m_loaderCount;
    ucSize = m_loaderSize; // Loader��������ʱ�Ѿ�512����
    break;
  default:
    return false;
  }
  if (ucIndex >= ucCount) {
    return false;
  }
  const auto pEntry = reinterpret_cast<PSTRUCT_RKBOOT_ENTRY>(
      m_BootData + dwOffset + ucSize * ucIndex);
  dwDelay = pEntry->dwDataDelay;
  dwSize = pEntry->dwDataSize;
  if (pName) {
    WCHAR_To_char(pEntry->szName, pName, 20);
  }
  return true;
}

bool CRKBoot::GetEntryData(ENUM_RKBOOTENTRY type, unsigned char ucIndex, PBYTE lpData) {
  unsigned int dwOffset;
  unsigned char ucCount, ucSize;
  switch (type) {
  case ENTRY471:
    dwOffset = m_471Offset;
    ucCount = m_471Count;
    ucSize = m_471Size;
    break;
  case ENTRY472:
    dwOffset = m_472Offset;
    ucCount = m_472Count;
    ucSize = m_472Size;
    break;
  case ENTRYLOADER:
    dwOffset = m_loaderOffset;
    ucCount = m_loaderCount;
    ucSize = m_loaderSize;
    break;
  default:
    return false;
  }
  if (ucIndex >= ucCount) {
    return false;
  }
  PSTRUCT_RKBOOT_ENTRY pEntry;
  pEntry = (PSTRUCT_RKBOOT_ENTRY)(m_BootData + dwOffset + ucSize * ucIndex);
  memcpy(lpData, m_BootData + pEntry->dwDataOffset, pEntry->dwDataSize);
  return true;
}

char CRKBoot::GetIndexByName(ENUM_RKBOOTENTRY type, char *pName) {
  unsigned int dwOffset;
  unsigned char ucCount, ucSize;
  switch (type) {
  case ENTRY471:
    dwOffset = m_471Offset;
    ucCount = m_471Count;
    ucSize = m_471Size;
    break;
  case ENTRY472:
    dwOffset = m_472Offset;
    ucCount = m_472Count;
    ucSize = m_472Size;
    break;
  case ENTRYLOADER:
    dwOffset = m_loaderOffset;
    ucCount = m_loaderCount;
    ucSize = m_loaderSize;
    break;
  default:
    return -1;
  }

  for (unsigned char i = 0; i < ucCount; i++) {
    const auto pEntry = reinterpret_cast<PSTRUCT_RKBOOT_ENTRY>(
        m_BootData + dwOffset + ucSize * i);

    char szName[20];
    WCHAR_To_char(pEntry->szName, szName, 20);

    if (strcasecmp(pName, szName) == 0) {
      return static_cast<signed char>(i);
    }
  }
  return -1;
}

CRKBoot::~CRKBoot() { delete[] m_BootData; }

CRKBoot::CRKBoot(PBYTE lpBootData, const unsigned int dwBootSize, bool &bCheck) {
  Rc4DisableFlag.setContainer(this);
  Rc4DisableFlag.getter(&CRKBoot::GetRc4DisableFlag);
  SignFlag.setContainer(this);
  SignFlag.getter(&CRKBoot::GetSignFlag);
  Version.setContainer(this);
  Version.getter(&CRKBoot::GetVersion);
  MergeVersion.setContainer(this);
  MergeVersion.getter(&CRKBoot::GetMergeVersion);
  ReleaseTime.setContainer(this);
  ReleaseTime.getter(&CRKBoot::GetReleaseTime);
  SupportDevice.setContainer(this);
  SupportDevice.getter(&CRKBoot::GetSupportDevice);
  Entry471Count.setContainer(this);
  Entry471Count.getter(&CRKBoot::GetEntry471Count);
  Entry472Count.setContainer(this);
  Entry472Count.getter(&CRKBoot::GetEntry472Count);
  EntryLoaderCount.setContainer(this);
  EntryLoaderCount.getter(&CRKBoot::GetEntryLoaderCount);
  bCheck = true;
  if (lpBootData != nullptr) {
    m_BootData = lpBootData;
    m_BootSize = dwBootSize;
    bCheck = CrcCheck();
    if (!bCheck) {
      return;
    }
    auto pBootHead = reinterpret_cast<PSTRUCT_RKBOOT_HEAD>(m_BootData);
    if (pBootHead->uiTag != 0x544F4F42 && pBootHead->uiTag != 0x2052444C) {
      bCheck = false;
      return;
    }
    if (pBootHead->ucRc4Flag) {
      m_bRc4Disable = true;
    } else {
      m_bRc4Disable = false;
    }
    if (pBootHead->ucSignFlag == 'S') {
      m_bSignFlag = true;
    } else {
      m_bSignFlag = false;
    }
    m_version = pBootHead->dwVersion;
    m_mergeVersion = pBootHead->dwMergeVersion;
    m_BootHeadSize = pBootHead->usSize;
    m_releaseTime.usYear = pBootHead->stReleaseTime.usYear;
    m_releaseTime.ucMonth = pBootHead->stReleaseTime.ucMonth;
    m_releaseTime.ucDay = pBootHead->stReleaseTime.ucDay;
    m_releaseTime.ucHour = pBootHead->stReleaseTime.ucHour;
    m_releaseTime.ucMinute = pBootHead->stReleaseTime.ucMinute;
    m_releaseTime.ucSecond = pBootHead->stReleaseTime.ucSecond;
    m_supportDevice = pBootHead->emSupportChip;

    m_471Offset = pBootHead->dw471EntryOffset;
    m_471Count = pBootHead->uc471EntryCount;
    m_471Size = pBootHead->uc471EntrySize;

    m_472Offset = pBootHead->dw472EntryOffset;
    m_472Count = pBootHead->uc472EntryCount;
    m_472Size = pBootHead->uc472EntrySize;

    m_loaderOffset = pBootHead->dwLoaderEntryOffset;
    m_loaderCount = pBootHead->ucLoaderEntryCount;
    m_loaderSize = pBootHead->ucLoaderEntrySize;

    memcpy(m_crc, m_BootData + (m_BootSize - 4), 4);
  } else {
    bCheck = false;
    m_BootData = nullptr;
  }
}

void CRKBoot::WCHAR_To_wchar(const unsigned short *src, wchar_t *dst, const int len) {
  memset(dst, 0, len * sizeof(wchar_t));
  for (int i = 0; i < len; i++) {
    memcpy(dst, src, 2);
    src++;
    dst++;
  }
}

void CRKBoot::WCHAR_To_char(const unsigned short *src, char *dst, const int len) {
  memset(dst, 0, len * sizeof(char));
  for (int i = 0; i < len; i++) {
    memcpy(dst, src, 1);
		src++;
		dst++;
	}
}

