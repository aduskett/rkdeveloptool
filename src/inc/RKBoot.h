#ifndef __RK_BOOT_H__
#define __RK_BOOT_H__

#include "DefineHeader.h"
#include "Property.hpp"

#define BOOT_RESERVED_SIZE 57
#pragma pack(1)
typedef struct {
  unsigned int uiTag;
  unsigned short usSize;
  unsigned int dwVersion;
  unsigned int dwMergeVersion;
  STRUCT_RKTIME stReleaseTime;
  ENUM_RKDEVICE_TYPE emSupportChip;
  unsigned char uc471EntryCount;
  unsigned int dw471EntryOffset;
  unsigned char uc471EntrySize;
  unsigned char uc472EntryCount;
  unsigned int dw472EntryOffset;
  unsigned char uc472EntrySize;
  unsigned char ucLoaderEntryCount;
  unsigned int dwLoaderEntryOffset;
  unsigned char ucLoaderEntrySize;
  unsigned char ucSignFlag;
  unsigned char ucRc4Flag;
  unsigned char reserved[BOOT_RESERVED_SIZE];
} STRUCT_RKBOOT_HEAD, *PSTRUCT_RKBOOT_HEAD;

typedef struct {
  unsigned char ucSize;
  ENUM_RKBOOTENTRY emType;
  unsigned short szName[20];
  unsigned int dwDataOffset;
  unsigned int dwDataSize;
  unsigned int dwDataDelay;
} STRUCT_RKBOOT_ENTRY, *PSTRUCT_RKBOOT_ENTRY;

#pragma pack()
class CRKBoot {
public:
  bool GetRc4DisableFlag();
  property<CRKBoot, bool, READ_ONLY> Rc4DisableFlag;
  bool GetSignFlag();
  property<CRKBoot, bool, READ_ONLY> SignFlag;
  unsigned int GetVersion();
  property<CRKBoot, unsigned int, READ_ONLY> Version;
  unsigned int GetMergeVersion();
  property<CRKBoot, unsigned int, READ_ONLY> MergeVersion;
  STRUCT_RKTIME GetReleaseTime();
  property<CRKBoot, STRUCT_RKTIME, READ_ONLY> ReleaseTime;
  ENUM_RKDEVICE_TYPE GetSupportDevice();
  property<CRKBoot, ENUM_RKDEVICE_TYPE, READ_ONLY> SupportDevice;
  unsigned char GetEntry471Count();
  property<CRKBoot, unsigned char, READ_ONLY> Entry471Count;
  unsigned char GetEntry472Count();
  property<CRKBoot, unsigned char, READ_ONLY> Entry472Count;
  unsigned char GetEntryLoaderCount();
  property<CRKBoot, unsigned char, READ_ONLY> EntryLoaderCount;
  bool CrcCheck();
  bool SaveEntryFile(ENUM_RKBOOTENTRY type, unsigned char ucIndex,
                     const std::string &fileName);
  bool GetEntryProperty(ENUM_RKBOOTENTRY type, unsigned char ucIndex,
                        unsigned int &dwSize, unsigned int &dwDelay,
                        char *pName = nullptr);
  char GetIndexByName(ENUM_RKBOOTENTRY type, char *pName);
  bool GetEntryData(ENUM_RKBOOTENTRY type, unsigned char ucIndex, PBYTE lpData);
  CRKBoot(PBYTE lpBootData, unsigned int dwBootSize, bool &bCheck);
  ~CRKBoot();

private:
  bool m_bRc4Disable;
  bool m_bSignFlag;
  unsigned int m_version;
  unsigned int m_mergeVersion;
  STRUCT_RKTIME m_releaseTime{};
  ENUM_RKDEVICE_TYPE m_supportDevice;
  unsigned int m_471Offset;
  unsigned char m_471Size;
  unsigned char m_471Count;
  unsigned int m_472Offset;
  unsigned char m_472Size;
  unsigned char m_472Count;
  unsigned int m_loaderOffset;
  unsigned char m_loaderSize;
  unsigned char m_loaderCount;
  BYTE m_crc[4]{};
  PBYTE m_BootData;
  unsigned int m_BootSize;
  unsigned short m_BootHeadSize;

  static void WCHAR_To_wchar(const unsigned short *src, wchar_t *dst, int len);

  static void WCHAR_To_char(const unsigned short *src, char *dst, int len);
};

#endif /* __RK_BOOT_H__ */