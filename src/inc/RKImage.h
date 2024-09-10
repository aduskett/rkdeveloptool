#ifndef __RK_IMAGE_H__
#define __RK_IMAGE_H__

#include "DefineHeader.h"
#include "RKBoot.h"
#include <algorithm>
#define IMAGE_RESERVED_SIZE 61
#pragma pack(1)
typedef struct {
  unsigned int uiTag;
  unsigned short usSize;
  unsigned int dwVersion;
  unsigned int dwMergeVersion;
  STRUCT_RKTIME stReleaseTime;
  ENUM_RKDEVICE_TYPE emSupportChip;
  unsigned int dwBootOffset;
  unsigned int dwBootSize;
  unsigned int dwFWOffset;
  unsigned int dwFWSize;
  BYTE reserved[IMAGE_RESERVED_SIZE];
} STRUCT_RKIMAGE_HEAD, *PSTRUCT_RKIMAGE_HEAD;
#pragma pack()

class CRKImage {
public:
  unsigned int GetVersion();
  property<CRKImage, unsigned int, READ_ONLY> Version;
  unsigned int GetMergeVersion();
  property<CRKImage, unsigned int, READ_ONLY> MergeVersion;
  STRUCT_RKTIME GetReleaseTime();
  property<CRKImage, STRUCT_RKTIME, READ_ONLY> ReleaseTime;
  ENUM_RKDEVICE_TYPE GetSupportDevice();
  property<CRKImage, ENUM_RKDEVICE_TYPE, READ_ONLY> SupportDevice;
  ENUM_OS_TYPE GetOsType();
  property<CRKImage, ENUM_OS_TYPE, READ_ONLY> OsType;

  unsigned short GetBackupSize();
  property<CRKImage, unsigned short, READ_ONLY> BackupSize;
  unsigned int GetBootOffset();
  property<CRKImage, unsigned int, READ_ONLY> BootOffset;
  unsigned int GetBootSize();
  property<CRKImage, unsigned int, READ_ONLY> BootSize;
  unsigned int GetFWOffset();
  property<CRKImage, unsigned int, READ_ONLY> FWOffset;
  long long GetFWSize();
  property<CRKImage, long long, READ_ONLY> FWSize;
  bool GetSignFlag();
  property<CRKImage, bool, READ_ONLY> SignFlag;

  CRKBoot *m_bootObject;
  bool SaveBootFile(const std::string &filename);
  bool SaveFWFile(const std::string &filename);
  bool GetData(long long dwOffset, unsigned int dwSize, PBYTE lpBuffer);
  void GetReservedData(PBYTE &lpData, unsigned short &usSize);
  long long GetMd5Data(PBYTE &lpMd5, PBYTE &lpSignMd5);
  long long GetImageSize();
  CRKImage(std::string filename, bool &bCheck);
  ~CRKImage();

private:
  unsigned int m_version;
  unsigned int m_mergeVersion;
  STRUCT_RKTIME m_releaseTime{};
  ENUM_RKDEVICE_TYPE m_supportDevice;
  unsigned int m_bootOffset;
  unsigned int m_bootSize;
  unsigned int m_fwOffset;
  long long m_fwSize;

  BYTE m_md5[32]{};
  BYTE m_signMd5[256]{};
  BYTE m_reserved[IMAGE_RESERVED_SIZE]{};
  bool m_bSignFlag;
  long long m_signMd5Size;
  FILE *m_pFile;
  long long m_fileSize;
};

#endif /* __RK_IMAGE_H__ */