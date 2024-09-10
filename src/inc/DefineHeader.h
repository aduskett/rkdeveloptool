#ifndef __DEFINE_H__
#define __DEFINE_H__

#include <cstring>
#include <dirent.h>
#include <libusb.h>
#include <list>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

typedef unsigned char BYTE, *PBYTE;

#define ALIGN(x, a) __ALIGN_MASK((x), (a)-1)
#define __ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define RK28_SEC2_RESERVED_LEN 473
#define CHIPINFO_LEN 16
#define RK28_SEC3_RESERVED_LEN 382
#define RKDEVICE_SN_LEN 60
#define RKDEVICE_UID_LEN 30
#define RKDEVICE_MAC_LEN 6
#define RKDEVICE_WIFI_LEN 6
#define RKDEVICE_BT_LEN 6
#define RKDEVICE_IMEI_LEN 15
typedef enum {
  RKNONE_DEVICE = 0,
  RK27_DEVICE = 0x10,
  RKCAYMAN_DEVICE,
  RK28_DEVICE = 0x20,
  RK281X_DEVICE,
  RKPANDA_DEVICE,
  RKNANO_DEVICE = 0x30,
  RKSMART_DEVICE,
  RKCROWN_DEVICE = 0x40,
  RK29_DEVICE = 0x50,
  RK292X_DEVICE,
  RK30_DEVICE = 0x60,
  RK30B_DEVICE,
  RK31_DEVICE = 0x70,
  RK32_DEVICE = 0x80
} ENUM_RKDEVICE_TYPE;
typedef enum { RK_OS = 0, ANDROID_OS = 0x1 } ENUM_OS_TYPE;

typedef enum {
  RKUSB_NONE = 0x0,
  RKUSB_MASKROM = 0x01,
  RKUSB_LOADER = 0x02,
  RKUSB_MSC = 0x04
} ENUM_RKUSB_TYPE;
typedef enum { ENTRY471 = 1, ENTRY472 = 2, ENTRYLOADER = 4 } ENUM_RKBOOTENTRY;

#pragma pack(1)
typedef struct sparse_header_t {
  unsigned int magic; /* 0xed26ff3a */
  unsigned short
      major_version; /* (0x1) - reject images with higher major versions */
  unsigned short
      minor_version; /* (0x0) - allow images with higer minor versions */
  unsigned short
      file_hdr_sz; /* 28 bytes for first revision of the file format */
  unsigned short
      chunk_hdr_sz;    /* 12 bytes for first revision of the file format */
  unsigned int blk_sz; /* block size in bytes, must be a multiple of 4 (4096) */
  unsigned int total_blks;     /* total blocks in the non-sparse output image */
  unsigned int total_chunks;   /* total chunks in the sparse input image */
  unsigned int image_checksum; /* CRC32 checksum of the original data, counting
                          "don't care" */
  /* as 0. Standard 802.3 polynomial, use a Public Domain */
  /* table implementation */
} sparse_header;
#define SPARSE_HEADER_MAGIC 0xed26ff3a
#define UBI_HEADER_MAGIC 0x23494255
#define CHUNK_TYPE_RAW 0xCAC1
#define CHUNK_TYPE_FILL 0xCAC2
#define CHUNK_TYPE_DONT_CARE 0xCAC3
#define CHUNK_TYPE_CRC32 0xCAC4
typedef struct chunk_header_t {
  unsigned short
      chunk_type; /* 0xCAC1 -> raw; 0xCAC2 -> fill; 0xCAC3 -> don't care */
  unsigned short reserved1;
  unsigned int chunk_sz; /* in blocks in output image */
  unsigned int
      total_sz; /* in bytes of chunk input file including chunk header and data
                 */
} chunk_header;

typedef struct {
  unsigned short usYear;
  BYTE ucMonth;
  BYTE ucDay;
  BYTE ucHour;
  BYTE ucMinute;
  BYTE ucSecond;
} STRUCT_RKTIME, *PSTRUCT_RKTIME;

typedef struct {
  char szItemName[20];
  char szItemValue[256];
} STRUCT_CONFIG_ITEM, *PSTRUCT_CONFIG_ITEM;
typedef struct {
  char szItemName[64];
  unsigned int uiItemOffset;
  unsigned int uiItemSize;
} STRUCT_PARAM_ITEM, *PSTRUCT_PARAM_ITEM;
typedef struct _STRUCT_RKDEVICE_DESC {
  unsigned short usVid;
  unsigned short usPid;
  unsigned short usbcdUsb;
  unsigned int uiLocationID;
  ENUM_RKUSB_TYPE emUsbType;
  ENUM_RKDEVICE_TYPE emDeviceType;
  void *pUsbHandle;
} STRUCT_RKDEVICE_DESC, *PSTRUCT_RKDEVICE_DESC;
typedef struct {
  unsigned int dwTag;
  BYTE reserved[4];
  unsigned int uiRc4Flag;
  unsigned short usBootCode1Offset;
  unsigned short usBootCode2Offset;
  BYTE reserved1[490];
  unsigned short usBootDataSize;
  unsigned short usBootCodeSize;
  unsigned short usCrc;
} RK28_IDB_SEC0, *PRK28_IDB_SEC0;

typedef struct {
  unsigned short usSysReservedBlock;
  unsigned short usDisk0Size;
  unsigned short usDisk1Size;
  unsigned short usDisk2Size;
  unsigned short usDisk3Size;
  unsigned int uiChipTag;
  unsigned int uiMachineId;
  unsigned short usLoaderYear;
  unsigned short usLoaderDate;
  unsigned short usLoaderVer;
  unsigned short usLastLoaderVer;
  unsigned short usReadWriteTimes;
  unsigned int dwFwVer;
  unsigned short usMachineInfoLen;
  unsigned char ucMachineInfo[30];
  unsigned short usManufactoryInfoLen;
  unsigned char ucManufactoryInfo[30];
  unsigned short usFlashInfoOffset;
  unsigned short usFlashInfoLen;
  unsigned char reserved[384];
  unsigned int uiFlashSize;
  BYTE reserved1;
  BYTE bAccessTime;
  unsigned short usBlockSize;
  BYTE bPageSize;
  BYTE bECCBits;
  BYTE reserved2[8];
  unsigned short usIdBlock0;
  unsigned short usIdBlock1;
  unsigned short usIdBlock2;
  unsigned short usIdBlock3;
  unsigned short usIdBlock4;
} RK28_IDB_SEC1, *PRK28_IDB_SEC1;

typedef struct {
  unsigned short usInfoSize;
  BYTE bChipInfo[CHIPINFO_LEN];
  BYTE reserved[RK28_SEC2_RESERVED_LEN];
  char szVcTag[3];
  unsigned short usSec0Crc;
  unsigned short usSec1Crc;
  unsigned int uiBootCodeCrc;
  unsigned short usSec3CustomDataOffset;
  unsigned short usSec3CustomDataSize;
  char szCrcTag[4];
  unsigned short usSec3Crc;
} RK28_IDB_SEC2, *PRK28_IDB_SEC2;

typedef struct {
  unsigned short usSNSize;
  BYTE sn[RKDEVICE_SN_LEN];
  BYTE reserved[RK28_SEC3_RESERVED_LEN];
  BYTE wifiSize;
  BYTE wifiAddr[RKDEVICE_WIFI_LEN];
  BYTE imeiSize;
  BYTE imei[RKDEVICE_IMEI_LEN];
  BYTE uidSize;
  BYTE uid[RKDEVICE_UID_LEN];
  BYTE blueToothSize;
  BYTE blueToothAddr[RKDEVICE_BT_LEN];
  BYTE macSize;
  BYTE macAddr[RKDEVICE_MAC_LEN];
} RK28_IDB_SEC3, *PRK28_IDB_SEC3;
#pragma pack()
typedef std::list<STRUCT_RKDEVICE_DESC> RKDEVICE_DESC_SET;
typedef RKDEVICE_DESC_SET::iterator device_list_iter;
typedef std::vector<std::string> STRING_VECTOR;
typedef std::vector<unsigned int> UINT_VECTOR;
typedef std::vector<STRUCT_CONFIG_ITEM> CONFIG_ITEM_VECTOR;
typedef std::vector<STRUCT_PARAM_ITEM> PARAM_ITEM_VECTOR;
typedef enum {
  TESTDEVICE_PROGRESS,
  DOWNLOADIMAGE_PROGRESS,
  CHECKIMAGE_PROGRESS,
  TAGBADBLOCK_PROGRESS,
  TESTBLOCK_PROGRESS,
  ERASEFLASH_PROGRESS,
  ERASESYSTEM_PROGRESS,
  LOWERFORMAT_PROGRESS,
  ERASEUSERDATA_PROGRESS
} ENUM_PROGRESS_PROMPT;

typedef enum { CALL_FIRST, CALL_MIDDLE, CALL_LAST } ENUM_CALL_STEP;

typedef void (*ProgressPromptCB)(unsigned int deviceLayer,
                                 ENUM_PROGRESS_PROMPT promptID,
                                 long long totalValue, long long currentValue,
                                 ENUM_CALL_STEP emCall);

//	bool WideStringToString(unsigned short_t *pszSrc, char *&pszDest);
//	bool StringToWideString(char *pszSrc, unsigned short_t *&pszDest);
#endif /* __DEFINE_H__ */
