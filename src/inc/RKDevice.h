#ifndef __RK_DEVICE_H__
#define __RK_DEVICE_H__
#include "DefineHeader.h"
#include "RKComm.h"
#include "RKImage.h"
#include "RKLog.h"

#define SECTOR_SIZE 512
#define PAGE_SIZE 2048
#define SPARE_SIZE 16
#define CHIPINFO_LEN 16
#define IDBLOCK_TOP 50

#define CALC_UNIT(a, b) ((a > 0) ? ((a - 1) / b + 1) : (a))
#define BYTE2SECTOR(x) (CALC_UNIT(x, SECTOR_SIZE))
#define PAGEALIGN(x) (CALC_UNIT(x, 4))

#pragma pack(1)
typedef struct STRUCT_FLASH_INFO {
  char szManufacturerName[16];
  unsigned int uiFlashSize;
  unsigned short usBlockSize;
  unsigned int uiPageSize;
  unsigned int uiSectorPerBlock;
  BYTE blockState[IDBLOCK_TOP];
  unsigned int uiBlockNum;
  BYTE bECCBits;
  BYTE bAccessTime;
  BYTE bFlashCS;
  unsigned short usValidSecPerBlock;
  unsigned short usPhyBlokcPerIDB;
  unsigned int uiSecNumPerIDB;
} STRUCT_FLASH_INFO, *PSTRUCT_FLASH_INFO;

typedef struct STRUCT_FLASHINFO_CMD {
  unsigned int uiFlashSize;
  unsigned short usBlockSize;
  BYTE bPageSize;
  BYTE bECCBits;
  BYTE bAccessTime;
  BYTE bManufCode;
  BYTE bFlashCS;
  BYTE reserved[501];
} STRUCT_FLASHINFO_CMD, *PSTRUCT_FLASHINFO_CMD;
#pragma pack()

class CRKDevice {
public:
  unsigned short GetVendorID();

  void SetVendorID(unsigned short value);

  property<CRKDevice, unsigned short, READ_WRITE> VendorID;

  unsigned short GetProductID();

  void SetProductID(unsigned short value);

  property<CRKDevice, unsigned short, READ_WRITE> ProductID;

  ENUM_RKDEVICE_TYPE GetDeviceType();

  void SetDeviceType(ENUM_RKDEVICE_TYPE value);

  property<CRKDevice, ENUM_RKDEVICE_TYPE, READ_WRITE> DeviceType;

  ENUM_RKUSB_TYPE GetUsbType();

  void SetUsbType(ENUM_RKUSB_TYPE value);

  property<CRKDevice, ENUM_RKUSB_TYPE, READ_WRITE> UsbType;

  char *GetLayerName();

  void SetLayerName(char *value);

  property<CRKDevice, char *, READ_WRITE> LayerName;

  unsigned int GetLocationID();

  void SetLocationID(unsigned int value);

  property<CRKDevice, unsigned int, READ_WRITE> LocationID;

  unsigned short GetBcdUsb();

  void SetBcdUsb(unsigned short value);

  property<CRKDevice, unsigned short, READ_WRITE> BcdUsb;

  ENUM_OS_TYPE GetOsType();

  void SetOsType(ENUM_OS_TYPE value);

  property<CRKDevice, ENUM_OS_TYPE, READ_WRITE> OsType;

  CRKLog *GetLogObjectPointer();

  property<CRKDevice, CRKLog *, READ_ONLY> LogObjectPointer;

  CRKComm *GetCommObjectPointer();

  property<CRKDevice, CRKComm *, READ_ONLY> CommObjectPointer;

  void SetCallBackPointer(ProgressPromptCB value);

  property<CRKDevice, ProgressPromptCB, WRITE_ONLY> CallBackPointer;

  int DownloadBoot();

  bool TestDevice();

  bool ResetDevice();

  bool PowerOffDevice();

  bool CheckChip();

  bool GetFlashInfo();

  int EraseAllBlocks(bool force_block_erase = false);

  bool SetObject(CRKImage *pImage, CRKComm *pComm, CRKLog *pLog);

  static std::string GetLayerString(unsigned int dwLocationID);

  explicit CRKDevice(const STRUCT_RKDEVICE_DESC &device);

  ~CRKDevice();

protected:
  STRUCT_FLASH_INFO m_flashInfo{};
  PBYTE m_pFlashInfoData;
  unsigned short m_usFlashInfoDataOffset;
  unsigned short m_usFlashInfoDataLen;
  PBYTE m_chipData;
  CRKImage *m_pImage;
  CRKComm *m_pComm;
  CRKLog *m_pLog;
  ProgressPromptCB m_callBackProc;
  bool m_bEmmc;
  bool m_bDirectLba;
  bool m_bFirst4mAccess;

  int EraseEmmcBlock(unsigned char ucFlashCS, unsigned int dwPos,
                     unsigned int dwCount);

  int EraseEmmcByWriteLBA(unsigned int dwSectorPos, unsigned int dwCount);

  bool EraseEmmc();

  bool Boot_VendorRequest(unsigned int requestCode, PBYTE pBuffer,
                          unsigned int dwDataSize);

  bool ReadCapability();

private:
  unsigned short m_vid;
  unsigned short m_pid;
  ENUM_RKDEVICE_TYPE m_device;
  ENUM_OS_TYPE m_os{};
  ENUM_RKUSB_TYPE m_usb;
  unsigned int m_locationID;
  unsigned short m_bcdUsb;

protected:
  char m_layerName[32]{};
};

#endif /* __RK_DEVICE_H__ */
