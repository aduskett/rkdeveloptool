#ifndef __RK_SCAN_H__
#define __RK_SCAN_H__
#include "DefineHeader.h"
#include "RKLog.h"

typedef struct {
  unsigned short usVid;
  unsigned short usPid;
  ENUM_RKDEVICE_TYPE emDeviceType;
} STRUCT_DEVICE_CONFIG, *PSTRUCT_DEVICE_CONFIG;

typedef std::vector<STRUCT_DEVICE_CONFIG> RKDEVICE_CONFIG_SET;
class CRKScan {
public:
  unsigned int GetMSC_TIMEOUT();
  void SetMSC_TIMEOUT(unsigned int value);
  property<CRKScan, unsigned int, READ_WRITE> MSC_TIMEOUT;

  unsigned int GetRKUSB_TIMEOUT();
  void SetRKUSB_TIMEOUT(unsigned int value);
  property<CRKScan, unsigned int, READ_WRITE> RKUSB_TIMEOUT;

  int GetDEVICE_COUNTS();
  property<CRKScan, int, READ_ONLY> DEVICE_COUNTS;

  explicit CRKScan(unsigned int uiMscTimeout = 30,
                   unsigned int uiRKusbTimeout = 20);
  void SetVidPid(unsigned short mscVid = 0, unsigned short mscPid = 0);
  void AddRockusbVidPid(unsigned short newVid, unsigned short newPid,
                        unsigned short oldVid, unsigned short oldPid);
  bool FindRockusbVidPid(ENUM_RKDEVICE_TYPE type, unsigned short &usVid,
                         unsigned short &usPid);
  int Search(unsigned int type);
  bool Wait(STRUCT_RKDEVICE_DESC &device, ENUM_RKUSB_TYPE usbType,
            unsigned short usVid = 0, unsigned short usPid = 0);
  bool MutexWaitPrepare(UINT_VECTOR &vecExistedDevice,
                        unsigned int uiOfflineDevice);
  bool MutexWait(UINT_VECTOR &vecExistedDevice, STRUCT_RKDEVICE_DESC &device,
                 ENUM_RKUSB_TYPE usbType, unsigned short usVid = 0,
                 unsigned short usPid = 0);
  int GetPos(unsigned int locationID);
  bool GetDevice(STRUCT_RKDEVICE_DESC &device, int pos);
  bool SetLogObject(CRKLog *pLog);
  ~CRKScan();

private:
  unsigned int m_waitRKusbSecond;
  unsigned int m_waitMscSecond;
  CRKLog *m_log;
  RKDEVICE_DESC_SET m_list;
  RKDEVICE_CONFIG_SET m_deviceConfigSet;
  RKDEVICE_CONFIG_SET m_deviceMscConfigSet;
  static int FindConfigSetPos(const RKDEVICE_CONFIG_SET &devConfigSet,
                              unsigned short vid, unsigned short pid);
  static int FindWaitSetPos(const RKDEVICE_CONFIG_SET &waitDeviceSet,
                            unsigned short vid, unsigned short pid);
  void EnumerateUsbDevice(RKDEVICE_DESC_SET &list,
                          unsigned int &uiTotalMatchDevices);
  static void FreeDeviceList(RKDEVICE_DESC_SET &list);
  bool IsRockusbDevice(ENUM_RKDEVICE_TYPE &type, unsigned short vid,
                       unsigned short pid);
};

#endif /* __RK_SCAN_H__ */