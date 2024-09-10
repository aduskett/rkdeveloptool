/*
 * (C) Copyright 2017 Fuzhou Rockchip Electronics Co., Ltd
 * Seth Liu 2017.03.01
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#include "inc/RKComm.h"
#include "inc/Endian.h"
#include "inc/RKLog.h"

extern unsigned short CRC_CCITT(const unsigned char *p, unsigned int CalculateNumber);

CRKComm::CRKComm(CRKLog *pLog) {
  memset(&m_deviceDesc, 0, sizeof(STRUCT_RKDEVICE_DESC));
  m_log = pLog;
}

CRKComm::~CRKComm() = default;

CRKUsbComm::CRKUsbComm(const STRUCT_RKDEVICE_DESC &devDesc, CRKLog *pLog,
                       bool &bRet)
    : CRKComm(pLog) {
  bRet = InitializeUsb(devDesc);
}

CRKUsbComm::~CRKUsbComm() { UninitializeUsb(); }

bool CRKUsbComm::InitializeUsb(const STRUCT_RKDEVICE_DESC &devDesc) {
  m_pUsbHandle = nullptr;
  m_pipeBulkIn = m_pipeBulkOut = 0;
  m_interfaceNum = -1;
  if (!devDesc.pUsbHandle) {
    return false;
  }
  memcpy(&m_deviceDesc, &devDesc, sizeof(STRUCT_RKDEVICE_DESC));
  int iRet =
      libusb_open(static_cast<libusb_device *>(devDesc.pUsbHandle),
                  reinterpret_cast<libusb_device_handle **>(&m_pUsbHandle));
  if (iRet != 0) {
    if (m_log) {
      m_log->Record("Error:InitializeUsb-->open device failed,err=%d", iRet);
    }
    return false;
  }
  libusb_config_descriptor *pConfigDesc = nullptr;
  iRet = libusb_get_active_config_descriptor(
      static_cast<libusb_device *>(devDesc.pUsbHandle), &pConfigDesc);
  if (iRet != 0) {
    if (m_log) {
      m_log->Record(
          "Error:InitializeUsb-->get device config descriptor failed, err=%d",
          iRet);
    }
    return false;
  }
  for (int i = 0; i < pConfigDesc->bNumInterfaces; i++) {
    const libusb_interface *pInterface = pConfigDesc->interface + i;
    for (int j = 0; j < pInterface->num_altsetting; j++) {
      const libusb_interface_descriptor *pInterfaceDesc =
          pInterface->altsetting + j;
      if (m_deviceDesc.emUsbType == RKUSB_MSC) {
        if (pInterfaceDesc->bInterfaceClass != 8 ||
            pInterfaceDesc->bInterfaceSubClass != 6 ||
            pInterfaceDesc->bInterfaceProtocol != 0x50)
          continue;
      } else {
        if (pInterfaceDesc->bInterfaceClass != 0xff ||
            pInterfaceDesc->bInterfaceSubClass != 6 ||
            pInterfaceDesc->bInterfaceProtocol != 5)
          continue;
      }
      for (int k = 0; k < pInterfaceDesc->bNumEndpoints; k++) {
        const libusb_endpoint_descriptor *pEndpointDesc =
            pInterfaceDesc->endpoint + k;
        if ((pEndpointDesc->bEndpointAddress & 0x80) == 0) {
          if (m_pipeBulkOut == 0)
            m_pipeBulkOut = pEndpointDesc->bEndpointAddress;
        } else {
          if (m_pipeBulkIn == 0)
            m_pipeBulkIn = pEndpointDesc->bEndpointAddress;
        }
        if (m_pipeBulkIn != 0 && m_pipeBulkOut != 0) {
          // found it
          m_interfaceNum = i;
          libusb_free_config_descriptor(pConfigDesc);
          iRet = libusb_claim_interface(
              static_cast<libusb_device_handle *>(m_pUsbHandle),
              m_interfaceNum);
          if (iRet != 0) {
            if (m_log) {
              m_log->Record("Error:libusb_claim_interface failed,err=%d", iRet);
            }
            return false;
          }
          return true;
        }
      }
    }
  }
  libusb_free_config_descriptor(pConfigDesc);
  return false;
}

void CRKUsbComm::UninitializeUsb() {
  if (m_pUsbHandle) {
    libusb_close(static_cast<libusb_device_handle *>(m_pUsbHandle));
    m_pUsbHandle = nullptr;
  }
  memset(&m_deviceDesc, 0, sizeof(STRUCT_RKDEVICE_DESC));
  m_pipeBulkIn = m_pipeBulkOut = 0;
}

bool CRKUsbComm::Reset_Usb_Config(const STRUCT_RKDEVICE_DESC devDesc) {
  UninitializeUsb();
  const bool bRet = InitializeUsb(devDesc);
  return bRet;
}

bool CRKUsbComm::Reset_Usb_Device() {
  int iRet = -1;
  if (m_pUsbHandle) {
    iRet =
        libusb_reset_device(static_cast<libusb_device_handle *>(m_pUsbHandle));
  }
  return iRet == 0 ? true : false;
}

bool CRKUsbComm::RKU_Read(BYTE *lpBuffer, const unsigned int dwSize) {
  int nRead;
  const int iRet = libusb_bulk_transfer(
      static_cast<libusb_device_handle *>(m_pUsbHandle), m_pipeBulkIn, lpBuffer,
      static_cast<int>(dwSize), &nRead, CMD_TIMEOUT);
  if (iRet != 0) {
    if (m_log) {
      m_log->Record("Error:RKU_Read failed,err=%d", iRet);
    }
    return false;
  }
  if (nRead != static_cast<int>(dwSize)) {
    if (m_log) {
      m_log->Record("Error:RKU_Read failed, size=%d, read=%d", dwSize, nRead);
    }
    return false;
  }
  return true;
}

bool CRKUsbComm::RKU_Write(BYTE *lpBuffer, const unsigned int dwSize) {
  int nWrite;
  const int iRet = libusb_bulk_transfer(
      static_cast<libusb_device_handle *>(m_pUsbHandle), m_pipeBulkOut,
      lpBuffer, static_cast<int>(dwSize), &nWrite, CMD_TIMEOUT);
  if (iRet != 0) {
    if (m_log) {
      m_log->Record("Error:RKU_Write failed, err=%d", iRet);
    }
    return false;
  }
  if (nWrite != static_cast<int>(dwSize)) {
    if (m_log) {
      m_log->Record("Error:RKU_Write failed, size=%d, read=%d", dwSize, nWrite);
    }
    return false;
  }
  return true;
}

int CRKUsbComm::RandomInteger(const int low, const int high) {
  const double d =
      static_cast<double>(rand()) / (static_cast<double>(RAND_MAX) + 1);
  const int k = static_cast<int>(d * (high - low + 1));
  return low + k;
}

unsigned int CRKUsbComm::MakeCBWTag() {
  unsigned int tag = 0;

  for (int i = 0; i < 4; i++) {
    tag <<= 8;
    tag += RandomInteger(0, 0xFF);
  }
  return tag;
}

void CRKUsbComm::InitializeCBW(PCBW pCBW, USB_OPERATION_CODE code) {
  memset(pCBW, 0, sizeof(CBW));

  pCBW->dwCBWSignature = CBW_SIGN;
  pCBW->dwCBWTag = MakeCBWTag();
  pCBW->cbwcb.ucOperCode = code;

  switch (code) {
  case TEST_UNIT_READY: /* Test Unit Ready: 0 */
  case READ_FLASH_ID:   /* Read Flash ID: 1 */
  case READ_FLASH_INFO:
  case READ_CHIP_INFO:
  case READ_EFUSE:
  case READ_CAPABILITY:
    pCBW->ucCBWFlags = DIRECTION_IN;
    pCBW->ucCBWCBLength = 0x06;
    break;
  case DEVICE_RESET: /* Reset Device: 0xff */
  case ERASE_SYSTEMDISK:
  case SET_RESET_FLAG:
    pCBW->ucCBWFlags = DIRECTION_OUT;
    pCBW->ucCBWCBLength = 0x06;
    break;
  case TEST_BAD_BLOCK: /* Test Bad Block: 3 */
  case READ_SECTOR:    /* Read Pages: 4 */
  case READ_LBA:       /* Read Pages: 4 */
  case READ_SDRAM:     /* Write Pages: 15 */
  case READ_SPI_FLASH:
  case READ_NEW_EFUSE:
    pCBW->ucCBWFlags = DIRECTION_IN;
    pCBW->ucCBWCBLength = 0x0a;
    break;
  case WRITE_SECTOR: /* Write Pages: 5 */
  case WRITE_LBA:    /* Write Pages: 15 */
  case WRITE_SDRAM:  /* Write Pages: 15 */
  case EXECUTE_SDRAM:
  case ERASE_NORMAL: /* Erase Blocks: 6 */
  case ERASE_FORCE:  /* Read Spare: 11 */
  case WRITE_EFUSE:
  case WRITE_SPI_FLASH:
  case WRITE_NEW_EFUSE:
  case ERASE_LBA:
    pCBW->ucCBWFlags = DIRECTION_OUT;
    pCBW->ucCBWCBLength = 0x0a;
    break;
  default:
    break;
  }
}

bool CRKUsbComm::RKU_ClearBuffer(const CBW &cbw, CSW &csw) const {
  unsigned int dwTotalRead = 0;
  int iTryCount = 3;
  do {
    const unsigned int dwReadBytes =
        RKU_Read_EX(reinterpret_cast<BYTE *>(&csw), sizeof(CSW));

    if (UFI_CHECK_SIGN(cbw, csw)) {
      return true;
    }
    if (dwReadBytes != sizeof(CSW)) {
      iTryCount--;
      sleep(3);
    }
    dwTotalRead += dwReadBytes;
    if (dwTotalRead >= MAX_CLEAR_LEN) {
      break;
    }
  } while (iTryCount > 0);
  return false;
}

unsigned int CRKUsbComm::RKU_Read_EX(BYTE *lpBuffer, const unsigned int dwSize) const {
  int nRead;
  const int iRet = libusb_bulk_transfer(
      static_cast<libusb_device_handle *>(m_pUsbHandle), m_pipeBulkIn, lpBuffer,
      static_cast<signed int>(dwSize), &nRead, 5000);
  if (iRet != 0) {
    if (m_log) {
      m_log->Record("Error:RKU_Read_EX failed, err=%d", iRet);
    }
    return 0;
  }
  return nRead;
}

int CRKUsbComm::RKU_EraseBlock(const BYTE ucFlashCS, const unsigned int dwPos,
                               const unsigned int dwCount, BYTE ucEraseType) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_EraseBlock failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  CBW cbw;
  CSW csw;
  const unsigned short usCount = dwCount;
  if (dwCount > MAX_ERASE_BLOCKS)
    return ERR_CROSS_BORDER;

  InitializeCBW(&cbw, static_cast<USB_OPERATION_CODE>(ucEraseType));
  cbw.ucCBWLUN = ucFlashCS;
  cbw.cbwcb.dwAddress = EndianU32_LtoB(dwPos);
  cbw.cbwcb.usLength = EndianU16_LtoB(usCount);

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  if (csw.ucCSWStatus == 1)
    return ERR_FOUND_BAD_BLOCK;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_ReadChipInfo(BYTE *lpBuffer) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_ReadChipInfo failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }

  CBW cbw;
  CSW csw;

  InitializeCBW(&cbw, READ_CHIP_INFO);
  cbw.dwCBWTransferLength = 16;

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(lpBuffer, 16)) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_ReadFlashID(BYTE *lpBuffer) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_ReadChipInfo failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }

  CBW cbw;
  CSW csw;

  InitializeCBW(&cbw, READ_FLASH_ID);
  cbw.dwCBWTransferLength = 5;

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(lpBuffer, 5)) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_ReadFlashInfo(BYTE *lpBuffer, unsigned int *puiRead) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_ReadFlashInfo failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  CBW cbw;
  CSW csw;

  InitializeCBW(&cbw, READ_FLASH_INFO);
  cbw.dwCBWTransferLength = 11;

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  const unsigned int dwRead = RKU_Read_EX(lpBuffer, 512);
  if (dwRead < 11 || dwRead > 512) {
    return ERR_DEVICE_READ_FAILED;
  }
  if (puiRead) {
    *puiRead = dwRead;
  }
  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_ReadCapability(BYTE *lpBuffer) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_ReadCapability failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }

  CBW cbw;
  CSW csw;

  InitializeCBW(&cbw, READ_CAPABILITY);
  cbw.dwCBWTransferLength = 8;

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  const unsigned int dwRead = RKU_Read_EX(reinterpret_cast<BYTE *>(&csw), sizeof(CSW));
  if (dwRead != 8) {
    return ERR_DEVICE_READ_FAILED;
  }
  memcpy(lpBuffer, &csw, 8);

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_ReadLBA(const unsigned int dwPos, const unsigned int dwCount,
                            BYTE *lpBuffer, const BYTE bySubCode) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_ReadLBA failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  CBW cbw;
  CSW csw;
  constexpr unsigned short wSectorSize = 512;
  const unsigned short usSectorLen = dwCount;

  InitializeCBW(&cbw, READ_LBA);
  cbw.dwCBWTransferLength = dwCount * wSectorSize;
  cbw.cbwcb.dwAddress = EndianU32_LtoB(dwPos);
  cbw.cbwcb.usLength = EndianU16_LtoB(usSectorLen);
  cbw.cbwcb.ucReserved = bySubCode;

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }
  const unsigned int dwTotal = usSectorLen * wSectorSize;

  if (!RKU_Read(lpBuffer, dwTotal)) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  if (csw.ucCSWStatus == 1)
    return ERR_FAILED;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_ResetDevice(const BYTE bySubCode) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_ResetDevice failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }

  CBW cbw;
  CSW csw;

  InitializeCBW(&cbw, DEVICE_RESET);
  cbw.cbwcb.ucReserved = bySubCode;

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw)) {
    const bool bRet = RKU_ClearBuffer(cbw, csw);
    if (!bRet) {
      return ERR_CMD_NOT_MATCH;
    }
  }

  if (csw.ucCSWStatus == 1)
    return ERR_FAILED;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_TestDeviceReady(unsigned int *dwTotal, unsigned int *dwCurrent,
                                    BYTE bySubCode) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_TestDeviceReady failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  CBW cbw;
  CSW csw;

  InitializeCBW(&cbw, TEST_UNIT_READY);

  cbw.cbwcb.ucReserved = bySubCode;
  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw)) {
    const bool bRet = RKU_ClearBuffer(cbw, csw);
    if (!bRet) {
      return ERR_CMD_NOT_MATCH;
    }
  }

  if (dwTotal != nullptr && dwCurrent != nullptr) {
    *dwCurrent = csw.dwCBWDataResidue >> 16;
    *dwTotal = csw.dwCBWDataResidue & 0x0000FFFF;

    *dwTotal = EndianU16_BtoL(*dwTotal);
    *dwCurrent = EndianU16_BtoL(*dwCurrent);
  }
  if (csw.ucCSWStatus == 1) {
    return ERR_DEVICE_UNREADY;
  }

  return ERR_DEVICE_READY;
}

int CRKUsbComm::RKU_WriteLBA(unsigned int dwPos, unsigned int dwCount, BYTE *lpBuffer,
                             BYTE bySubCode) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_WriteLBA failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  CBW cbw;
  CSW csw;
  constexpr unsigned short wSectorSize = 512;
  const unsigned short usCount = dwCount;
  const unsigned int dwTotal = usCount * wSectorSize;

  InitializeCBW(&cbw, WRITE_LBA);
  cbw.dwCBWTransferLength = dwCount * wSectorSize;
  cbw.cbwcb.dwAddress = EndianU32_LtoB(dwPos);
  cbw.cbwcb.usLength = EndianU16_LtoB(usCount);
  cbw.cbwcb.ucReserved = bySubCode;
  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Write(lpBuffer, dwTotal)) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  if (csw.ucCSWStatus == 1)
    return ERR_FAILED;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_EraseLBA(const unsigned int dwPos, const unsigned int dwCount) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_WriteLBA failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  CBW cbw;
  CSW csw;
  const unsigned short usCount = dwCount;

  InitializeCBW(&cbw, ERASE_LBA);
  cbw.cbwcb.dwAddress = EndianU32_LtoB(dwPos);
  cbw.cbwcb.usLength = EndianU16_LtoB(usCount);

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  if (csw.ucCSWStatus == 1)
    return ERR_FAILED;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_WriteSector(const unsigned int dwPos, const unsigned int dwCount,
                                BYTE *lpBuffer) {
  if (m_deviceDesc.emUsbType != RKUSB_LOADER &&
      m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_WriteSector failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  CBW cbw;
  CSW csw;
  const unsigned short usCount = dwCount;
  if (usCount > 32)
    return ERR_CROSS_BORDER;

  constexpr unsigned short wSectorSize = 528;
  InitializeCBW(&cbw, WRITE_SECTOR);
  cbw.dwCBWTransferLength = dwCount * wSectorSize;
  cbw.cbwcb.dwAddress = EndianU32_LtoB(dwPos);
  cbw.cbwcb.usLength = EndianU16_LtoB(usCount);

  if (!RKU_Write(reinterpret_cast<BYTE *>(&cbw), sizeof(CBW))) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Write(lpBuffer, usCount * wSectorSize)) {
    return ERR_DEVICE_WRITE_FAILED;
  }

  if (!RKU_Read(reinterpret_cast<BYTE *>(&csw), sizeof(CSW))) {
    return ERR_DEVICE_READ_FAILED;
  }

  if (!UFI_CHECK_SIGN(cbw, csw))
    return ERR_CMD_NOT_MATCH;

  if (csw.ucCSWStatus == 1)
    return ERR_FAILED;

  return ERR_SUCCESS;
}

int CRKUsbComm::RKU_DeviceRequest(unsigned int dwRequest, BYTE *lpBuffer,
                                  unsigned int dwDataSize) {
  if (m_deviceDesc.emUsbType != RKUSB_MASKROM) {
    if (m_log) {
      m_log->Record("Error:RKU_DeviceRequest failed,device not support");
    }
    return ERR_DEVICE_NOT_SUPPORT;
  }
  if (dwRequest != 0x0471 && dwRequest != 0x0472) {
    if (m_log) {
      m_log->Record("Error:RKU_DeviceRequest failed,request not support");
    }
    return ERR_REQUEST_NOT_SUPPORT;
  }

  bool bSendPendPacket = false;
  const auto pData = new BYTE[dwDataSize + 5];
  memset(pData, 0, dwDataSize + 5);
  memcpy(pData, lpBuffer, dwDataSize);

  switch (dwDataSize % 4096) {
  case 4095:
    ++dwDataSize;
    break;
  case 4094:
    bSendPendPacket = true;
    break;
  case 0:
  default:
    break;
  }

  const unsigned short crcValue = CRC_CCITT(pData, dwDataSize);
  pData[dwDataSize] = (crcValue & 0xff00) >> 8;
  pData[dwDataSize + 1] = crcValue & 0x00ff;
  dwDataSize += 2;

  unsigned int dwTotalSent = 0;
  int iRet;

  while (dwTotalSent < dwDataSize) {
    const unsigned int nSendBytes =
        dwDataSize - dwTotalSent > 4096 ? 4096 : dwDataSize - dwTotalSent;
    iRet = libusb_control_transfer(
        static_cast<libusb_device_handle *>(m_pUsbHandle), 0x40, 0xC, 0,
        dwRequest, pData + dwTotalSent, nSendBytes, CMD_TIMEOUT);
    if (iRet != static_cast<int>(nSendBytes)) {
      if (m_log) {
        m_log->Record("Error:RKU_DeviceRequest-->DeviceRequest vendor=0x%x "
                      "failed, err=%d",
                      dwRequest, iRet);
      }
      delete[] pData;
      return ERR_REQUEST_FAIL;
    }
    dwTotalSent += nSendBytes;
  }

  if (bSendPendPacket) {
    BYTE ucFillByte = 0;
    iRet = libusb_control_transfer(
        static_cast<libusb_device_handle *>(m_pUsbHandle), 0x40, 0xC, 0,
        dwRequest, &ucFillByte, 1, CMD_TIMEOUT);
    if (iRet != 0) {
      if (m_log) {
        m_log->Record("Error:RKU_DeviceRequest-->DeviceRequest vendor=0x%x "
                      "failed, err=%d",
                      dwRequest, iRet);
      }
      delete[] pData;
      return ERR_REQUEST_FAIL;
    }
  }

  delete[] pData;

  return ERR_SUCCESS;
}
