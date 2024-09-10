/*
 * (C) Copyright 2017 Fuzhou Rockchip Electronics Co., Ltd
 * Seth Liu 2017.03.01
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <dirent.h>
#include <iomanip>
#include <iostream>
#include <unistd.h>

#include "config.h"
#include "inc/DefineHeader.h"
#include "inc/RKComm.h"
#include "inc/RKDevice.h"
#include "inc/RKImage.h"
#include "inc/RKLog.h"
#include "inc/RKScan.h"
#include "inc/boot_merger.h"
#include "inc/gpt.h"

extern const char *szManufName[];
CRKLog *g_pLogObject = nullptr;
CONFIG_ITEM_VECTOR g_ConfigItemVec;
#define DEFAULT_RW_LBA 128
#define CURSOR_MOVEUP_LINE(n) printf("%c[%dA", 0x1B, n)
#define CURSOR_DEL_LINE printf("%c[2K", 0x1B)
#define CURSOR_MOVE_HOME printf("%c[H", 0x1B)
#define CURSOR_CLEAR_SCREEN printf("%c[2J", 0x1B)
#define ERROR_COLOR_ATTR printf("%c[30;41m", 0x1B);
#define NORMAL_COLOR_ATTR printf("%c[0m", 0x1B);

extern unsigned int CRC_32(unsigned char *pData, unsigned int ulSize);

extern unsigned short CRC_16(const unsigned char *aData, unsigned int aSize);

extern void P_RC4(unsigned char *buf, unsigned short len);

extern unsigned int crc32_le(unsigned int crc, unsigned char *p,
                             unsigned int len);

void usage() {
  printf("\r\n---------------------Tool Usage ---------------------\r\n");
  printf("Help:\t\t\t-h or --help\r\n");
  printf("Version:\t\t-v or --version\r\n");
  printf("ListDevice:\t\tld\r\n");
  printf("DownloadBoot:\t\tdb <Loader>\r\n");
  printf("UpgradeLoader:\t\tul <Loader>\r\n");
  printf("ReadLBA:\t\trl  <BeginSec> <SectorLen> <File>\r\n");
  printf("WriteLBA:\t\twl  <BeginSec> <File>\r\n");
  printf("WriteLBA:\t\twlx  <PartitionName> <File>\r\n");
  printf("WriteGPT:\t\tgpt <gpt partition table>\r\n");
  printf("WriteParameter:\t\tprm <parameter>\r\n");
  printf("PrintPartition:\t\tppt \r\n");
  printf("EraseFlash:\t\tef \r\n");
  printf("TestDevice:\t\ttd\r\n");
  printf("ResetDevice:\t\trd [subcode]\r\n");
  printf("ReadFlashID:\t\trid\r\n");
  printf("ReadFlashInfo:\t\trfi\r\n");
  printf("ReadChipInfo:\t\trci\r\n");
  printf("ReadCapability:\t\trcb\r\n");
  printf("PackBootLoader:\t\tpack\r\n");
  printf("UnpackBootLoader:\tunpack <boot loader>\r\n");
  printf("TagSPL:\t\t\ttagspl <tag> <U-Boot SPL>\r\n");
  printf("-------------------------------------------------------\r\n\r\n");
}

void ProgressInfoProc(unsigned int deviceLayer, ENUM_PROGRESS_PROMPT promptID,
                      long long totalValue, long long currentValue,
                      ENUM_CALL_STEP emCall) {
  std::string strInfoText;
  char szText[256];
  switch (promptID) {
  case TESTDEVICE_PROGRESS:
    sprintf(szText, "Test Device total %lld, current %lld", totalValue,
            currentValue);
    strInfoText = szText;
    break;
  case LOWERFORMAT_PROGRESS:
    sprintf(szText, "Lowerformat Device total %lld, current %lld", totalValue,
            currentValue);
    strInfoText = szText;
    break;
  case DOWNLOADIMAGE_PROGRESS:
    sprintf(szText, "Download Image total %lldK, current %lldK",
            totalValue / 1024, currentValue / 1024);
    strInfoText = szText;
    break;
  case CHECKIMAGE_PROGRESS:
    sprintf(szText, "Check Image total %lldK, current %lldK", totalValue / 1024,
            currentValue / 1024);
    strInfoText = szText;
    break;
  case TAGBADBLOCK_PROGRESS:
    sprintf(szText, "Tag Bad Block total %lld, current %lld", totalValue,
            currentValue);
    strInfoText = szText;
    break;
  case TESTBLOCK_PROGRESS:
    sprintf(szText, "Test Block total %lld, current %lld", totalValue,
            currentValue);
    strInfoText = szText;
    break;
  case ERASEFLASH_PROGRESS:
    sprintf(szText, "Erase Flash total %lld, current %lld", totalValue,
            currentValue);
    strInfoText = szText;
    break;
  case ERASESYSTEM_PROGRESS:
    sprintf(szText, "Erase System partition total %lld, current %lld",
            totalValue, currentValue);
    strInfoText = szText;
    break;
  case ERASEUSERDATA_PROGRESS:
    sprintf(szText,
            "<LocationID=%x> Erase Userdata partition total %lld, current %lld",
            deviceLayer, totalValue, currentValue);
    strInfoText = szText;
    break;
  }
  if (!strInfoText.empty()) {
    CURSOR_MOVEUP_LINE(1);
    CURSOR_DEL_LINE;
    std::cout << strInfoText << std::endl;
  }
  if (emCall == CALL_LAST)
    deviceLayer = 0;
}

void PrintData(PBYTE pData, int nSize) {
  char szPrint[17] = "\0";
  int i;
  for (i = 0; i < nSize; i++) {
    if (i % 16 == 0) {
      if (i / 16 > 0) {
        printf("     %s\r\n", szPrint);
      }
      printf("%08d ", i / 16);
    }
    printf("%02X ", pData[i]);
    szPrint[i % 16] = isprint(pData[i]) ? pData[i] : '.';
  }
  if (i / 16 > 0) {
    printf("     %s\r\n", szPrint);
  }
}

int find_config_item(CONFIG_ITEM_VECTOR &vecItems, const char *pszName) {
  for (auto i = 0; i < vecItems.size(); i++) {
    if (strcasecmp(pszName, vecItems[i].szItemName) == 0) {
      return i;
    }
  }
  return -1;
}

void string_to_uuid(const std::string &strUUid, char *uuid) {
  memset(uuid, 0, 16);
  for (unsigned int i = 0; i < strUUid.size(); i++) {
    int value = 0;
    if (strUUid[i] >= '0' && strUUid[i] <= '9')
      value = strUUid[i] - '0';
    if (strUUid[i] >= 'a' && strUUid[i] <= 'f')
      value = strUUid[i] - 'a' + 10;
    if (strUUid[i] >= 'A' && strUUid[i] <= 'F')
      value = strUUid[i] - 'A' + 10;
    if (i % 2 == 0)
      uuid[i / 2] += static_cast<char>(value << 4);
    else
      uuid[i / 2] += static_cast<char>(value);
  }
  auto *p32 = reinterpret_cast<unsigned int *>(uuid);
  *p32 = cpu_to_be32(*p32);
  auto *p16 = reinterpret_cast<unsigned short *>(uuid + 4);
  *p16 = cpu_to_be16(*p16);
  p16 = reinterpret_cast<unsigned short *>(uuid + 6);
  *p16 = cpu_to_be16(*p16);
}

bool parse_config(const char *pConfig, CONFIG_ITEM_VECTOR &vecItem) {
  std::stringstream configStream(pConfig);
  std::string strLine, strItemName, strItemValue;
  vecItem.clear();
  while (!configStream.eof()) {
    getline(configStream, strLine);
    const std::string::size_type line_size = strLine.size();
    if (line_size == 0) {
      continue;
    }
    if (strLine[line_size - 1] == '\r') {
      strLine = strLine.substr(0, line_size - 1);
    }
    strLine.erase(0, strLine.find_first_not_of(' '));
    strLine.erase(strLine.find_last_not_of(' ') + 1);
    if (strLine.empty()) {
      continue;
    }
    if (strLine[0] == '#') {
      continue;
    }
    const std::string::size_type pos = strLine.find('=');
    if (pos == std::string::npos) {
      continue;
    }
    strItemName = strLine.substr(0, pos);
    strItemValue = strLine.substr(pos + 1);
    strItemName.erase(0, strItemName.find_first_not_of(' '));
    strItemName.erase(strItemName.find_last_not_of(' ') + 1);
    strItemValue.erase(0, strItemValue.find_first_not_of(' '));
    strItemValue.erase(strItemValue.find_last_not_of(' ') + 1);
    if (!strItemName.empty() && !strItemValue.empty()) {
      STRUCT_CONFIG_ITEM item;
      strcpy(item.szItemName, strItemName.c_str());
      strcpy(item.szItemValue, strItemValue.c_str());
      vecItem.push_back(item);
    }
  }
  return true;
}

bool parse_config_file(const char *pConfigFile, CONFIG_ITEM_VECTOR &vecItem) {
  FILE *file = nullptr;
  file = fopen(pConfigFile, "rb");
  if (!file) {
    if (g_pLogObject) {
      g_pLogObject->Record("%s failed, err=%d, can't open file: %s\r\n",
                           __func__, errno, pConfigFile);
    }
    return false;
  }
  fseek(file, 0, SEEK_END);
  const auto iFileSize = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *pConfigBuf = nullptr;
  pConfigBuf = new char[iFileSize + 1];
  if (!pConfigBuf) {
    fclose(file);
    return false;
  }
  memset(pConfigBuf, 0, iFileSize + 1);
  const auto iRead = fread(pConfigBuf, 1, iFileSize, file);
  if (iRead != iFileSize) {
    if (g_pLogObject)
      g_pLogObject->Record("%s failed, err=%d, read=%d, total=%d\r\n", __func__,
                           errno, iRead, iFileSize);
    fclose(file);
    delete[] pConfigBuf;
    return false;
  }
  fclose(file);
  const bool bRet = parse_config(pConfigBuf, vecItem);
  delete[] pConfigBuf;
  return bRet;
}

bool ParsePartitionInfo(std::string &strPartInfo, std::string &strName, unsigned int &uiOffset,
                        unsigned int &uiLen) {
  std::string::size_type pos;
  std::string strOffset, strLen;
  int iCount;
  std::string::size_type prevPos = pos = 0;
  if (strPartInfo.empty()) {
    return false;
  }
  pos = strPartInfo.find('@');
  if (pos == std::string::npos) {
    return false;
  }
  strLen = strPartInfo.substr(prevPos, pos - prevPos);
  strLen.erase(0, strLen.find_first_not_of(' '));
  strLen.erase(strLen.find_last_not_of(' ') + 1);
  if (strchr(strLen.c_str(), '-')) {
    uiLen = 0xFFFFFFFF;
  } else {
    iCount = sscanf(strLen.c_str(), "0x%x", &uiLen);
    if (iCount != 1) {
      return false;
    }
  }

  prevPos = pos + 1;
  pos = strPartInfo.find('(', prevPos);
  if (pos == std::string::npos) {
    return false;
  }
  strOffset = strPartInfo.substr(prevPos, pos - prevPos);
  strOffset.erase(0, strOffset.find_first_not_of(' '));
  strOffset.erase(strOffset.find_last_not_of(' ') + 1);
  iCount = sscanf(strOffset.c_str(), "0x%x", &uiOffset);
  if (iCount != 1) {
    return false;
  }
  prevPos = pos + 1;
  pos = strPartInfo.find(')', prevPos);
  if (pos == std::string::npos) {
    return false;
  }
  strName = strPartInfo.substr(prevPos, pos - prevPos);
  strName.erase(0, strName.find_first_not_of(' '));
  strName.erase(strName.find_last_not_of(' ') + 1);

  return true;
}

bool ParseUuidInfo(std::string &strUuidInfo, std::string &strName, std::string &strUUid) {
  std::string::size_type pos(0);

  if (strUuidInfo.empty()) {
    return false;
  }
  pos = strUuidInfo.find('=');
  if (pos == std::string::npos) {
    return false;
  }
  strName = strUuidInfo.substr(0, pos);
  strName.erase(0, strName.find_first_not_of(' '));
  strName.erase(strName.find_last_not_of(' ') + 1);

  strUUid = strUuidInfo.substr(pos + 1);
  strUUid.erase(0, strUUid.find_first_not_of(' '));
  strUUid.erase(strUUid.find_last_not_of(' ') + 1);

  while (true) {
    pos = 0;
    if ((pos = strUUid.find('-')) != std::string::npos)
      strUUid.replace(pos, 1, "");
    else
      break;
  }
  if (strUUid.size() != 32)
    return false;
  return true;
}

bool parse_parameter(const char *pParameter, PARAM_ITEM_VECTOR &vecItem,
                     CONFIG_ITEM_VECTOR &vecUuidItem) {
  std::stringstream paramStream(pParameter);
  bool bRet, bFind = false;
  std::string strLine, strPartition, strPartInfo, strPartName, strUUid;
  std::string::size_type line_size, pos, posColon, posComma;
  unsigned int uiPartOffset, uiPartSize;
  vecItem.clear();
  vecUuidItem.clear();
  while (!paramStream.eof()) {
    STRUCT_PARAM_ITEM item;
    getline(paramStream, strLine);
    line_size = strLine.size();
    if (line_size == 0)
      continue;
    if (strLine[line_size - 1] == '\r') {
      strLine = strLine.substr(0, line_size - 1);
    }
    strLine.erase(0, strLine.find_first_not_of(' '));
    strLine.erase(strLine.find_last_not_of(' ') + 1);
    if (strLine.empty())
      continue;
    if (strLine[0] == '#')
      continue;
    pos = strLine.find("uuid:");
    if (pos != std::string::npos) {
      strPartInfo = strLine.substr(pos + 5);
      bRet = ParseUuidInfo(strPartInfo, strPartName, strUUid);
      if (bRet) {
        STRUCT_CONFIG_ITEM uuid_item;
        strcpy(uuid_item.szItemName, strPartName.c_str());
        string_to_uuid(strUUid, uuid_item.szItemValue);
        vecUuidItem.push_back(uuid_item);
      }
      continue;
    }

    pos = strLine.find("mtdparts");
    if (pos == std::string::npos) {
      continue;
    }
    bFind = true;
    posColon = strLine.find(':', pos);
    if (posColon == std::string::npos) {
      continue;
    }
    strPartition = strLine.substr(posColon + 1);
    pos = 0;
    posComma = strPartition.find(',', pos);
    while (posComma != std::string::npos) {
      strPartInfo = strPartition.substr(pos, posComma - pos);
      bRet = ParsePartitionInfo(strPartInfo, strPartName, uiPartOffset,
                                uiPartSize);
      if (bRet) {
        strcpy(item.szItemName, strPartName.c_str());
        item.uiItemOffset = uiPartOffset;
        item.uiItemSize = uiPartSize;
        vecItem.push_back(item);
      }
      pos = posComma + 1;
      posComma = strPartition.find(',', pos);
    }
    strPartInfo = strPartition.substr(pos);
    if (!strPartInfo.empty()) {
      bRet = ParsePartitionInfo(strPartInfo, strPartName, uiPartOffset,
                                uiPartSize);
      if (bRet) {
        strcpy(item.szItemName, strPartName.c_str());
        item.uiItemOffset = uiPartOffset;
        item.uiItemSize = uiPartSize;
        vecItem.push_back(item);
      }
    }
  }
  return bFind;
}

bool parse_parameter_file(char *pParamFile, PARAM_ITEM_VECTOR &vecItem,
                          CONFIG_ITEM_VECTOR &vecUuidItem) {
  FILE *file = nullptr;
  file = fopen(pParamFile, "rb");
  if (!file) {
    if (g_pLogObject)
      g_pLogObject->Record("%s failed, err=%d, can't open file: %s\r\n",
                           __func__, errno, pParamFile);
    return false;
  }
  fseek(file, 0, SEEK_END);
  const auto iFileSize = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *pParamBuf = nullptr;
  pParamBuf = new char[iFileSize];
  if (!pParamBuf) {
    fclose(file);
    return false;
  }
  if (const auto iRead = fread(pParamBuf, 1, iFileSize, file);
      iRead != iFileSize) {
    if (g_pLogObject)
      g_pLogObject->Record("%s failed, err=%d, read=%d, total=%d\r\n", __func__,
                           errno, iRead, iFileSize);
    fclose(file);
    delete[] pParamBuf;
    return false;
  }
  fclose(file);
  auto bRet = parse_parameter(pParamBuf, vecItem, vecUuidItem);
  delete[] pParamBuf;
  return bRet;
}

bool is_sparse_image(char *szImage) {
  FILE *file = nullptr;
  sparse_header head;
  file = fopen(szImage, "rb");
  if (!file) {
    if (g_pLogObject)
      g_pLogObject->Record("%s failed, err=%d, can't open file: %s\r\n",
                           __func__, errno, szImage);
    return false;
  }
  if (const u32 uiRead = fread(&head, 1, sizeof(head), file);
      uiRead != sizeof(head)) {
    if (g_pLogObject)
      g_pLogObject->Record("%s failed, err=%d, read=%d, total=%d\r\n", __func__,
                           errno, uiRead, sizeof(head));
    fclose(file);
    return false;
  }
  fclose(file);
  if (head.magic != SPARSE_HEADER_MAGIC) {
    return false;
  }
  return true;
}

bool is_ubifs_image(char *szImage) {
  FILE *file = nullptr;
  u32 magic;
  file = fopen(szImage, "rb");
  if (!file) {
    if (g_pLogObject) {
      g_pLogObject->Record("%s failed, err=%d, can't open file: %s\r\n",
                           __func__, errno, szImage);
    }
    return false;
  }
  if (const u32 uiRead = fread(&magic, 1, sizeof(magic), file);
      uiRead != sizeof(magic)) {
    if (g_pLogObject) {
      g_pLogObject->Record("%s failed, err=%d, read=%d, total=%d\r\n", __func__,
                           errno, uiRead, sizeof(magic));
    }
    fclose(file);
    return false;
  }
  fclose(file);
  if (magic != UBI_HEADER_MAGIC) {
    return false;
  }
  return true;
}

void gen_rand_uuid(unsigned char *uuid_bin) {
  efi_guid_t id;
  auto *ptr = reinterpret_cast<unsigned int *>(&id);

  /* Set all fields randomly */
  for (unsigned int i = 0; i < sizeof(id) / sizeof(*ptr); i++)
    *(ptr + i) = cpu_to_be32(rand());

  id.uuid.time_hi_and_version = (id.uuid.time_hi_and_version & 0x0FFF) | 0x4000;
  id.uuid.clock_seq_hi_and_reserved = id.uuid.clock_seq_hi_and_reserved | 0x80;

  memcpy(uuid_bin, id.raw, sizeof(id));
}

void prepare_gpt_backup(u8 *master, u8 *backup) {
  auto *gptMasterHead = reinterpret_cast<gpt_header *>(master + SECTOR_SIZE);
  auto *gptBackupHead =
      reinterpret_cast<gpt_header *>(backup + 32 * SECTOR_SIZE);

  /* recalculate the values for the Backup GPT Header */
  const auto val = le64_to_cpu(gptMasterHead->my_lba);
  gptBackupHead->my_lba = gptMasterHead->alternate_lba;
  gptBackupHead->alternate_lba = cpu_to_le64(val);
  gptBackupHead->partition_entry_lba =
      cpu_to_le64(le64_to_cpu(gptMasterHead->last_usable_lba) + 1);
  gptBackupHead->header_crc32 = 0;

  u32 calc_crc32 = crc32_le(0, reinterpret_cast<unsigned char *>(gptBackupHead),
                            le32_to_cpu(gptBackupHead->header_size));
  gptBackupHead->header_crc32 = cpu_to_le32(calc_crc32);
}

bool get_lba_from_gpt(u8 *master, const char *pszName, u64 *lba, u64 *lba_end) {
  auto *gptMasterHead = reinterpret_cast<gpt_header *>(master + SECTOR_SIZE);
  const gpt_entry *gptEntry = nullptr;
  u32 j;
  u8 zerobuf[GPT_ENTRY_SIZE];
  bool bFound = false;
  memset(zerobuf, 0, GPT_ENTRY_SIZE);

  for (auto i = 0; i < le32_to_cpu(gptMasterHead->num_partition_entries); i++) {
    gptEntry = reinterpret_cast<gpt_entry *>(master + 2 * SECTOR_SIZE +
                                             i * GPT_ENTRY_SIZE);
    if (memcmp(zerobuf, gptEntry, GPT_ENTRY_SIZE) == 0) {
      break;
    }
    for (j = 0; j < strlen(pszName); j++) {
      if (gptEntry->partition_name[j] != pszName[j]) {
        break;
      }
    }
    if (gptEntry->partition_name[j] != 0) {
      continue;
    }
    if (j == strlen(pszName)) {
      bFound = true;
      break;
    }
  }
  if (bFound) {
    *lba = le64_to_cpu(gptEntry->starting_lba);
    if (gptMasterHead->last_usable_lba == gptEntry->ending_lba) {
      *lba_end = 0xFFFFFFFF;
    } else {
      *lba_end = le64_to_cpu(gptEntry->ending_lba);
    }
    return true;
  }
  return false;
}

bool get_lba_from_param(u8 *param, const char *pszName, u32 *part_offset,
                        u32 *part_size) {
  u32 i;
  bool bFound = false;
  PARAM_ITEM_VECTOR vecItem;
  CONFIG_ITEM_VECTOR vecUuid;

  const bool bRet =
      parse_parameter(reinterpret_cast<char *>(param), vecItem, vecUuid);
  if (!bRet)
    return false;

  for (i = 0; i < vecItem.size(); i++) {
    if (strcasecmp(pszName, vecItem[i].szItemName) == 0) {
      bFound = true;
      break;
    }
  }
  if (bFound) {
    *part_offset = vecItem[i].uiItemOffset;
    *part_size = vecItem[i].uiItemSize;
    return true;
  }
  return false;
}

void update_gpt_disksize(u8 *master, u8 *backup, const u32 total_sector) {
  auto *gptMasterHead = reinterpret_cast<gpt_header *>(master + SECTOR_SIZE);
  gpt_entry *gptLastPartEntry = nullptr;
  u32 i;
  u8 zerobuf[GPT_ENTRY_SIZE] = {};

  const u64 old_disksize = le64_to_cpu(gptMasterHead->alternate_lba) + 1;
  for (i = 0; i < le32_to_cpu(gptMasterHead->num_partition_entries); i++) {
    gptLastPartEntry = reinterpret_cast<gpt_entry *>(master + 2 * SECTOR_SIZE +
                                                     i * GPT_ENTRY_SIZE);
    if (memcmp(zerobuf, gptLastPartEntry, GPT_ENTRY_SIZE) == 0) {
      break;
    }
  }
  i--;
  gptLastPartEntry = reinterpret_cast<gpt_entry *>(master + 2 * SECTOR_SIZE +
                                                   i * sizeof(gpt_entry));

  gptMasterHead->alternate_lba = cpu_to_le64(total_sector - 1);
  gptMasterHead->last_usable_lba = cpu_to_le64(total_sector - 34);

  if (gptLastPartEntry->ending_lba == (old_disksize - 34)) {
    // grow partition
    gptLastPartEntry->ending_lba = cpu_to_le64(total_sector - 34);
    gptMasterHead->partition_entry_array_crc32 = cpu_to_le32(crc32_le(
        0, master + 2 * SECTOR_SIZE, GPT_ENTRY_SIZE * GPT_ENTRY_NUMBERS));
  }
  gptMasterHead->header_crc32 = 0;
  gptMasterHead->header_crc32 =
      cpu_to_le32(crc32_le(0, master + SECTOR_SIZE, sizeof(gpt_header)));
  memcpy(backup, master + 2 * SECTOR_SIZE, GPT_ENTRY_SIZE * GPT_ENTRY_NUMBERS);
  memcpy(backup + GPT_ENTRY_SIZE * GPT_ENTRY_NUMBERS, master + SECTOR_SIZE,
         SECTOR_SIZE);
  prepare_gpt_backup(master, backup);
}

bool load_gpt_buffer(char *pParamFile, u8 *master, u8 *backup) {
  FILE *file = nullptr;
  file = fopen(pParamFile, "rb");
  if (!file) {
    if (g_pLogObject) {
      g_pLogObject->Record("%s failed, err=%d, can't open file: %s\r\n",
                           __func__, errno, pParamFile);
    }
    return false;
  }

  fseek(file, 0, SEEK_END);
  const auto iFileSize = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (iFileSize != 67 * SECTOR_SIZE) {
    if (g_pLogObject) {
      g_pLogObject->Record("%s failed, wrong size file: %s\r\n", __func__,
                           pParamFile);
    }
    fclose(file);
    return false;
  }

  auto iRead = fread(master, 1, 34 * SECTOR_SIZE, file);

  if (iRead != 34 * SECTOR_SIZE) {
    if (g_pLogObject) {
      g_pLogObject->Record(
          "%s failed,read master gpt err=%d, read=%d, total=%d\r\n", __func__,
          errno, iRead, 34 * SECTOR_SIZE);
    }
    fclose(file);
    return false;
  }
  iRead = fread(backup, 1, 33 * SECTOR_SIZE, file);

  if (iRead != 33 * SECTOR_SIZE) {
    if (g_pLogObject) {
      g_pLogObject->Record(
          "%s failed,read backup gpt err=%d, read=%d, total=%d\r\n", __func__,
          errno, iRead, 33 * SECTOR_SIZE);
    }
    fclose(file);
    return false;
  }
  fclose(file);
  return true;
}

void create_gpt_buffer(u8 *gpt, PARAM_ITEM_VECTOR &vecParts,
                       CONFIG_ITEM_VECTOR &vecUuid, const u64 diskSectors) {
  auto *mbr = reinterpret_cast<legacy_mbr *>(gpt);
  auto *gptHead = reinterpret_cast<gpt_header *>(gpt + SECTOR_SIZE);
  auto *gptEntry = reinterpret_cast<gpt_entry *>(gpt + 2 * SECTOR_SIZE);
  int pos;
  /*1.protective mbr*/
  memset(gpt, 0, SECTOR_SIZE);
  mbr->signature = MSDOS_MBR_SIGNATURE;
  mbr->partition_record[0].sys_ind = EFI_PMBR_OSTYPE_EFI_GPT;
  mbr->partition_record[0].start_sect = 1;
  mbr->partition_record[0].nr_sects = (u32)-1;
  /*2.gpt header*/
  memset(gpt + SECTOR_SIZE, 0, SECTOR_SIZE);
  gptHead->signature = cpu_to_le64(GPT_HEADER_SIGNATURE);
  gptHead->revision = cpu_to_le32(GPT_HEADER_REVISION_V1);
  gptHead->header_size = cpu_to_le32(sizeof(gpt_header));
  gptHead->my_lba = cpu_to_le64(1);
  gptHead->alternate_lba = cpu_to_le64(diskSectors - 1);
  gptHead->first_usable_lba = cpu_to_le64(34);
  gptHead->last_usable_lba = cpu_to_le64(diskSectors - 34);
  gptHead->partition_entry_lba = cpu_to_le64(2);
  gptHead->num_partition_entries = cpu_to_le32(GPT_ENTRY_NUMBERS);
  gptHead->sizeof_partition_entry = cpu_to_le32(GPT_ENTRY_SIZE);
  gptHead->header_crc32 = 0;
  gptHead->partition_entry_array_crc32 = 0;
  gen_rand_uuid(gptHead->disk_guid.raw);

  /*3.gpt partition entry*/
  memset(gpt + 2 * SECTOR_SIZE, 0, 32 * SECTOR_SIZE);
  for (auto &[szItemName, uiItemOffset, uiItemSize] : vecParts) {
    gen_rand_uuid(gptEntry->partition_type_guid.raw);
    gen_rand_uuid(gptEntry->unique_partition_guid.raw);
    gptEntry->starting_lba = cpu_to_le64(uiItemOffset);
    gptEntry->ending_lba = cpu_to_le64(gptEntry->starting_lba + uiItemSize - 1);
    gptEntry->attributes.raw = 0;
    std::string strPartName = szItemName;
    if (const std::string::size_type colonPos = strPartName.find_first_of(':');
        colonPos != std::string::npos) {
      if (strPartName.find("bootable") != std::string::npos) {
        gptEntry->attributes.raw = PART_PROPERTY_BOOTABLE;
      }
      if (strPartName.find("grow") != std::string::npos) {
        gptEntry->ending_lba = cpu_to_le64(diskSectors - 34);
      }
      strPartName = strPartName.substr(0, colonPos);
      szItemName[strPartName.size()] = 0;
    }
    for (u32 j = 0; j < strlen(szItemName); j++) {
      gptEntry->partition_name[j] = static_cast<unsigned char>(szItemName[j]);
    }
    if ((pos = find_config_item(vecUuid, szItemName)) != -1) {
      memcpy(gptEntry->unique_partition_guid.raw, vecUuid[pos].szItemValue, 16);
    }
    gptEntry++;
  }

  gptHead->partition_entry_array_crc32 = cpu_to_le32(
      crc32_le(0, gpt + 2 * SECTOR_SIZE, GPT_ENTRY_SIZE * GPT_ENTRY_NUMBERS));
  gptHead->header_crc32 =
      cpu_to_le32(crc32_le(0, gpt + SECTOR_SIZE, sizeof(gpt_header)));
}

bool MakeSector0(PBYTE pSector, unsigned short usFlashDataSec, unsigned short usFlashBootSec,
                 bool rc4Flag) {
  memset(pSector, 0, SECTOR_SIZE);
  const auto pSec0 = reinterpret_cast<PRK28_IDB_SEC0>(pSector);

  pSec0->dwTag = 0x0FF0AA55;
  pSec0->uiRc4Flag = rc4Flag;
  pSec0->usBootCode1Offset = 0x4;
  pSec0->usBootCode2Offset = 0x4;
  pSec0->usBootDataSize = usFlashDataSec;
  pSec0->usBootCodeSize = usFlashDataSec + usFlashBootSec;
  return true;
}

bool MakeSector1(PBYTE pSector) {
  memset(pSector, 0, SECTOR_SIZE);
  const auto pSec1 = reinterpret_cast<PRK28_IDB_SEC1>(pSector);

  pSec1->usSysReservedBlock = 0xC;
  pSec1->usDisk0Size = 0xFFFF;
  pSec1->uiChipTag = 0x38324B52;
  return true;
}

bool MakeSector2(PBYTE pSector) {
  memset(pSector, 0, SECTOR_SIZE);
  const auto pSec2 = reinterpret_cast<PRK28_IDB_SEC2>(pSector);

  strcpy(pSec2->szVcTag, "VC");
  strcpy(pSec2->szCrcTag, "CRC");
  return true;
}

bool MakeSector3(PBYTE pSector) {
  memset(pSector, 0, SECTOR_SIZE);
  return true;
}

int MakeIDBlockData(PBYTE pDDR, PBYTE pLoader, PBYTE lpIDBlock,
                    unsigned short usFlashDataSec, unsigned short usFlashBootSec,
                    unsigned int dwLoaderDataSize, unsigned int dwLoaderSize, bool rc4Flag) {
  RK28_IDB_SEC0 sector0Info;
  RK28_IDB_SEC1 sector1Info;
  RK28_IDB_SEC2 sector2Info;
  RK28_IDB_SEC3 sector3Info;
  unsigned int i;
  MakeSector0(reinterpret_cast<PBYTE>(&sector0Info), usFlashDataSec,
              usFlashBootSec, rc4Flag);
  MakeSector1(reinterpret_cast<PBYTE>(&sector1Info));
  if (!MakeSector2(reinterpret_cast<PBYTE>(&sector2Info))) {
    return -6;
  }
  if (!MakeSector3(reinterpret_cast<PBYTE>(&sector3Info))) {
    return -7;
  }
  sector2Info.usSec0Crc =
      CRC_16(reinterpret_cast<PBYTE>(&sector0Info), SECTOR_SIZE);
  sector2Info.usSec1Crc =
      CRC_16(reinterpret_cast<PBYTE>(&sector1Info), SECTOR_SIZE);
  sector2Info.usSec3Crc =
      CRC_16(reinterpret_cast<PBYTE>(&sector3Info), SECTOR_SIZE);

  memcpy(lpIDBlock, &sector0Info, SECTOR_SIZE);
  memcpy(lpIDBlock + SECTOR_SIZE, &sector1Info, SECTOR_SIZE);
  memcpy(lpIDBlock + SECTOR_SIZE * 3, &sector3Info, SECTOR_SIZE);

  if (rc4Flag) {
    for (i = 0; i < dwLoaderDataSize / SECTOR_SIZE; i++) {
      P_RC4(pDDR + i * SECTOR_SIZE, SECTOR_SIZE);
    }
    for (i = 0; i < dwLoaderSize / SECTOR_SIZE; i++) {
      P_RC4(pLoader + i * SECTOR_SIZE, SECTOR_SIZE);
    }
  }

  memcpy(lpIDBlock + SECTOR_SIZE * 4, pDDR, dwLoaderDataSize);
  memcpy(lpIDBlock + SECTOR_SIZE * (4 + usFlashDataSec), pLoader, dwLoaderSize);

  sector2Info.uiBootCodeCrc = CRC_32(lpIDBlock + SECTOR_SIZE * 4,
                                     sector0Info.usBootCodeSize * SECTOR_SIZE);
  memcpy(lpIDBlock + SECTOR_SIZE * 2, &sector2Info, SECTOR_SIZE);
  for (i = 0; i < 4; i++) {
    if (i == 1) {
    } else {
      P_RC4(lpIDBlock + SECTOR_SIZE * i, SECTOR_SIZE);
    }
  }
  return 0;
}

bool check_device_type(STRUCT_RKDEVICE_DESC &dev, unsigned int uiSupportType) {
  if ((static_cast<unsigned int>(dev.emUsbType) & uiSupportType) ==
      static_cast<unsigned int>(dev.emUsbType)) {
    return true;
  }
  ERROR_COLOR_ATTR;
  printf("The device does not support this operation!");
  NORMAL_COLOR_ATTR;
  printf("\r\n");
  return false;
}

bool MakeParamBuffer(char *pParamFile, char *&pParamData) {
  FILE *file = nullptr;
  file = fopen(pParamFile, "rb");
  if (!file) {
    if (g_pLogObject) {
      g_pLogObject->Record(
          "MakeParamBuffer failed,err=%d,can't open file: %s\r\n", errno,
          pParamFile);
    }
    return false;
  }
  fseek(file, 0, SEEK_END);
  const int iFileSize = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *pParamBuf = nullptr;
  pParamBuf = new char[iFileSize + 12];
  if (!pParamBuf) {
    fclose(file);
    return false;
  }
  memset(pParamBuf, 0, iFileSize + 12);
  *reinterpret_cast<unsigned int *>(pParamBuf) = 0x4D524150;

  if (const auto iRead = fread(pParamBuf + 8, 1, iFileSize, file);
      iRead != iFileSize) {
    if (g_pLogObject) {
      g_pLogObject->Record("MakeParamBuffer failed,err=%d,read=%d,total=%d\r\n",
                           errno, iRead, iFileSize);
    }
    fclose(file);
    delete[] pParamBuf;
    return false;
  }
  fclose(file);

  *reinterpret_cast<unsigned int *>(pParamBuf + 4) = iFileSize;
  *reinterpret_cast<unsigned int *>(pParamBuf + 8 + iFileSize) =
      CRC_32(reinterpret_cast<PBYTE>(pParamBuf) + 8, iFileSize);
  pParamData = pParamBuf;
  return true;
}

bool write_parameter(STRUCT_RKDEVICE_DESC &dev, char *szParameter) {
  CRKComm *pComm = nullptr;
  char *pParamBuf = nullptr;
  char *writeBuf[512 * 1024];
  bool bRet, bSuccess = false;
  if (!check_device_type(dev, RKUSB_MASKROM | RKUSB_LOADER)) {
    return false;
  }

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Creating Comm Object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  if (!MakeParamBuffer(szParameter, pParamBuf)) {
    ERROR_COLOR_ATTR;
    printf("Generating parameter failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  printf("Writing parameter...\r\n");
  const auto nParamSize = *reinterpret_cast<unsigned int *>(pParamBuf + 4) + 12;
  const auto nParamSec = BYTE2SECTOR(nParamSize);
  if (nParamSec > 1024) {
    ERROR_COLOR_ATTR;
    printf("parameter is too large!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  memset(writeBuf, 0, nParamSec * 512);
  memcpy(writeBuf, pParamBuf, nParamSize);
  if (const int iRet = pComm->RKU_WriteLBA(0x2000, nParamSec,
                                           reinterpret_cast<BYTE *>(writeBuf),
                                           RWMETHOD_IMAGE);
      iRet != ERR_SUCCESS) {
    ERROR_COLOR_ATTR;
    printf("Writing parameter failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  bSuccess = true;
  CURSOR_MOVEUP_LINE(1);
  CURSOR_DEL_LINE;
  printf("Writing parameter succeeded.\r\n");
  return bSuccess;
}

bool write_gpt(STRUCT_RKDEVICE_DESC &dev, char *szParameter) {
  u8 flash_info[SECTOR_SIZE], master_gpt[34 * SECTOR_SIZE],
      backup_gpt[33 * SECTOR_SIZE];
  CRKComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  if (!check_device_type(dev, RKUSB_MASKROM))
    return false;

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Creating Comm Object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  printf("Writing gpt...\r\n");

  // 1.get flash info
  auto iRet = pComm->RKU_ReadFlashInfo(flash_info, nullptr);
  if (iRet != ERR_SUCCESS) {
    ERROR_COLOR_ATTR;
    printf("Reading Flash Info failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  const u32 total_size_sector = *reinterpret_cast<u32 *>(flash_info);
  if (strstr(szParameter, ".img")) {
    if (!load_gpt_buffer(szParameter, master_gpt, backup_gpt)) {
      ERROR_COLOR_ATTR;
      printf("Loading partition image failed!");
      NORMAL_COLOR_ATTR;
      printf("\r\n");
      return bSuccess;
    }
    update_gpt_disksize(master_gpt, backup_gpt, total_size_sector);
  } else {
    CONFIG_ITEM_VECTOR vecUuid;
    PARAM_ITEM_VECTOR vecItems;

    // 2.get partition from parameter
    bRet = parse_parameter_file(szParameter, vecItems, vecUuid);
    if (!bRet) {
      ERROR_COLOR_ATTR;
      printf("Parsing parameter failed!");
      NORMAL_COLOR_ATTR;
      printf("\r\n");
      return bSuccess;
    }

    // 3.generate gpt info
    create_gpt_buffer(master_gpt, vecItems, vecUuid, total_size_sector);
    memcpy(backup_gpt, master_gpt + 2 * SECTOR_SIZE, 32 * SECTOR_SIZE);
    memcpy(backup_gpt + 32 * SECTOR_SIZE, master_gpt + SECTOR_SIZE,
           SECTOR_SIZE);
    prepare_gpt_backup(master_gpt, backup_gpt);
  }

  // 4. write gpt
  iRet = pComm->RKU_WriteLBA(0, 34, master_gpt, RWMETHOD_IMAGE);
  if (iRet != ERR_SUCCESS) {
    ERROR_COLOR_ATTR;
    printf("Writing master gpt failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  iRet = pComm->RKU_WriteLBA(total_size_sector - 33, 33, backup_gpt,
                             RWMETHOD_IMAGE);
  if (iRet != ERR_SUCCESS) {
    ERROR_COLOR_ATTR;
    printf("Writing backup gpt failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  bSuccess = true;
  CURSOR_MOVEUP_LINE(1);
  CURSOR_DEL_LINE;
  printf("Writing gpt succeeded.\r\n");
  return bSuccess;
}

#define ENTRY_ALIGN (2048)
options gOpts;
char gSubfix[MAX_LINE_LEN] = OUT_SUBFIX;
char *gConfigPath;
uint8_t gBuf[MAX_MERGE_SIZE];

static void fixPath(char *path) {
  const auto len = strlen(path);
  for (int i = 0; i < len; i++) {
    if (path[i] == '\\') {
      path[i] = '/';
    } else if (path[i] == '\r' || path[i] == '\n') {
      path[i] = '\0';
    }
  }
}

static bool parseChip(FILE *file) {
  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_NAME "=%s", gOpts.chip) != 1) {
    return false;
  }
  printf("chip: %s\n", gOpts.chip);
  return true;
}

static bool parseVersion(FILE *file) {
  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_MAJOR "=%d", &gOpts.major) != 1) {
    return false;
  }
  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_MINOR "=%d", &gOpts.minor) != 1) {
    return false;
  }
  printf("major: %d, minor: %d\n", gOpts.major, gOpts.minor);
  return true;
}

static bool parse471(FILE *file) {
  int index;

  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_NUM "=%d", &gOpts.code471Num) != 1) {
    return false;
  }
  printf("num: %d\n", gOpts.code471Num);
  if (!gOpts.code471Num) {
    return true;
  }
  if (gOpts.code471Num < 0) {
    return false;
  }
  gOpts.code471Path =
      static_cast<line_t *>(malloc(sizeof(line_t) * gOpts.code471Num));
  for (int i = 0; i < gOpts.code471Num; i++) {
    char buf[MAX_LINE_LEN];
    if (SCANF_EAT(file) != 0) {
      return false;
    }
    if (fscanf(file, OPT_PATH "%d=%[^\r^\n]", &index, buf) != 2) {
      return false;
    }
    index--;
    fixPath(buf);
    strcpy(gOpts.code471Path[index], buf);
    printf("path%i: %s\n", index, gOpts.code471Path[index]);
  }
  const auto pos = ftell(file);
  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_SLEEP "=%d", &gOpts.code471Sleep) != 1) {
    fseek(file, pos, SEEK_SET);
  }
  printf("sleep: %d\n", gOpts.code471Sleep);
  return true;
}

static bool parse472(FILE *file) {
  int index;

  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_NUM "=%d", &gOpts.code472Num) != 1) {
    return false;
  }
  printf("num: %d\n", gOpts.code472Num);
  if (!gOpts.code472Num) {
    return true;
  }
  if (gOpts.code472Num < 0) {
    return false;
  }
  gOpts.code472Path =
      static_cast<line_t *>(malloc(sizeof(line_t) * gOpts.code472Num));
  for (auto i = 0; i < gOpts.code472Num; i++) {
    char buf[MAX_LINE_LEN];
    if (SCANF_EAT(file) != 0) {
      return false;
    }
    if (fscanf(file, OPT_PATH "%d=%[^\r^\n]", &index, buf) != 2) {
      return false;
    }
    fixPath(buf);
    index--;
    strcpy(gOpts.code472Path[index], buf);
    printf("path%i: %s\n", index, gOpts.code472Path[index]);
  }
  const auto pos = ftell(file);
  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_SLEEP "=%d", &gOpts.code472Sleep) != 1) {
    fseek(file, pos, SEEK_SET);
  }
  printf("sleep: %d\n", gOpts.code472Sleep);
  return true;
}

static bool parseLoader(FILE *file) {
  int i;
  int j;
  int index;
  char buf[MAX_LINE_LEN];

  if (SCANF_EAT(file) != 0) {
    return false;
  }
  auto pos = ftell(file);
  if (fscanf(file, OPT_NUM "=%d", &gOpts.loaderNum) != 1) {
    fseek(file, pos, SEEK_SET);
    if (fscanf(file, OPT_LOADER_NUM "=%d", &gOpts.loaderNum) != 1) {
      return false;
    }
  }
  printf("num: %d\n", gOpts.loaderNum);
  if (!gOpts.loaderNum) {
    return false;
  }
  if (gOpts.loaderNum < 0) {
    return false;
  }
  gOpts.loader =
      static_cast<name_entry *>(malloc(sizeof(name_entry) * gOpts.loaderNum));
  for (i = 0; i < gOpts.loaderNum; i++) {
    if (SCANF_EAT(file) != 0) {
      return false;
    }
    if (fscanf(file, OPT_LOADER_NAME "%d=%s", &index, buf) != 2) {
      return false;
    }
    strcpy(gOpts.loader[index].name, buf);
    printf("name%d: %s\n", index, gOpts.loader[index].name);
    index++;
  }
  for (i = 0; i < gOpts.loaderNum; i++) {
    char buf2[MAX_LINE_LEN];
    if (SCANF_EAT(file) != 0) {
      return false;
    }
    if (fscanf(file, "%[^=]=%[^\r^\n]", buf, buf2) != 2) {
      return false;
    }
    for (j = 0; j < gOpts.loaderNum; j++) {
      if (!strcmp(gOpts.loader[j].name, buf)) {
        fixPath(buf2);
        strcpy(gOpts.loader[j].path, buf2);
        printf("%s=%s\n", gOpts.loader[j].name, gOpts.loader[j].path);
        break;
      }
    }
    if (j >= gOpts.loaderNum) {
      return false;
    }
  }
  return true;
}

static bool parseOut(FILE *file) {
  if (SCANF_EAT(file) != 0) {
    return false;
  }
  if (fscanf(file, OPT_OUT_PATH "=%[^\r^\n]", gOpts.outPath) != 1) {
    return false;
  }
  fixPath(gOpts.outPath);
  printf("out: %s\n", gOpts.outPath);
  return true;
}

void printOpts(FILE *out) {
  int i;
  fprintf(out, SEC_CHIP "\n" OPT_NAME "=%s\n", gOpts.chip);
  fprintf(out, SEC_VERSION "\n" OPT_MAJOR "=%d\n" OPT_MINOR "=%d\n",
          gOpts.major, gOpts.minor);

  fprintf(out, SEC_471 "\n" OPT_NUM "=%d\n", gOpts.code471Num);
  for (i = 0; i < gOpts.code471Num; i++) {
    fprintf(out, OPT_PATH "%d=%s\n", i + 1, gOpts.code471Path[i]);
  }
  if (gOpts.code471Sleep > 0) {
    fprintf(out, OPT_SLEEP "=%d\n", gOpts.code471Sleep);
  }

  fprintf(out, SEC_472 "\n" OPT_NUM "=%d\n", gOpts.code472Num);
  for (i = 0; i < gOpts.code472Num; i++) {
    fprintf(out, OPT_PATH "%d=%s\n", i + 1, gOpts.code472Path[i]);
  }
  if (gOpts.code472Sleep > 0) {
    fprintf(out, OPT_SLEEP "=%d\n", gOpts.code472Sleep);
  }

  fprintf(out, SEC_LOADER "\n" OPT_NUM "=%d\n", gOpts.loaderNum);
  for (i = 0; i < gOpts.loaderNum; i++) {
    fprintf(out, OPT_LOADER_NAME "%d=%s\n", i + 1, gOpts.loader[i].name);
  }
  for (i = 0; i < gOpts.loaderNum; i++) {
    fprintf(out, "%s=%s\n", gOpts.loader[i].name, gOpts.loader[i].path);
  }

  fprintf(out, SEC_OUT "\n" OPT_OUT_PATH "=%s\n", gOpts.outPath);
}

static bool parseOpts() {
  bool ret = false;
  bool chipOk = false;
  bool versionOk = false;
  bool code471Ok = true;
  bool code472Ok = true;
  bool loaderOk = false;
  bool outOk = false;
  char buf[MAX_LINE_LEN];

  char *configPath =
      (gConfigPath == (char *)nullptr) ? (char *)DEF_CONFIG_FILE : gConfigPath;
  FILE *file = fopen(configPath, "r");
  if (!file) {
    fprintf(stderr, "config (%s) not found!\n", configPath);
    if (strcmp(configPath, (char *)DEF_CONFIG_FILE) == 0) {
      file = fopen(DEF_CONFIG_FILE, "w");
      if (file) {
        fprintf(stderr, "creating defconfig\n");
        printOpts(file);
      }
    }
    goto end;
  }

  printf("Starting to parse...\n");

  if (SCANF_EAT(file) != 0) {
    goto end;
  }
  while (fscanf(file, "%s", buf) == 1) {
    if (!strcmp(buf, SEC_CHIP)) {
      chipOk = parseChip(file);
      if (!chipOk) {
        printf("parseChip failed!\n");
        goto end;
      }
    } else if (!strcmp(buf, SEC_VERSION)) {
      versionOk = parseVersion(file);
      if (!versionOk) {
        printf("parseVersion failed!\n");
        goto end;
      }
    } else if (!strcmp(buf, SEC_471)) {
      code471Ok = parse471(file);
      if (!code471Ok) {
        printf("parse471 failed!\n");
        goto end;
      }
    } else if (!strcmp(buf, SEC_472)) {
      code472Ok = parse472(file);
      if (!code472Ok) {
        printf("parse472 failed!\n");
        goto end;
      }
    } else if (!strcmp(buf, SEC_LOADER)) {
      loaderOk = parseLoader(file);
      if (!loaderOk) {
        printf("parseLoader failed!\n");
        goto end;
      }
    } else if (!strcmp(buf, SEC_OUT)) {
      outOk = parseOut(file);
      if (!outOk) {
        printf("parseOut failed!\n");
        goto end;
      }
    } else if (buf[0] == '#') {
      continue;
    } else {
      printf("unknown sec: %s!\n", buf);
      goto end;
    }
    if (SCANF_EAT(file) != 0) {
      goto end;
    }
  }

  if (chipOk && versionOk && code471Ok && code472Ok && loaderOk && outOk) {
    ret = true;
  }
end:
  if (file) {
    fclose(file);
  }
  return ret;
}

bool initOpts() {
  // set default opts
  gOpts.major = DEF_MAJOR;
  gOpts.minor = DEF_MINOR;
  strcpy(gOpts.chip, DEF_CHIP);
  gOpts.code471Sleep = DEF_CODE471_SLEEP;
  gOpts.code472Sleep = DEF_CODE472_SLEEP;
  gOpts.code471Num = DEF_CODE471_NUM;
  gOpts.code471Path =
      static_cast<line_t *>(malloc(sizeof(line_t) * gOpts.code471Num));
  strcpy(gOpts.code471Path[0], DEF_CODE471_PATH);
  gOpts.code472Num = DEF_CODE472_NUM;
  gOpts.code472Path =
      static_cast<line_t *>(malloc(sizeof(line_t) * gOpts.code472Num));
  strcpy(gOpts.code472Path[0], DEF_CODE472_PATH);
  gOpts.loaderNum = DEF_LOADER_NUM;
  gOpts.loader =
      static_cast<name_entry *>(malloc(sizeof(name_entry) * gOpts.loaderNum));
  strcpy(gOpts.loader[0].name, DEF_LOADER0);
  strcpy(gOpts.loader[0].path, DEF_LOADER0_PATH);
  strcpy(gOpts.loader[1].name, DEF_LOADER1);
  strcpy(gOpts.loader[1].path, DEF_LOADER1_PATH);
  strcpy(gOpts.outPath, DEF_OUT_PATH);

  return parseOpts();
}

/************merge code****************/

static uint32_t getBCD(unsigned short value) {
  uint8_t tmp[2] = {};
  for (unsigned char &i : tmp) {
    i = value / 10 % 10 << 4 | value % 10;
    value /= 100;
  }
  const uint32_t ret = static_cast<uint16_t>(tmp[1] << 8) | tmp[0];

  printf("ret: %x\n", ret);
  return ret & 0xFF;
}

static void str2wide(const char *str, uint16_t *wide, const long len) {
  for (int i = 0; i < len; i++) {
    wide[i] = static_cast<unsigned char>(str[i]);
  }
  wide[len] = 0;
}

static void getName(char *path, uint16_t *dst) {
  if (!path || !dst) {
    return;
  }
  const char *start = strrchr(path, '/');
  if (!start) {
    start = path;
  } else {
    start++;
  }
  const char *end = strrchr(path, '.');
  if (!end || end < start) {
    end = path + strlen(path);
  }
  long len = end - start;
  if (len >= MAX_NAME_LEN) {
    len = MAX_NAME_LEN - 1;
  }
  str2wide(start, dst, len);

  char name[MAX_NAME_LEN] = {};
  memcpy(name, start, len);
  std::cout << "path: " << path << " name: " << name << std::endl;
}

static bool getFileSize(const char *path, uint32_t *size) {
  struct stat st {};
  if (stat(path, &st) < 0) {
    return false;
  }
  *size = st.st_size;
  printf("path: %s, size: %d\n", path, *size);
  return true;
}

static rk_time getTime() {
  rk_time rkTime;

  const time_t tt = time(nullptr);
  const tm *tm = localtime(&tt);
  rkTime.year = tm->tm_year + 1900;
  rkTime.month = tm->tm_mon + 1;
  rkTime.day = tm->tm_mday;
  rkTime.hour = tm->tm_hour;
  rkTime.minute = tm->tm_min;
  rkTime.second = tm->tm_sec;
  std::cout << rkTime.year << "-" << rkTime.month << "-" << rkTime.day << " "
            << std::setw(2) << std::setfill('0') << rkTime.hour << ":"
            << std::setw(2) << std::setfill('0') << rkTime.minute << ":"
            << std::setw(2) << std::setfill('0') << rkTime.second << std::endl;
  return rkTime;
}

static bool writeFile(FILE *outFile, const char *path, bool fix) {
  bool ret = false;
  uint32_t size = 0, fixSize = 0;

  FILE *inFile = fopen(path, "rb");
  if (!inFile) {
    goto end;
  }

  if (!getFileSize(path, &size)) {
    goto end;
  }
  if (fix) {
    fixSize = ((size - 1) / SMALL_PACKET + 1) * SMALL_PACKET;
    uint32_t tmp = fixSize % ENTRY_ALIGN;
    tmp = tmp ? (ENTRY_ALIGN - tmp) : 0;
    fixSize += tmp;
    memset(gBuf, 0, fixSize);
  } else {
    memset(gBuf, 0, size + ENTRY_ALIGN);
  }
  if (!fread(gBuf, size, 1, inFile)) {
    goto end;
  }

  if (fix) {
    uint8_t *buf = gBuf;
    size = fixSize;
    while (true) {
      P_RC4(buf, fixSize < SMALL_PACKET ? fixSize : SMALL_PACKET);
      buf += SMALL_PACKET;
      if (fixSize <= SMALL_PACKET) {
        break;
      }
      fixSize -= SMALL_PACKET;
    }
  } else {
    uint32_t tmp = size % ENTRY_ALIGN;
    tmp = tmp ? (ENTRY_ALIGN - tmp) : 0;
    size += tmp;
    P_RC4(gBuf, size);
  }

  if (!fwrite(gBuf, size, 1, outFile)) {
    goto end;
  }
  ret = true;
end:
  if (inFile) {
    fclose(inFile);
  }
  if (!ret) {
    printf("writing entry (%s) failed\n", path);
  }
  return ret;
}

static bool saveEntry(FILE *outFile, char *path, const rk_entry_type type,
                      const uint16_t delay, uint32_t *offset, char *fixName,
                      const bool fix) {
  uint32_t size;
  rk_boot_entry entry;

  printf("writing: %s\n", path);
  memset(&entry, 0, sizeof(rk_boot_entry));
  getName(fixName ? fixName : path, entry.name);
  entry.size = sizeof(rk_boot_entry);
  entry.type = type;
  entry.dataOffset = *offset;
  if (!getFileSize(path, &size)) {
    printf("Saving entry (%s) failed:\n\tCannot get file size.\n", path);
    return false;
  }
  if (fix) {
    size = ((size - 1) / SMALL_PACKET + 1) * SMALL_PACKET;
  }
  const uint32_t tmp = size % ENTRY_ALIGN;
  size += tmp ? (ENTRY_ALIGN - tmp) : 0;
  printf("alignment size: %d\n", size);
  entry.dataSize = size;
  entry.dataDelay = delay;
  *offset += size;
  fwrite(&entry, sizeof(rk_boot_entry), 1, outFile);
  return true;
}

static uint32_t convertChipType(const char *chip) {
  char buffer[5] = {};
  snprintf(buffer, sizeof(buffer), "%s", chip);
  return buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3];
}

static uint32_t getChipType(const char *chip) {
  printf("chip: %s\n", chip);
  uint32_t chipType = RKNONE_DEVICE;
  if (!chip) {
    goto end;
  }
  if (!strcmp(chip, CHIP_RK28)) {
    chipType = RK28_DEVICE;
  } else if (!strcmp(chip, CHIP_RK281X)) {
    chipType = RK281X_DEVICE;
  } else if (!strcmp(chip, CHIP_RKPANDA)) {
    chipType = RKPANDA_DEVICE;
  } else if (!strcmp(chip, CHIP_RK27)) {
    chipType = RK27_DEVICE;
  } else if (!strcmp(chip, CHIP_RKNANO)) {
    chipType = RKNANO_DEVICE;
  } else if (!strcmp(chip, CHIP_RKSMART)) {
    chipType = RKSMART_DEVICE;
  } else if (!strcmp(chip, CHIP_RKCROWN)) {
    chipType = RKCROWN_DEVICE;
  } else if (!strcmp(chip, CHIP_RKCAYMAN)) {
    chipType = RKCAYMAN_DEVICE;
  } else if (!strcmp(chip, CHIP_RK29)) {
    chipType = RK29_DEVICE;
  } else if (!strcmp(chip, CHIP_RK292X)) {
    chipType = RK292X_DEVICE;
  } else if (!strcmp(chip, CHIP_RK30)) {
    chipType = RK30_DEVICE;
  } else if (!strcmp(chip, CHIP_RK30B)) {
    chipType = RK30B_DEVICE;
  } else if (!strcmp(chip, CHIP_RK31)) {
    chipType = RK31_DEVICE;
  } else if (!strcmp(chip, CHIP_RK32)) {
    chipType = RK32_DEVICE;
  } else {
    chipType = convertChipType(chip + 2);
  }

end:
  printf("type: 0x%x\n", chipType);
  if (chipType == RKNONE_DEVICE) {
    printf("chip type not supported!\n");
  }
  return chipType;
}

static void getBoothdr(rk_boot_header *hdr) {
  memset(hdr, 0, sizeof(rk_boot_header));
  hdr->tag = TAG;
  hdr->size = sizeof(rk_boot_header);
  hdr->version = (getBCD(gOpts.major) << 8) | getBCD(gOpts.minor);
  hdr->mergerVersion = MERGER_VERSION;
  hdr->releaseTime = getTime();
  hdr->chipType = getChipType(gOpts.chip);

  hdr->code471Num = gOpts.code471Num;
  hdr->code471Offset = sizeof(rk_boot_header);
  hdr->code471Size = sizeof(rk_boot_entry);

  hdr->code472Num = gOpts.code472Num;
  hdr->code472Offset = hdr->code471Offset + gOpts.code471Num * hdr->code471Size;
  hdr->code472Size = sizeof(rk_boot_entry);

  hdr->loaderNum = gOpts.loaderNum;
  hdr->loaderOffset = hdr->code472Offset + gOpts.code472Num * hdr->code472Size;
  hdr->loaderSize = sizeof(rk_boot_entry);
#ifndef USE_P_RC4
  hdr->rc4Flag = 1;
#endif
}

static uint32_t getCrc(const char *path) {
  uint32_t size = 0;
  uint32_t crc = 0;

  FILE *file = fopen(path, "rb");
  getFileSize(path, &size);
  if (!file) {
    goto end;
  }
  if (!fread(gBuf, size, 1, file)) {
    goto end;
  }
  crc = CRC_32(gBuf, size);
  printf("crc: 0x%08x\n", crc);
end:
  if (file) {
    fclose(file);
  }
  return crc;
}

bool mergeBoot() {
  uint32_t dataOffset;
  bool ret = false;
  int i;
  uint32_t crc;
  rk_boot_header hdr;

  if (!initOpts())
    return false;
  {
    char *subfix = strstr(gOpts.outPath, OUT_SUBFIX);
    char version[MAX_LINE_LEN];
    snprintf(version, sizeof(version), "%s", gSubfix);
    if (subfix && !strcmp(subfix, OUT_SUBFIX)) {
      subfix[0] = '\0';
    }
    strcat(gOpts.outPath, version);
    printf("fix opt: %s\n", gOpts.outPath);
  }

  printf("---------------\nUSING CONFIG:\n");
  printOpts(stdout);
  printf("---------------\n\n");

  FILE *outFile = fopen(gOpts.outPath, "wb+");
  if (!outFile) {
    printf("Opening output file (%s) failed\n", gOpts.outPath);
    goto end;
  }

  getBoothdr(&hdr);
  printf("Writing header...\n");
  fwrite(&hdr, 1, sizeof(rk_boot_header), outFile);

  dataOffset = sizeof(rk_boot_header) +
               (gOpts.code471Num + gOpts.code472Num + gOpts.loaderNum) *
                   sizeof(rk_boot_entry);

  printf("Writing code 471 entry...\n");
  for (i = 0; i < gOpts.code471Num; i++) {
    if (!saveEntry(outFile, gOpts.code471Path[i], ENTRY_471, gOpts.code471Sleep,
                   &dataOffset, nullptr, false)) {
      goto end;
    }
  }
  printf("Writing code 472 entry...\n");
  for (i = 0; i < gOpts.code472Num; i++) {
    if (!saveEntry(outFile, gOpts.code472Path[i], ENTRY_472, gOpts.code472Sleep,
                   &dataOffset, nullptr, false)) {
      goto end;
    }
  }
  printf("Writing loader entry...\n");
  for (i = 0; i < gOpts.loaderNum; i++) {
    if (!saveEntry(outFile, gOpts.loader[i].path, ENTRY_LOADER, 0, &dataOffset,
                   gOpts.loader[i].name, true)) {
      goto end;
    }
  }

  printf("Writing code 471...\n");
  for (i = 0; i < gOpts.code471Num; i++) {
    if (!writeFile(outFile, gOpts.code471Path[i], false)) {
      goto end;
    }
  }
  printf("Writing code 472...\n");
  for (i = 0; i < gOpts.code472Num; i++) {
    if (!writeFile(outFile, gOpts.code472Path[i], false)) {
      goto end;
    }
  }
  printf("Writing loader...\n");
  for (i = 0; i < gOpts.loaderNum; i++) {
    if (!writeFile(outFile, gOpts.loader[i].path, true)) {
      goto end;
    }
  }
  fflush(outFile);

  printf("Writing crc...\n");
  crc = getCrc(gOpts.outPath);
  if (!fwrite(&crc, sizeof(crc), 1, outFile)) {
    goto end;
  }
  printf("Done.\n");
  ret = true;
end:
  if (outFile) {
    fclose(outFile);
  }
  return ret;
}

/************merge code end************/
/************unpack code***************/

static void wide2str(const uint16_t *wide, char *str, int len) {
  for (int i = 0; i < len; i++) {
    str[i] = static_cast<char>(wide[i] & 0xFF);
  }
}

static bool unpackEntry(rk_boot_entry *entry, const char *name, FILE *inFile) {
  bool ret = false;
  uint32_t size;
  FILE *outFile = fopen(name, "wb+");
  if (!outFile) {
    goto end;
  }
  printf("unpacking entry (%s)\n", name);
  fseek(inFile, entry->dataOffset, SEEK_SET);
  size = entry->dataSize;
  if (!fread(gBuf, size, 1, inFile)) {
    goto end;
  }
  if (entry->type == ENTRY_LOADER) {
    int i;
    for (i = 0; i < size / SMALL_PACKET; i++) {
      P_RC4(gBuf + i * SMALL_PACKET, SMALL_PACKET);
    }
    if (size % SMALL_PACKET) {
      P_RC4(gBuf + i * SMALL_PACKET, size - SMALL_PACKET * 512);
    }
  } else {
    P_RC4(gBuf, size);
  }
  if (!fwrite(gBuf, size, 1, outFile)) {
    goto end;
  }
  ret = true;
end:
  if (outFile) {
    fclose(outFile);
  }
  return ret;
}

bool unpackBoot(char *path) {
  bool ret = false;
  rk_boot_entry *entrys;
  int entryNum;
  FILE *inFile = fopen(path, "rb");
  if (!inFile) {
    fprintf(stderr, "loader (%s) not found\n", path);
    goto end;
  }

  rk_boot_header hdr;
  if (!fread(&hdr, sizeof(rk_boot_header), 1, inFile)) {
    fprintf(stderr, "reading header failed\n");
    goto end;
  }
  printf("471 num:%d, 472 num:%d, loader num:%d\n", hdr.code471Num,
         hdr.code472Num, hdr.loaderNum);
  entryNum = hdr.code471Num + hdr.code472Num + hdr.loaderNum;
  entrys =
      static_cast<rk_boot_entry *>(malloc(sizeof(rk_boot_entry) * entryNum));
  if (!fread(entrys, sizeof(rk_boot_entry) * entryNum, 1, inFile)) {
    fprintf(stderr, "reading data failed\n");
    goto end;
  }

  printf("entry num: %d\n", entryNum);
  for (int i = 0; i < entryNum; i++) {
    char name[MAX_NAME_LEN];
    wide2str(entrys[i].name, name, MAX_NAME_LEN);

    printf("entry: t=%d, name=%s, off=%d, size=%d\n", entrys[i].type, name,
           entrys[i].dataOffset, entrys[i].dataSize);
    if (!unpackEntry(entrys + i, name, inFile)) {
      fprintf(stderr, "unpacking entry (%s) failed\n", name);
      goto end;
    }
  }
  printf("done\n");
  ret = true;
end:
  if (inFile)
    fclose(inFile);
  return ret;
}

bool download_boot(STRUCT_RKDEVICE_DESC &dev, const char *szLoader) {
  if (!check_device_type(dev, RKUSB_MASKROM)) {
    return false;
  }
  CRKImage *pImage = nullptr;
  bool bRet;
  bool bSuccess = false;

  pImage = new CRKImage(szLoader, bRet);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Opening loader failed, exiting download boot!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  CRKBoot *pBoot = nullptr;
  pBoot = pImage->m_bootObject;
  CRKComm *pComm = nullptr;
  CRKDevice *pDevice = nullptr;

  dev.emDeviceType = pBoot->SupportDevice;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    delete pImage;
    ERROR_COLOR_ATTR;
    printf("Creating Comm Object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  pDevice = new CRKDevice(dev);
  if (!pDevice) {
    delete pImage;
    delete pComm;
    ERROR_COLOR_ATTR;
    printf("Creating device object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  pDevice->SetObject(pImage, pComm, g_pLogObject);
  printf("Downloading bootloader...\r\n");
  int iRet = pDevice->DownloadBoot();

  CURSOR_MOVEUP_LINE(1);
  CURSOR_DEL_LINE;
  if (iRet == 0) {
    bSuccess = true;
    printf("Downloading bootloader succeeded.\r\n");
  } else {
    printf("Downloading bootloader failed!\r\n");
  }
  delete pImage;
  delete pDevice;
  return bSuccess;
}

bool upgrade_loader(STRUCT_RKDEVICE_DESC &dev, const char *szLoader) {
  if (!check_device_type(dev, RKUSB_MASKROM)) {
    return false;
  }
  CRKImage *pImage = nullptr;
  CRKComm *pComm = nullptr;
  bool bRet, bNewIDBlock = false, bSuccess = false;
  int iRet;
  unsigned short usFlashHeadSec = 0;
  unsigned int dwLoaderSize, dwLoaderDataSize, dwLoaderHeadSize, dwDelay, dwSectorNum;
  char loaderCodeName[] = "FlashBoot";
  char loaderDataName[] = "FlashData";
  char loaderHeadName[] = "FlashHead";
  PBYTE loaderCodeBuffer = nullptr;
  PBYTE loaderDataBuffer = nullptr;
  PBYTE loaderHeadBuffer = nullptr;
  PBYTE pIDBData = nullptr;
  unsigned short usFlashDataSec;
  unsigned short usFlashBootSec;
  CRKBoot *pBoot = nullptr;
  signed char index;
  pImage = new CRKImage(szLoader, bRet);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Opening loader failed, exiting upgrade loader!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    goto Exit_UpgradeLoader;
  }

  pBoot = pImage->m_bootObject;
  dev.emDeviceType = pBoot->SupportDevice;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Creating Comm Object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    goto Exit_UpgradeLoader;
  }

  printf("Upgrading loader...\r\n");
  index = pBoot->GetIndexByName(ENTRYLOADER, loaderCodeName);
  if (index == -1) {
    if (g_pLogObject) {
      g_pLogObject->Record("ERROR: %s --> Get LoaderCode Entry failed",
                           __func__);
    }
    goto Exit_UpgradeLoader;
  }
  bRet = pBoot->GetEntryProperty(ENTRYLOADER, index, dwLoaderSize, dwDelay);
  if (!bRet) {
    if (g_pLogObject) {
      g_pLogObject->Record("ERROR: %s --> Get LoaderCode Entry Size failed",
                           __func__);
    }
    goto Exit_UpgradeLoader;
  }

  loaderCodeBuffer = new BYTE[dwLoaderSize];
  memset(loaderCodeBuffer, 0, dwLoaderSize);
  if (!pBoot->GetEntryData(ENTRYLOADER, index, loaderCodeBuffer)) {
    if (g_pLogObject) {
      g_pLogObject->Record("ERROR: %s --> Get LoaderCode Data failed",
                           __func__);
    }
    goto Exit_UpgradeLoader;
  }

  index = pBoot->GetIndexByName(ENTRYLOADER, loaderDataName);
  if (index == -1) {
    if (g_pLogObject) {
      g_pLogObject->Record("ERROR: %s --> Get LoaderData Entry failed",
                           __func__);
    }
    delete[] loaderCodeBuffer;
    return false;
  }

  bRet = pBoot->GetEntryProperty(ENTRYLOADER, index, dwLoaderDataSize, dwDelay);
  if (!bRet) {
    if (g_pLogObject) {
      g_pLogObject->Record("ERROR: %s --> Get LoaderData Entry Size failed",
                           __func__);
    }
    goto Exit_UpgradeLoader;
  }

  loaderDataBuffer = new BYTE[dwLoaderDataSize];
  memset(loaderDataBuffer, 0, dwLoaderDataSize);
  if (!pBoot->GetEntryData(ENTRYLOADER, index, loaderDataBuffer)) {
    if (g_pLogObject) {
      g_pLogObject->Record("ERROR: %s --> Get LoaderData Data failed",
                           __func__);
    }
    goto Exit_UpgradeLoader;
  }

  index = pBoot->GetIndexByName(ENTRYLOADER, loaderHeadName);
  if (index != -1) {
    BYTE capability[8];
    bRet =
        pBoot->GetEntryProperty(ENTRYLOADER, index, dwLoaderHeadSize, dwDelay);
    if (!bRet) {
      if (g_pLogObject) {
        g_pLogObject->Record("ERROR: %s --> Get LoaderHead Entry Size failed",
                             __func__);
      }
      goto Exit_UpgradeLoader;
    }

    loaderHeadBuffer = new BYTE[dwLoaderHeadSize];
    memset(loaderHeadBuffer, 0, dwLoaderHeadSize);
    if (!pBoot->GetEntryData(ENTRYLOADER, index, loaderHeadBuffer)) {
      if (g_pLogObject) {
        g_pLogObject->Record("ERROR: %s --> Get LoaderHead Data failed",
                             __func__);
      }
      goto Exit_UpgradeLoader;
    }

    iRet = pComm->RKU_ReadCapability(capability);
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject) {
        g_pLogObject->Record("ERROR: %s --> read capability failed", __func__);
      }
      goto Exit_UpgradeLoader;
    }
    if ((capability[1] & 1) == 0) {
      if (g_pLogObject) {
        g_pLogObject->Record(
            "ERROR: %s --> device did not support to upgrade the loader",
            __func__);
      }
      ERROR_COLOR_ATTR;
      printf("Device not support to upgrade the loader!");
      NORMAL_COLOR_ATTR;
      printf("\r\n");
      goto Exit_UpgradeLoader;
    }
    bNewIDBlock = true;
  }

  usFlashDataSec = (ALIGN(dwLoaderDataSize, 2048)) / SECTOR_SIZE;
  usFlashBootSec = (ALIGN(dwLoaderSize, 2048)) / SECTOR_SIZE;
  if (bNewIDBlock) {
    usFlashHeadSec = (ALIGN(dwLoaderHeadSize, 2048)) / SECTOR_SIZE;
    dwSectorNum = usFlashHeadSec + usFlashDataSec + usFlashBootSec;
  } else {
    dwSectorNum = 4 + usFlashDataSec + usFlashBootSec;
  }
  pIDBData = new BYTE[dwSectorNum * SECTOR_SIZE];
  if (!pIDBData) {
    ERROR_COLOR_ATTR;
    printf("Allocating memory failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    goto Exit_UpgradeLoader;
  }
  memset(pIDBData, 0, dwSectorNum * SECTOR_SIZE);
  if (bNewIDBlock) {
    if (pBoot->Rc4DisableFlag) {
      unsigned int i;
      // close rc4 encryption
      for (i = 0; i < dwLoaderHeadSize / SECTOR_SIZE; i++) {
        P_RC4(loaderHeadBuffer + SECTOR_SIZE * i, SECTOR_SIZE);
      }
      for (i = 0; i < dwLoaderDataSize / SECTOR_SIZE; i++) {
        P_RC4(loaderDataBuffer + SECTOR_SIZE * i, SECTOR_SIZE);
      }
      for (i = 0; i < dwLoaderSize / SECTOR_SIZE; i++) {
        P_RC4(loaderCodeBuffer + SECTOR_SIZE * i, SECTOR_SIZE);
      }
    }
    memcpy(pIDBData, loaderHeadBuffer, dwLoaderHeadSize);
    memcpy(pIDBData + SECTOR_SIZE * usFlashHeadSec, loaderDataBuffer,
           dwLoaderDataSize);
    memcpy(pIDBData + SECTOR_SIZE * (usFlashHeadSec + usFlashDataSec),
           loaderCodeBuffer, dwLoaderSize);
  } else {
    iRet = MakeIDBlockData(loaderDataBuffer, loaderCodeBuffer, pIDBData,
                           usFlashDataSec, usFlashBootSec, dwLoaderDataSize,
                           dwLoaderSize, pBoot->Rc4DisableFlag);
    if (iRet != 0) {
      ERROR_COLOR_ATTR;
      printf("Making ID block failed!");
      NORMAL_COLOR_ATTR;
      printf("\r\n");
      goto Exit_UpgradeLoader;
    }
  }

  iRet = pComm->RKU_WriteLBA(64, dwSectorNum, pIDBData, RWMETHOD_IMAGE);
  CURSOR_MOVEUP_LINE(1);
  CURSOR_DEL_LINE;
  if (iRet == ERR_SUCCESS) {
    bSuccess = true;
    printf("Upgrading loader succeeded.\r\n");
  } else {
    printf("Upgrading loader failed!\r\n");
  }

Exit_UpgradeLoader:
  delete pImage;
  delete pComm;
  delete[] loaderCodeBuffer;
  delete[] loaderDataBuffer;
  delete[] loaderHeadBuffer;
  delete[] pIDBData;
  return bSuccess;
}

bool print_gpt(STRUCT_RKDEVICE_DESC &dev) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  u8 master_gpt[34 * SECTOR_SIZE];
  auto *gptHead = reinterpret_cast<gpt_header *>(master_gpt + SECTOR_SIZE);
  bool bRet, bSuccess = false;
  int iRet;
  gpt_entry *gptEntry = nullptr;
  u32 i, j;
  u8 zerobuf[GPT_ENTRY_SIZE];
  memset(zerobuf, 0, GPT_ENTRY_SIZE);
  CRKComm *pComm = nullptr;
  char partName[36];
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Creating Comm Object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  iRet = pComm->RKU_ReadLBA(0, 34, master_gpt, RWMETHOD_IMAGE);
  if (ERR_SUCCESS == iRet) {
    if (gptHead->signature != le64_to_cpu(GPT_HEADER_SIGNATURE)) {
      goto Exit_PrintGpt;
    }
  } else {
    if (g_pLogObject)
      g_pLogObject->Record("Error: read gpt failed, err=%d", iRet);
    printf("Read GPT failed!\r\n");
    goto Exit_PrintGpt;
  }

  printf("**********Partition Info(GPT)**********\r\n");
  printf("NO  LBA       Name                \r\n");
  for (i = 0; i < le32_to_cpu(gptHead->num_partition_entries); i++) {
    gptEntry = reinterpret_cast<gpt_entry *>(master_gpt + 2 * SECTOR_SIZE +
                                             i * GPT_ENTRY_SIZE);
    if (memcmp(zerobuf, gptEntry, GPT_ENTRY_SIZE) == 0)
      break;
    memset(partName, 0, 36);
    j = 0;
    while (gptEntry->partition_name[j]) {
      partName[j] = static_cast<char>(gptEntry->partition_name[j]);
      j++;
    }
    printf("%02d  %08X  %s\r\n", i, static_cast<u32>(gptEntry->starting_lba),
           partName);
  }
  bSuccess = true;
Exit_PrintGpt:
  delete pComm;
  return bSuccess;
}

bool print_parameter(STRUCT_RKDEVICE_DESC &dev) {
  u8 param_buf[512 * SECTOR_SIZE];
  bool bRet;
  bool bSuccess = false;
  int iRet;
  uint32_t i;
  uint32_t nParamSize;
  CRKComm *pComm = nullptr;
  PARAM_ITEM_VECTOR vecParamItem;
  CONFIG_ITEM_VECTOR vecUuidItem;

  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM)) {
    return false;
  }
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Creating Comm Object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  iRet = pComm->RKU_ReadLBA(0x2000, 512, param_buf, RWMETHOD_IMAGE);
  if (ERR_SUCCESS == iRet) {
    if (*reinterpret_cast<u32 *>(param_buf) != 0x4D524150) {
      goto Exit_PrintParam;
    }
  } else {
    if (g_pLogObject)
      g_pLogObject->Record("Error: read parameter failed, err=%d", iRet);
    printf("Read parameter failed!\r\n");
    goto Exit_PrintParam;
  }
  nParamSize = *reinterpret_cast<u32 *>(param_buf + 4);
  memset(param_buf + 8 + nParamSize, 0, 512 * SECTOR_SIZE - nParamSize - 8);

  bRet = parse_parameter(reinterpret_cast<char *>(param_buf + 8), vecParamItem, vecUuidItem);
  if (!bRet) {
    if (g_pLogObject) {
      g_pLogObject->Record("Error: parse parameter failed");
    }
    printf("Parse parameter failed!\r\n");
    goto Exit_PrintParam;
  }
  printf("**********Partition Info(parameter)**********\r\n");
  printf("NO  LBA       Name                \r\n");
  for (i = 0; i < vecParamItem.size(); i++) {
    printf("%02d  %08X  %s\r\n", i, vecParamItem[i].uiItemOffset,
           vecParamItem[i].szItemName);
  }
  bSuccess = true;
Exit_PrintParam:
  delete pComm;
  return bSuccess;
}

bool erase_flash(STRUCT_RKDEVICE_DESC &dev) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM)) {
    return false;
  }
  CRKImage *pImage = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  CRKScan *pScan = nullptr;
  pScan = new CRKScan();
  pScan->SetVidPid();

  CRKComm *pComm = nullptr;
  CRKDevice *pDevice = nullptr;

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    delete pScan;
    ERROR_COLOR_ATTR;
    printf("Creating Comm Object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  pDevice = new CRKDevice(dev);
  if (!pDevice) {
    delete pComm;
    delete pScan;
    ERROR_COLOR_ATTR;
    printf("Creating device object failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  pDevice->SetObject(pImage, pComm, g_pLogObject);
  pDevice->CallBackPointer = ProgressInfoProc;

  printf("Starting to erase flash...\r\n");
  bRet = pDevice->GetFlashInfo();
  if (!bRet) {
    delete pDevice;
    delete pScan;
    ERROR_COLOR_ATTR;
    printf("Getting flash info from device failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  iRet = pDevice->EraseAllBlocks();
  delete pDevice;

  if (iRet == 0) {
    if (pScan) {
      pScan->SetVidPid();
      pScan->Wait(dev, RKUSB_MASKROM, dev.usVid, dev.usPid);
      delete pScan;
    }
    CURSOR_MOVEUP_LINE(1);
    CURSOR_DEL_LINE;
    bSuccess = true;
    printf("Erasing flash complete.\r\n");
  }

  return bSuccess;
}

bool test_device(STRUCT_RKDEVICE_DESC &dev) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    iRet = pComm->RKU_TestDeviceReady(nullptr, nullptr, TU_NONE_SUB_CODE);
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject)
        g_pLogObject->Record("Error: RKU_TestDeviceReady failed, err=%d", iRet);
      printf("Test Device failed!\r\n");
    } else {
      bSuccess = true;
      printf("Test Device OK.\r\n");
    }
  } else {
    printf("Test Device quit, creating comm object failed!\r\n");
  }
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool reset_device(STRUCT_RKDEVICE_DESC &dev, BYTE subCode = RST_NONE_SUBCODE) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    iRet = pComm->RKU_ResetDevice(subCode);
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject)
        g_pLogObject->Record("Error: RKU_ResetDevice failed, err=%d", iRet);
      printf("Reset Device failed!\r\n");
    } else {
      bSuccess = true;
      printf("Reset Device OK.\r\n");
    }
  } else {
    printf("Reset Device quit, creating comm object failed!\r\n");
  }
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool read_flash_id(STRUCT_RKDEVICE_DESC &dev) {
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return bSuccess;

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    BYTE flashID[5];
    iRet = pComm->RKU_ReadFlashID(flashID);
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject)
        g_pLogObject->Record("Error: RKU_ReadFlashID failed, err=%d", iRet);
      printf("Reading flash ID failed!\r\n");
    } else {
      printf("Flash ID: %02X %02X %02X %02X %02X\r\n", flashID[0], flashID[1],
             flashID[2], flashID[3], flashID[4]);
      bSuccess = true;
    }
  } else {
    printf("Read Flash ID quit, creating comm object failed!\r\n");
  }
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool read_flash_info(STRUCT_RKDEVICE_DESC &dev) {
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return bSuccess;

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    STRUCT_FLASHINFO_CMD info;
    unsigned int uiRead;
    iRet = pComm->RKU_ReadFlashInfo((BYTE *)&info, &uiRead);
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject)
        g_pLogObject->Record("Error: RKU_ReadFlashInfo failed, err=%d", iRet);
      printf("Read Flash Info failed!\r\n");
    } else {
      printf("Flash Info:\r\n");
      if (info.bManufCode <= 7) {
        printf("\tManufacturer: %s, value=%02X\r\n",
               szManufName[info.bManufCode], info.bManufCode);
      } else
        printf("\tManufacturer: %s, value=%02X\r\n", "Unknown",
               info.bManufCode);

      printf("\tFlash Size: %d MB\r\n", info.uiFlashSize / 2 / 1024);
      printf("\tFlash Size: %d Sectors\r\n", info.uiFlashSize);
      printf("\tBlock Size: %d KB\r\n", info.usBlockSize / 2);
      printf("\tPage Size: %d KB\r\n", info.bPageSize / 2);
      printf("\tECC Bits: %d\r\n", info.bECCBits);
      printf("\tAccess Time: %d\r\n", info.bAccessTime);
      printf("\tFlash CS: ");
      for (int i = 0; i < 8; i++) {
        if (info.bFlashCS & (1 << i))
          printf("Flash<%d> ", i);
      }
      printf("\r\n");
      bSuccess = true;
    }
  } else {
    printf("Read Flash Info quit, creating comm object failed!\r\n");
  }
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool read_chip_info(STRUCT_RKDEVICE_DESC &dev) {
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return bSuccess;

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    BYTE chipInfo[16];
    iRet = pComm->RKU_ReadChipInfo(chipInfo);
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject)
        g_pLogObject->Record("Error: RKU_ReadChipInfo failed, err=%d", iRet);
      printf("Read Chip Info failed!\r\n");
    } else {
      std::string strChipInfo;
      g_pLogObject->PrintBuffer(strChipInfo, chipInfo, 16, 16);
      printf("Chip Info: %s\r\n", strChipInfo.c_str());
      bSuccess = true;
    }
  } else {
    printf("Read Chip Info quit, creating comm object failed!\r\n");
  }
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool read_capability(STRUCT_RKDEVICE_DESC &dev) {
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return bSuccess;

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    BYTE capability[8];
    iRet = pComm->RKU_ReadCapability(capability);
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject)
        g_pLogObject->Record("Error:read_capability failed,err=%d", iRet);
      printf("Read capability Fail!\r\n");
    } else {
      printf("Capability:%02X %02X %02X %02X %02X %02X %02X %02X \r\n",
             capability[0], capability[1], capability[2], capability[3],
             capability[4], capability[5], capability[6], capability[7]);
      if (capability[0] & 1) {
        printf("Direct LBA:\tenabled\r\n");
      }

      if (capability[0] & 2) {
        printf("Vendor Storage:\tenabled\r\n");
      }

      if (capability[0] & 4) {
        printf("First 4m Access:\tenabled\r\n");
      }
      if (capability[0] & 8) {
        printf("Read LBA:\tenabled\r\n");
      }

      if (capability[0] & 20) {
        printf("Read Com Log:\tenabled\r\n");
      }

      if (capability[0] & 40) {
        printf("Read IDB Config:\tenabled\r\n");
      }

      if (capability[0] & 80) {
        printf("Read Secure Mode:\tenabled\r\n");
      }

      if (capability[1] & 1) {
        printf("New IDB:\tenabled\r\n");
      }
      bSuccess = true;
    }
  } else {
    printf("Read capability quit, creating comm object failed!\r\n");
  }
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool read_param(STRUCT_RKDEVICE_DESC &dev, u8 *pParam) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM)) {
    return false;
  }
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    iRet = pComm->RKU_ReadLBA(0x2000, 512, pParam, RWMETHOD_IMAGE);
    if (ERR_SUCCESS == iRet) {
      if (*(u32 *)pParam != 0x4D524150) {
        goto Exit_ReadParam;
      }
    } else {
      if (g_pLogObject)
        g_pLogObject->Record("Error: read parameter failed, err=%d", iRet);
      printf("Read parameter failed!\r\n");
      goto Exit_ReadParam;
    }
    bSuccess = true;
  }
Exit_ReadParam:
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool read_gpt(STRUCT_RKDEVICE_DESC &dev, u8 *pGpt) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  auto *gptHead = (gpt_header *)(pGpt + SECTOR_SIZE);
  CRKUsbComm *pComm = nullptr;
  bool bRet, bSuccess = false;
  int iRet;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    iRet = pComm->RKU_ReadLBA(0, 34, pGpt, RWMETHOD_IMAGE);
    if (ERR_SUCCESS == iRet) {
      if (gptHead->signature != le64_to_cpu(GPT_HEADER_SIGNATURE)) {
        goto Exit_ReadGPT;
      }
    } else {
      if (g_pLogObject)
        g_pLogObject->Record("Error: read gpt failed, err=%d", iRet);
      printf("Read GPT failed!\r\n");
      goto Exit_ReadGPT;
    }
    bSuccess = true;
  }
Exit_ReadGPT:
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  return bSuccess;
}

bool read_lba(STRUCT_RKDEVICE_DESC &dev, unsigned int uiBegin, unsigned int uiLen,
              char *szFile) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  CRKUsbComm *pComm = nullptr;
  FILE *file = nullptr;
  bool bRet, bFirst = true, bSuccess = false;
  int iRet;
  unsigned int iTotalRead = 0, iRead = 0;
  int nSectorSize = 512;
  BYTE pBuf[nSectorSize * DEFAULT_RW_LBA];
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    if (szFile) {
      file = fopen(szFile, "wb+");
      if (!file) {
        printf("Read LBA failed, err=%d, can't open file: %s\r\n", errno,
               szFile);
        goto Exit_ReadLBA;
      }
    }

    while (uiLen > 0) {
      memset(pBuf, 0, nSectorSize * DEFAULT_RW_LBA);
      iRead = (uiLen >= DEFAULT_RW_LBA) ? DEFAULT_RW_LBA : uiLen;
      iRet =
          pComm->RKU_ReadLBA(uiBegin + iTotalRead, iRead, pBuf, RWMETHOD_IMAGE);
      if (ERR_SUCCESS == iRet) {
        uiLen -= iRead;
        iTotalRead += iRead;

        if (szFile) {
          fwrite(pBuf, 1, iRead * nSectorSize, file);
          if (bFirst) {
            if (iTotalRead >= 1024)
              printf("Read LBA to file (%d%%)\r\n",
                     (iTotalRead / 1024) * 100 / ((uiLen + iTotalRead) / 1024));
            else
              printf("Read LBA to file (%d%%)\r\n",
                     iTotalRead * 100 / (uiLen + iTotalRead));
            bFirst = false;
          } else {
            CURSOR_MOVEUP_LINE(1);
            CURSOR_DEL_LINE;
            if (iTotalRead >= 1024)
              printf("Read LBA to file (%d%%)\r\n",
                     (iTotalRead / 1024) * 100 / ((uiLen + iTotalRead) / 1024));
            else
              printf("Read LBA to file (%d%%)\r\n",
                     iTotalRead * 100 / (uiLen + iTotalRead));
          }
        } else
          PrintData(pBuf, nSectorSize * iRead);
      } else {
        if (g_pLogObject)
          g_pLogObject->Record("Error: RKU_ReadLBA failed, err=%d", iRet);

        printf("Read LBA failed!\r\n");
        goto Exit_ReadLBA;
      }
    }
    bSuccess = true;
  } else {
    printf("Read LBA quit, creating comm object failed!\r\n");
  }
Exit_ReadLBA:
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  if (file)
    fclose(file);
  return bSuccess;
}

bool erase_ubi_block(STRUCT_RKDEVICE_DESC &dev, u32 uiOffset, u32 uiPartSize) {
  STRUCT_FLASHINFO_CMD info;
  CRKComm *pComm = nullptr;
  BYTE flashID[5];
  bool bRet, bSuccess = false;
  unsigned int uiReadCount;
  unsigned int uiStartBlock;
  unsigned int uiEraseBlock;
  unsigned int uiBlockCount;
  unsigned int uiErasePos;
  int iRet;
  const unsigned int *pID = nullptr;

  printf("Erase ubi in, offset=0x%08x,size=0x%08x!\r\n", uiOffset, uiPartSize);
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (!bRet) {
    printf("Erase ubi quit, creating comm object failed!\r\n");
    goto EXIT_UBI_ERASE;
  }
  iRet = pComm->RKU_ReadFlashID(flashID);
  if (iRet != ERR_SUCCESS) {
    if (g_pLogObject) {
      g_pLogObject->Record(
          "Error:EraseUBIBlock-->RKU_ReadFlashID failed,RetCode(%d)", iRet);
    }
    goto EXIT_UBI_ERASE;
  }
  pID = reinterpret_cast<unsigned int *>(flashID);

  if (*pID == 0x434d4d45) // eMMC
  {
    bSuccess = true;
    goto EXIT_UBI_ERASE;
  }

  iRet =
      pComm->RKU_ReadFlashInfo(reinterpret_cast<BYTE *>(&info), &uiReadCount);
  if (iRet != ERR_SUCCESS) {
    if (g_pLogObject) {
      g_pLogObject->Record("Error:EraseUBIBlock-->RKU_ReadFlashInfo err=%d",
                           iRet);
    }
    goto EXIT_UBI_ERASE;
  }
  if (uiPartSize == 0xFFFFFFFF)
    uiPartSize = info.uiFlashSize - uiOffset;

  uiStartBlock = uiOffset / info.usBlockSize;
  uiEraseBlock = (uiPartSize + info.usBlockSize - 1) / info.usBlockSize;

  printf("Erase block start, offset=0x%08x,count=0x%08x!\r\n", uiStartBlock,
         uiEraseBlock);
  uiErasePos = uiStartBlock;
  while (uiEraseBlock > 0) {
    uiBlockCount =
        (uiEraseBlock < MAX_ERASE_BLOCKS) ? uiEraseBlock : MAX_ERASE_BLOCKS;

    iRet = pComm->RKU_EraseBlock(0, uiErasePos, uiBlockCount, ERASE_FORCE);
    if ((iRet != ERR_SUCCESS) && (iRet != ERR_FOUND_BAD_BLOCK)) {
      if (g_pLogObject) {
        g_pLogObject->Record(
            "Error:EraseUBIBlock-->RKU_EraseBlock failed,RetCode(%d)", iRet);
      }
      goto EXIT_UBI_ERASE;
    }

    uiErasePos += uiBlockCount;
    uiEraseBlock -= uiBlockCount;
  }
  bSuccess = true;
EXIT_UBI_ERASE:
  delete pComm;
  return bSuccess;
}

bool erase_partition(CRKUsbComm *pComm, unsigned int uiOffset, unsigned int uiSize) {
  constexpr unsigned int uiErase = 1024 * 32;
  bool bSuccess = true;
  int iRet;
  while (uiSize) {
    if (uiSize >= uiErase) {
      iRet = pComm->RKU_EraseLBA(uiOffset, uiErase);
      uiSize -= uiErase;
      uiOffset += uiErase;
    } else {
      iRet = pComm->RKU_EraseLBA(uiOffset, uiSize);
      uiSize = 0;
      uiOffset += uiSize;
    }
    if (iRet != ERR_SUCCESS) {
      if (g_pLogObject) {
        g_pLogObject->Record("ERROR:erase_partition failed,err=%d", iRet);
      }
      bSuccess = false;
      break;
    }
  }
  return bSuccess;
}

bool EatSparseChunk(FILE *file, chunk_header &chunk) {
  if (const unsigned int uiRead = fread(&chunk, 1, sizeof(chunk_header), file);
      uiRead != sizeof(chunk_header)) {
    if (g_pLogObject) {
      g_pLogObject->Record("Error:EatSparseChunk failed,err=%d", errno);
    }
    return false;
  }
  return true;
}

bool EatSparseData(FILE *file, PBYTE pBuf, const unsigned int dwSize) {
  if (const unsigned int uiRead = fread(pBuf, 1, dwSize, file); uiRead != dwSize) {
    if (g_pLogObject) {
      g_pLogObject->Record("Error:EatSparseData failed,err=%d", errno);
    }
    return false;
  }
  return true;
}

bool write_sparse_lba(STRUCT_RKDEVICE_DESC &dev, unsigned int uiBegin, unsigned int uiSize,
                      char *szFile) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  CRKUsbComm *pComm = nullptr;
  FILE *file = nullptr;
  bool bRet, bSuccess = false;
  unsigned int dwFillByte, dwCrc;
  sparse_header header;
  constexpr unsigned int dwMaxReadWriteBytes = DEFAULT_RW_LBA * SECTOR_SIZE;
  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    u64 iTotalWrite = 0;
    u64 iFileSize = 0;
    u64 dwChunkDataSize;
    bool bFirst = true;
    int iRet;
    unsigned int uiTransferSec;
    unsigned int iRead = 0;
    unsigned int dwTransferBytes;
    chunk_header chunk;
    file = fopen(szFile, "rb");
    if (!file) {
      printf("%s failed, err=%d, can't open file: %s\r\n", __func__, errno,
             szFile);
      goto Exit_WriteSparseLBA;
    }
    fseeko(file, 0, SEEK_SET);
    iRead = fread(&header, 1, sizeof(header), file);
    if (iRead != sizeof(sparse_header)) {
      if (g_pLogObject) {
        g_pLogObject->Record(
            "ERROR:%s-->read sparse header failed,file=%s,err=%d", __func__,
            szFile, errno);
      }
      goto Exit_WriteSparseLBA;
    }
    iFileSize = header.blk_sz * static_cast<u64>(header.total_blks);
    iTotalWrite = 0;
    unsigned int curChunk = 0;
    if (uiSize == static_cast<u32>(-1))
      uiSize = ALIGN(iFileSize, SECTOR_SIZE);
    bRet = erase_partition(pComm, uiBegin, uiSize);
    if (!bRet) {
      printf("%s failed, erase partition error\r\n", __func__);
      goto Exit_WriteSparseLBA;
    }
    while (curChunk < header.total_chunks) {
      BYTE pBuf[SECTOR_SIZE * DEFAULT_RW_LBA];
      if (!EatSparseChunk(file, chunk)) {
        goto Exit_WriteSparseLBA;
      }
      curChunk++;
      switch (chunk.chunk_type) {
      case CHUNK_TYPE_RAW:
        dwChunkDataSize = chunk.total_sz - sizeof(chunk_header);
        while (dwChunkDataSize) {
          memset(pBuf, 0, dwMaxReadWriteBytes);
          if (dwChunkDataSize >= dwMaxReadWriteBytes) {
            dwTransferBytes = dwMaxReadWriteBytes;
            uiTransferSec = DEFAULT_RW_LBA;
          } else {
            dwTransferBytes = dwChunkDataSize;
            uiTransferSec = ((dwTransferBytes % SECTOR_SIZE == 0)
                                 ? (dwTransferBytes / SECTOR_SIZE)
                                 : (dwTransferBytes / SECTOR_SIZE + 1));
          }
          if (!EatSparseData(file, pBuf, dwTransferBytes)) {
            goto Exit_WriteSparseLBA;
          }
          iRet =
              pComm->RKU_WriteLBA(uiBegin, uiTransferSec, pBuf, RWMETHOD_IMAGE);
          if (ERR_SUCCESS == iRet) {
            dwChunkDataSize -= dwTransferBytes;
            iTotalWrite += dwTransferBytes;
            uiBegin += uiTransferSec;
          } else {
            if (g_pLogObject) {
              g_pLogObject->Record(
                  "ERROR:%s-->RKU_WriteLBA failed,Written(%d),RetCode(%d)",
                  __func__, iTotalWrite, iRet);
            }
            goto Exit_WriteSparseLBA;
          }
          if (bFirst) {
            if (iTotalWrite >= 1024)
              printf("Write LBA from file (%lld%%)\r\n",
                     (iTotalWrite / 1024) * 100 / (iFileSize / 1024));
            else
              printf("Write LBA from file (%lld%%)\r\n",
                     iTotalWrite * 100 / iFileSize);
            bFirst = false;
          } else {
            CURSOR_MOVEUP_LINE(1);
            CURSOR_DEL_LINE;
            printf("Write LBA from file (%lld%%)\r\n",
                   (iTotalWrite / 1024) * 100 / (iFileSize / 1024));
          }
        }
        break;
      case CHUNK_TYPE_FILL:
        dwChunkDataSize = static_cast<u64>(chunk.chunk_sz) * header.blk_sz;
        if (!EatSparseData(file, reinterpret_cast<PBYTE>(&dwFillByte), 4)) {
          goto Exit_WriteSparseLBA;
        }
        while (dwChunkDataSize) {
          memset(pBuf, 0, dwMaxReadWriteBytes);
          if (dwChunkDataSize >= dwMaxReadWriteBytes) {
            dwTransferBytes = dwMaxReadWriteBytes;
            uiTransferSec = DEFAULT_RW_LBA;
          } else {
            dwTransferBytes = dwChunkDataSize;
            uiTransferSec = dwTransferBytes % SECTOR_SIZE == 0
                                ? dwTransferBytes / SECTOR_SIZE
                                : dwTransferBytes / SECTOR_SIZE + 1;
          }
          for (unsigned int i = 0; i < dwTransferBytes / 4; i++) {
            *reinterpret_cast<unsigned int *>(pBuf + i * 4) = dwFillByte;
          }
          iRet =
              pComm->RKU_WriteLBA(uiBegin, uiTransferSec, pBuf, RWMETHOD_IMAGE);
          if (ERR_SUCCESS == iRet) {
            dwChunkDataSize -= dwTransferBytes;
            iTotalWrite += dwTransferBytes;
            uiBegin += uiTransferSec;
          } else {
            if (g_pLogObject) {
              g_pLogObject->Record(
                  "ERROR:%s-->RKU_WriteLBA failed,Written(%d),RetCode(%d)",
                  __func__, iTotalWrite, iRet);
            }
            goto Exit_WriteSparseLBA;
          }
          if (bFirst) {
            if (iTotalWrite >= 1024)
              printf("Write LBA from file (%lld%%)\r\n",
                     (iTotalWrite / 1024) * 100 / (iFileSize / 1024));
            else
              printf("Write LBA from file (%lld%%)\r\n",
                     iTotalWrite * 100 / iFileSize);
            bFirst = false;
          } else {
            CURSOR_MOVEUP_LINE(1);
            CURSOR_DEL_LINE;
            printf("Write LBA from file (%lld%%)\r\n",
                   iTotalWrite / 1024 * 100 / (iFileSize / 1024));
          }
        }
        break;
      case CHUNK_TYPE_DONT_CARE:
        dwChunkDataSize = static_cast<u64>(chunk.chunk_sz) * header.blk_sz;
        iTotalWrite += dwChunkDataSize;
        uiTransferSec = dwChunkDataSize % SECTOR_SIZE == 0
                            ? dwChunkDataSize / SECTOR_SIZE
                            : dwChunkDataSize / SECTOR_SIZE + 1;
        uiBegin += uiTransferSec;
        if (bFirst) {
          if (iTotalWrite >= 1024) {
            printf("Write LBA from file (%lld%%)\r\n",
                   (iTotalWrite / 1024) * 100 / (iFileSize / 1024));
          } else {
            printf("Write LBA from file (%lld%%)\r\n",
                   iTotalWrite * 100 / iFileSize);
          }
          bFirst = false;
        } else {
          CURSOR_MOVEUP_LINE(1);
          CURSOR_DEL_LINE;
          printf("Write LBA from file (%lld%%)\r\n",
                 (iTotalWrite / 1024) * 100 / (iFileSize / 1024));
        }
        break;
      case CHUNK_TYPE_CRC32:
        EatSparseData(file, reinterpret_cast<PBYTE>(&dwCrc), 4);
        break;
      default:;
      }
    }
    bSuccess = true;
  } else {
    printf("Write LBA quit, creating comm object failed!\r\n");
  }
Exit_WriteSparseLBA:
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  if (file) {
    fclose(file);
  }
  return bSuccess;
}

bool write_lba(STRUCT_RKDEVICE_DESC &dev, unsigned int uiBegin, char *szFile) {
  if (!check_device_type(dev, RKUSB_LOADER | RKUSB_MASKROM))
    return false;
  CRKUsbComm *pComm = nullptr;
  FILE *file = nullptr;
  bool bRet, bSuccess = false;

  pComm = new CRKUsbComm(dev, g_pLogObject, bRet);
  if (bRet) {
    bool bFirst = true;
    unsigned int iWrite = 0;
    long long iFileSize = 0;
    long long iTotalWrite = 0;
    file = fopen(szFile, "rb");
    if (!file) {
      printf("Write LBA failed, err=%d, can't open file: %s\r\n", errno,
             szFile);
      goto Exit_WriteLBA;
    }

    int iRet = fseeko(file, 0, SEEK_END);
    iFileSize = ftello(file);
    fseeko(file, 0, SEEK_SET);
    while (iTotalWrite < iFileSize) {
      constexpr int nSectorSize = 512;
      BYTE pBuf[nSectorSize * DEFAULT_RW_LBA] = {};
      iWrite = fread(pBuf, 1, nSectorSize * DEFAULT_RW_LBA, file);
      const unsigned int uiLen =
          ((iWrite % 512) == 0) ? (iWrite / 512) : (iWrite / 512 + 1);
      iRet = pComm->RKU_WriteLBA(uiBegin, uiLen, pBuf, RWMETHOD_IMAGE);
      if (ERR_SUCCESS == iRet) {
        uiBegin += uiLen;
        iTotalWrite += iWrite;
        if (bFirst) {
          if (iTotalWrite >= 1024)
            printf("Write LBA from file (%lld%%)\r\n",
                   (iTotalWrite / 1024) * 100 / (iFileSize / 1024));
          else
            printf("Write LBA from file (%lld%%)\r\n",
                   iTotalWrite * 100 / iFileSize);
          bFirst = false;
        } else {
          CURSOR_MOVEUP_LINE(1);
          CURSOR_DEL_LINE;
          printf("Write LBA from file (%lld%%)\r\n",
                 (iTotalWrite / 1024) * 100 / (iFileSize / 1024));
        }
      } else {
        if (g_pLogObject)
          g_pLogObject->Record("Error: RKU_WriteLBA failed, err=%d", iRet);

        printf("Write LBA failed!\r\n");
        goto Exit_WriteLBA;
      }
    }
    bSuccess = true;
  } else {
    printf("Write LBA quit, creating comm object failed!\r\n");
  }
Exit_WriteLBA:
  if (pComm) {
    delete pComm;
    pComm = nullptr;
  }
  if (file)
    fclose(file);
  return bSuccess;
}

void split_item(STRING_VECTOR &vecItems, char *pszItems) {
  std::string strItem;
  char szItem[100];
  char *pos = nullptr, *pStart;
  pStart = pszItems;
  pos = strchr(pStart, ',');
  while (pos != nullptr) {
    memset(szItem, 0, sizeof(szItem));
    strncpy(szItem, pStart, pos - pStart);
    strItem = szItem;
    vecItems.push_back(strItem);
    pStart = pos + 1;
    if (*pStart == 0)
      break;
    pos = strchr(pStart, ',');
  }
  if (strlen(pStart) > 0) {
    memset(szItem, 0, sizeof(szItem));
    strncpy(szItem, pStart, sizeof(szItem) - 1);
    strItem = szItem;
    vecItems.push_back(strItem);
  }
}

void tag_spl(const char *tag, const char *spl) {
  FILE *file = nullptr;

  if (!tag || !spl) {
    return;
  }
  size_t len = strlen(tag);
  printf("tag len=%lu\n", len);
  file = fopen(spl, "rb");
  if (!file) {
    return;
  }
  fseek(file, 0, SEEK_END);
  const long iFileSize = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *Buf = nullptr;
  Buf = new char[iFileSize + len + 1];
  if (!Buf) {
    fclose(file);
    return;
  }
  memset(Buf, 0, iFileSize + 1);
  memcpy(Buf, tag, len);
  if (const size_t iRead = fread(Buf + len, 1, iFileSize, file);
      iRead != iFileSize) {
    fclose(file);
    delete[] Buf;
    return;
  }
  fclose(file);

  len = strlen(spl);
  auto taggedspl = new char[len + 5];
  strcpy(taggedspl, spl);
  strcpy(taggedspl + len, ".tag");
  taggedspl[len + 4] = 0;
  printf("Writing tagged spl to %s\n", taggedspl);

  file = fopen(taggedspl, "wb");
  if (!file) {
    delete[] taggedspl;
    delete[] Buf;
    return;
  }
  fwrite(Buf, 1, iFileSize + len, file);
  fclose(file);
  delete[] taggedspl;
  delete[] Buf;
  printf("done\n");
}

void list_device(CRKScan *pScan) {
  STRUCT_RKDEVICE_DESC desc;
  std::string strDevType;
  const int cnt = pScan->DEVICE_COUNTS;
  if (cnt == 0) {
    printf("not found any devices!\r\n");
    return;
  }
  for (int i = 0; i < cnt; i++) {
    pScan->GetDevice(desc, i);
    if (desc.emUsbType == RKUSB_MASKROM)
      strDevType = "Maskrom";
    else if (desc.emUsbType == RKUSB_LOADER)
      strDevType = "Loader";
    else
      strDevType = "Unknown";
    printf("DevNo=%d\tVid=0x%x,Pid=0x%x,LocationID=%x\t%s\r\n", i + 1,
           desc.usVid, desc.usPid, desc.uiLocationID, strDevType.c_str());
  }
}

bool handle_command(int argc, char *argv[], CRKScan *pScan) {
  std::string strCmd;
  strCmd = argv[1];
  ssize_t cnt;
  bool bRet, bSuccess = false;
  char *s;
  int i;
  STRUCT_RKDEVICE_DESC dev;
  u64 lba, lba_end;
  u32 part_size, part_offset;

  std::transform(strCmd.begin(), strCmd.end(), strCmd.begin(),
            static_cast<int (*)(int)>(toupper));
  s = const_cast<char *>(strCmd.c_str());
  for (i = 0; i < static_cast<int>(strlen(s)); i++)
    s[i] = static_cast<char>(toupper(s[i]));

  if ((strcmp(strCmd.c_str(), "-H") == 0) ||
      (strcmp(strCmd.c_str(), "--HELP")) == 0) {
    usage();
    return true;
  }
  if ((strcmp(strCmd.c_str(), "-V") == 0) ||
             (strcmp(strCmd.c_str(), "--VERSION") == 0)) {
    printf("rkdeveloptool ver %s\r\n", PACKAGE_VERSION);
    return true;
  }
  if (strcmp(strCmd.c_str(), "PACK") == 0) {
    // pack boot loader
    mergeBoot();
    return true;
  }
  if (strcmp(strCmd.c_str(), "UNPACK") == 0) {
    // unpack boot loader
    std::string strLoader = argv[2];
    unpackBoot((char *)strLoader.c_str());
    return true;
  }
  if (strcmp(strCmd.c_str(), "TAGSPL") == 0) {
    // tag u-boot spl
    if (argc == 4) {
      std::string tag = argv[2];
      std::string spl = argv[3];
      printf("tag %s to %s\n", tag.c_str(), spl.c_str());
      tag_spl(tag.c_str(), spl.c_str());
      return true;
    }
    printf("tagspl: parameter error\n");
    usage();
  }
  cnt = pScan->Search(RKUSB_MASKROM | RKUSB_LOADER);
  if (strcmp(strCmd.c_str(), "LD") == 0) {
    list_device(pScan);
    return (cnt > 0) ? true : false;
  }

  if (cnt < 1) {
    ERROR_COLOR_ATTR;
    printf("Did not find any rockusb device, please plug device in!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }
  if (cnt > 1) {
    ERROR_COLOR_ATTR;
    printf("Found too many rockusb devices, please plug devices out!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  bRet = pScan->GetDevice(dev, 0);
  if (!bRet) {
    ERROR_COLOR_ATTR;
    printf("Getting information about rockusb device failed!");
    NORMAL_COLOR_ATTR;
    printf("\r\n");
    return bSuccess;
  }

  if (strcmp(strCmd.c_str(), "RD") == 0) {
    if (argc != 2 && argc != 3)
      printf("Parameter of [RD] command is invalid, please check help!\r\n");
    else {
      if (argc == 2)
        bSuccess = reset_device(dev);
      else {
        unsigned int uiSubCode;
        char *pszEnd;
        uiSubCode = strtoul(argv[2], &pszEnd, 0);
        if (*pszEnd) {
          printf("Subcode is invalid, please check!\r\n");
        } else {
          if (uiSubCode <= 5) {
            bSuccess = reset_device(dev, uiSubCode);
          } else {
            printf("Subcode is invalid, please check!\r\n");
          }
        }
      }
    }
  } else if (strcmp(strCmd.c_str(), "TD") == 0) {
    bSuccess = test_device(dev);
  } else if (strcmp(strCmd.c_str(), "RID") == 0) {
    // Read Flash ID
    bSuccess = read_flash_id(dev);
  } else if (strcmp(strCmd.c_str(), "RFI") == 0) {
    // Read Flash Info
    bSuccess = read_flash_info(dev);
  } else if (strcmp(strCmd.c_str(), "RCI") == 0) {
    // Read Chip Info
    bSuccess = read_chip_info(dev);
  } else if (strcmp(strCmd.c_str(), "RCB") == 0) {
    // Read Capability
    bSuccess = read_capability(dev);
  } else if (strcmp(strCmd.c_str(), "DB") == 0) {
    if (argc > 2) {
      std::string strLoader;
      strLoader = argv[2];
      bSuccess = download_boot(dev, strLoader.c_str());
    } else if (argc == 2) {
      if (auto ret = find_config_item(g_ConfigItemVec, "loader"); ret == -1) {
        printf("Did not find loader item in config!\r\n");
      } else {
        bSuccess = download_boot(dev, g_ConfigItemVec[ret].szItemValue);
      }
    } else {
      printf("Parameter of [DB] command is invalid, please check help!\r\n");
    }
  } else if (strcmp(strCmd.c_str(), "GPT") == 0) {
    if (argc > 2) {
      std::string strParameter;
      strParameter = argv[2];
      bSuccess = write_gpt(dev, const_cast<char *>(strParameter.c_str()));
    } else {
      printf("Parameter of [GPT] command is invalid, please check help!\r\n");
    }
  } else if (strcmp(strCmd.c_str(), "PRM") == 0) {
    if (argc > 2) {
      std::string strParameter;
      strParameter = argv[2];
      bSuccess = write_parameter(dev, const_cast<char *>(strParameter.c_str()));
    } else {
      printf("Parameter of [PRM] command is invalid, please check help!\r\n");
    }
  } else if (strcmp(strCmd.c_str(), "UL") == 0) {
    if (argc > 2) {
      std::string strLoader;
      strLoader = argv[2];
      bSuccess = upgrade_loader(dev, strLoader.c_str());
    } else {
      printf("Parameter of [UL] command is invalid, please check help!\r\n");
    }
  } else if (strcmp(strCmd.c_str(), "EF") == 0) {
    if (argc == 2) {
      bSuccess = erase_flash(dev);
    } else {
      printf("Parameter of [EF] command is invalid, please check help!\r\n");
    }
  } else if (strcmp(strCmd.c_str(), "WL") == 0) {
    if (argc == 4) {
      unsigned int uiBegin;
      char *pszEnd;
      uiBegin = strtoul(argv[2], &pszEnd, 0);
      if (*pszEnd)
        printf("Begin is invalid, please check!\r\n");
      else {
        if (is_sparse_image(argv[3]))
          bSuccess = write_sparse_lba(dev, uiBegin, (u32)-1, argv[3]);
        else {
          bSuccess = true;
          if (is_ubifs_image(argv[3]))
            bSuccess = erase_ubi_block(dev, uiBegin, (u32)-1);
          if (bSuccess)
            bSuccess = write_lba(dev, uiBegin, argv[3]);
          else
            printf("Failure of Erase for writing ubi image!\r\n");
        }
      }
    } else
      printf("Parameter of [WL] command is invalid, please check help!\r\n");
  } else if (strcmp(strCmd.c_str(), "WLX") == 0) {
    if (argc == 4) {
      u8 master_gpt[34 * SECTOR_SIZE];
      bRet = read_gpt(dev, master_gpt);
      if (bRet) {
        bRet = get_lba_from_gpt(master_gpt, argv[2], &lba, &lba_end);
        if (bRet) {
          if (is_sparse_image(argv[3]))
            bSuccess =
                write_sparse_lba(dev, static_cast<u32>(lba),
                                 static_cast<u32>(lba_end - lba + 1), argv[3]);
          else {
            bSuccess = true;
            if (is_ubifs_image(argv[3])) {
              if (lba_end == 0xFFFFFFFF)
                bSuccess = erase_ubi_block(dev, static_cast<u32>(lba),
                                           static_cast<u32>(lba_end));
              else
                bSuccess = erase_ubi_block(dev, static_cast<u32>(lba),
                                           static_cast<u32>(lba_end - lba + 1));
            }
            if (bSuccess) {
              bSuccess = write_lba(dev, static_cast<u32>(lba), argv[3]);
            } else {
              printf("Failure of Erase for writing ubi image!\r\n");
            }
          }
        } else
          printf("No found %s partition\r\n", argv[2]);
      } else {
        u8 param_buffer[512 * SECTOR_SIZE];
        bRet = read_param(dev, param_buffer);
        if (bRet) {
          bRet = get_lba_from_param(param_buffer + 8, argv[2], &part_offset,
                                    &part_size);
          if (bRet) {
            if (is_sparse_image(argv[3]))
              bSuccess = write_sparse_lba(dev, part_offset, part_size, argv[3]);
            else {
              bSuccess = true;
              if (is_ubifs_image(argv[3]))
                bSuccess = erase_ubi_block(dev, part_offset, part_size);
              if (bSuccess)
                bSuccess = write_lba(dev, part_offset, argv[3]);
              else
                printf("Failure of Erase for writing ubi image!\r\n");
            }
          } else
            printf("No found %s partition\r\n", argv[2]);
        } else
          printf("Not found any partition table!\r\n");
      }
    } else
      printf("Parameter of [WLX] command is invalid, please check help!\r\n");
  } else if (strcmp(strCmd.c_str(), "RL") == 0) {
    // Read LBA
    char *pszEnd;
    unsigned int uiBegin, uiLen;
    if (argc != 5)
      printf("Parameter of [RL] command is invalid, please check help!\r\n");
    else {
      uiBegin = strtoul(argv[2], &pszEnd, 0);
      if (*pszEnd)
        printf("Begin is invalid, please check!\r\n");
      else {
        uiLen = strtoul(argv[3], &pszEnd, 0);
        if (*pszEnd)
          printf("Len is invalid, please check!\r\n");
        else {
          bSuccess = read_lba(dev, uiBegin, uiLen, argv[4]);
        }
      }
    }
  } else if (strcmp(strCmd.c_str(), "PPT") == 0) {
    if (argc == 2) {
      bSuccess = print_gpt(dev);
      if (!bSuccess) {
        bSuccess = print_parameter(dev);
        if (!bSuccess)
          printf("Not found any partition table!\r\n");
      }
    } else
      printf("Parameter of [PPT] command is invalid, please check help!\r\n");
  } else {
    printf("command is invalid!\r\n");
    usage();
  }
  return bSuccess;
}

int main(int argc, char *argv[]) {
  CRKScan *pScan = nullptr;
  char szProgramProcPath[100];
  char szProgramDir[256];
  struct stat statBuf {};

  g_ConfigItemVec.clear();
  sprintf(szProgramProcPath, "/proc/%d/exe", getpid());
  if (readlink(szProgramProcPath, szProgramDir, 256) == -1)
    strcpy(szProgramDir, ".");
  else {
    if (char *pSlash = strrchr(szProgramDir, '/')) {
      *pSlash = '\0';
    }
  }
  std::string strLogDir = szProgramDir;
  strLogDir += "/log/";
  std::string strConfigFile = szProgramDir;
  strConfigFile += "/config.ini";
  if (opendir(strLogDir.c_str()) == nullptr) {
    mkdir(strLogDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH);
  }
  g_pLogObject = new CRKLog(strLogDir, "log", true);

  if (stat(strConfigFile.c_str(), &statBuf) < 0) {
    if (g_pLogObject) {
      g_pLogObject->Record("Error: failed to stat config.ini, err=%d", errno);
    }
  } else if (S_ISREG(statBuf.st_mode)) {
    parse_config_file(strConfigFile.c_str(), g_ConfigItemVec);
  }

  if (const int ret = libusb_init(nullptr); ret < 0) {
    if (g_pLogObject) {
      g_pLogObject->Record("Error: libusb_init failed, err=%d", ret);
      delete g_pLogObject;
    }
    return -1;
  }

  pScan = new CRKScan();
  if (!pScan) {
    if (g_pLogObject) {
      g_pLogObject->Record(
          "Error: failed to create object for searching device");
      delete g_pLogObject;
    }
    libusb_exit(nullptr);
    return -2;
  }
  pScan->SetVidPid();

  if (argc == 1) {
    usage();
  } else if (!handle_command(argc, argv, pScan)) {
    return -0xFF;
  }
  delete pScan;
  delete g_pLogObject;
  libusb_exit(nullptr);
  return 0;
}
