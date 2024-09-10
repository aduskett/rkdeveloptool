/*
 * (C) Copyright 2017 Fuzhou Rockchip Electronics Co., Ltd
 * Seth Liu 2017.03.01
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */
#include "inc/RKLog.h"

int file_stat(const std::string& strPath) {
	struct stat statBuf{};
	int ret = stat(strPath.c_str(), &statBuf);
	if (ret != 0) {
		return STAT_NOT_EXIST;
	}
	if (S_ISDIR(statBuf.st_mode))
		return STAT_DIR;
	return STAT_FILE;
}

std::string CRKLog::GetLogSavePath() {
	return m_path;
}

bool CRKLog::GetEnableLog() {
	return m_enable;
}

void CRKLog::SetEnableLog(const bool bEnable) {
	m_enable = bEnable;
}

CRKLog::CRKLog(std::string logFilePath, const std::string& logFileName, const bool enable) {
	LogSavePath.setContainer(this);
	LogSavePath.getter(&CRKLog::GetLogSavePath);

	EnableLog.setContainer(this);
	EnableLog.getter(&CRKLog::GetEnableLog);
	EnableLog.setter(&CRKLog::SetEnableLog);

	if (!opendir(logFilePath.c_str())) {
		m_path = "";
	} else {
		if (logFilePath[logFilePath.size() - 1] != '/') {
			logFilePath += '/';
		}
		m_path = logFilePath;
	}
	if (logFileName.empty()) {
		m_name = "Log";
	} else
		m_name = logFileName;
	m_enable = enable;
}

CRKLog::~CRKLog() = default;

void CRKLog::Record(const char *lpFmt, ...) {
	/************************* �������־ ***********************/
	char szBuf[1024] = "";
	GET_FMT_STRING(lpFmt, szBuf);
	if (m_enable && !m_path.empty()) {
		Write(szBuf);
	}
}

bool CRKLog::Write(std::string text) {
	time_t now;
	tm timeNow{};
	char szDateTime[100];
	std::string strName;
	FILE *file = nullptr;
	time(&now);
	localtime_r(&now, &timeNow);
	sprintf(szDateTime, "%04d-%02d-%02d.txt", timeNow.tm_year + 1900, timeNow.tm_mon + 1, timeNow.tm_mday);
	strName = m_path + m_name + szDateTime;

	try {
		file = fopen(strName.c_str(), "ab+");
		if (!file) {
			return false;
		}
		sprintf(szDateTime, "%02d:%02d:%02d \t", timeNow.tm_hour, timeNow.tm_min, timeNow.tm_sec);
		text = szDateTime + text + "\r\n";
		fwrite(text.c_str(), 1, text.size() * sizeof(char), file);
		fclose(file);
	} catch (...) {
		fclose(file);
		return false;
	}
	return true;
}

bool CRKLog::SaveBuffer(const std::string& fileName, PBYTE lpBuffer, const unsigned int dwSize) {
	FILE *file = fopen(fileName.c_str(), "wb+");
	if (!file) {
		return false;
	}
	fwrite(lpBuffer, 1, dwSize, file);
	fclose(file);
	return true;
}

void CRKLog::PrintBuffer(std::string &strOutput, PBYTE lpBuffer, const unsigned int dwSize, const unsigned int uiLineCount) {
	unsigned int i, count;
	strOutput = "";
	for (i = 0, count = 0; i < dwSize; i++, count++) {
		char strHex[32];
		sprintf(strHex, "%X", lpBuffer[i]);
		strOutput = strOutput + " " + strHex;
		if (count >= uiLineCount) {
			strOutput += "\r\n";
			count = 0;
		}
	}
}
