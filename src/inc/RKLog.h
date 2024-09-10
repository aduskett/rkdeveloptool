#ifndef __RK_LOG_H__
#define __RK_LOG_H__

#include <cstdarg>
#include "Property.hpp"
#include "DefineHeader.h"

#define GET_FMT_STRING(fmt, buf) \
	{ \
	va_list args; \
	va_start(args, fmt); \
	vsnprintf(buf, sizeof(buf)-1, fmt, args); \
	va_end(args); \
	buf[sizeof(buf)-1] = 0x00; \
};

class CRKLog {
public:
	std::string GetLogSavePath();

	bool GetEnableLog();

	void SetEnableLog(bool bEnable);

	property<CRKLog, std::string, READ_ONLY> LogSavePath;
	property<CRKLog, bool, READ_WRITE> EnableLog;

	CRKLog(std::string logFilePath, const std::string& logFileName, bool enable = false);

	~CRKLog();

	bool SaveBuffer(const std::string& fileName, PBYTE lpBuffer, unsigned int dwSize);

	void PrintBuffer(std::string &strOutput, PBYTE lpBuffer, unsigned int dwSize, unsigned int uiLineCount = 16);

	void Record(const char *lpFmt, ...);

protected:
private:
	std::string m_path;
	std::string m_name;
	bool m_enable;

	bool Write(std::string text);
};

typedef enum {
	STAT_NOT_EXIST = 0,
	STAT_FILE,
	STAT_DIR
} ENUM_FILE_STAT;

int file_stat(const std::string& strPath);

#endif /* __RK_LOG_H__ */
