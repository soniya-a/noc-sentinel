#ifndef __NOXIMLOGGER_H__
#define __NOXIMLOGGER_H__

#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace noxim {

enum LogLevel {
    LOG_LEVEL_OFF_VALUE = 0,
    LOG_LEVEL_ERROR_VALUE,
    LOG_LEVEL_WARN_VALUE,
    LOG_LEVEL_INFO_VALUE,
    LOG_LEVEL_DEBUG_VALUE,
    LOG_LEVEL_TRACE_VALUE
};

class Logger;

class LogMessage {
  public:
    LogMessage(Logger *logger,
               LogLevel level,
               const std::string &file,
               const std::string &function,
               const std::string &module_name,
               bool enabled);
    LogMessage(LogMessage &&other);
    LogMessage(const LogMessage &other) = delete;
    LogMessage &operator=(const LogMessage &other) = delete;
    ~LogMessage();

    template <typename T>
    LogMessage &operator<<(const T &value)
    {
        if (enabled_)
            stream_ << value;
        return *this;
    }

    LogMessage &operator<<(std::ostream &(*manip)(std::ostream &))
    {
        if (enabled_)
            manip(stream_);
        return *this;
    }

    LogMessage &operator<<(std::ios &(*manip)(std::ios &))
    {
        if (enabled_)
            manip(stream_);
        return *this;
    }

    LogMessage &operator<<(std::ios_base &(*manip)(std::ios_base &))
    {
        if (enabled_)
            manip(stream_);
        return *this;
    }

  private:
    Logger *logger_;
    LogLevel level_;
    std::string file_;
    std::string function_;
    std::string module_name_;
    bool enabled_;
    std::ostringstream stream_;
};

class Logger {
  public:
    static Logger &instance();

    void configure(const std::string &level,
                   const std::string &file_path,
                   bool log_to_stderr,
                   const std::vector<std::string> &components);
    void shutdown();

    LogMessage message(LogLevel level,
                       const char *file,
                       const char *function,
                       const std::string &module_name);

    static std::string normalizeComponentName(const std::string &component);

  private:
    Logger();

    static LogLevel parseLevel(const std::string &level);
    static std::string levelName(LogLevel level);
    static std::string basenameStem(const std::string &path);

    std::string componentFromFile(const std::string &file) const;
    bool shouldLog(LogLevel level, const std::string &component) const;
    void write(LogLevel level,
               const std::string &file,
               const std::string &function,
               const std::string &module_name,
               const std::string &message);

    LogLevel level_;
    bool log_to_stderr_;
    std::string file_path_;
    std::ofstream file_stream_;
    std::set<std::string> components_;
    std::mutex mutex_;

    friend class LogMessage;
};

} // namespace noxim

#define LOG noxim::Logger::instance().message(noxim::LOG_LEVEL_DEBUG_VALUE, __FILE__, __func__, name())

#endif
