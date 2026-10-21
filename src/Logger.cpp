/*
 * Noxim - the NoC Simulator
 *
 * (C) 2005-2018 by the University of Catania
 * For the complete list of authors refer to file ../doc/AUTHORS.txt
 * For the license applied to these sources refer to file ../doc/LICENSE.txt
 *
 * This file contains the implementation of the runtime logger
 */

#include "Logger.h"

#include "GlobalParams.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <systemc.h>

using namespace std;

namespace noxim {

namespace {

string normalizeToken(const string &value)
{
    string normalized;
    normalized.reserve(value.size());

    for (size_t i = 0; i < value.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
        if (isalnum(ch))
            normalized.push_back(static_cast<char>(tolower(ch)));
        else if (ch == '_' || ch == '-' || ch == ' ')
            normalized.push_back('_');
    }

    return normalized;
}

string canonicalComponent(const string &component)
{
    string normalized = normalizeToken(component);

    if (normalized == "router" ||
        normalized.find("routing_") == 0 ||
        normalized.find("selection_") == 0)
        return "router";
    if (normalized == "hub" || normalized == "target")
        return "hub";
    if (normalized == "channel")
        return "channel";
    if (normalized == "tokenring" || normalized == "token_ring")
        return "tokenring";
    if (normalized == "initiator")
        return "initiator";

    return normalized;
}

} // namespace

LogMessage::LogMessage(Logger *logger,
                       LogLevel level,
                       const string &file,
                       const string &function,
                       const string &module_name,
                       bool enabled)
    : logger_(logger),
      level_(level),
      file_(file),
      function_(function),
      module_name_(module_name),
      enabled_(enabled)
{
}

LogMessage::LogMessage(LogMessage &&other)
    : logger_(other.logger_),
      level_(other.level_),
      file_(other.file_),
      function_(other.function_),
      module_name_(other.module_name_),
      enabled_(other.enabled_),
      stream_(std::move(other.stream_))
{
    other.enabled_ = false;
}

LogMessage::~LogMessage()
{
    if (enabled_ && logger_ != NULL)
        logger_->write(level_, file_, function_, module_name_, stream_.str());
}

Logger::Logger()
    : level_(LOG_LEVEL_OFF_VALUE),
      log_to_stderr_(true)
{
}

Logger &Logger::instance()
{
    static Logger logger;
    return logger;
}

void Logger::configure(const string &level,
                       const string &file_path,
                       bool log_to_stderr,
                       const vector<string> &components)
{
    lock_guard<mutex> lock(mutex_);

    level_ = parseLevel(level);
    log_to_stderr_ = log_to_stderr;
    file_path_ = file_path;
    components_.clear();

    file_stream_.close();

    if (level_ != LOG_LEVEL_OFF_VALUE && !file_path_.empty()) {
        file_stream_.open(file_path_.c_str(), ios::out | ios::trunc);
        if (!file_stream_.is_open()) {
            cerr << "Error: Cannot open log file " << file_path_ << endl;
            exit(1);
        }
    }

    for (size_t i = 0; i < components.size(); ++i) {
        string normalized = normalizeComponentName(components[i]);
        if (normalized.empty())
            continue;
        if (normalized == "all" || normalized == "*") {
            components_.clear();
            break;
        }
        components_.insert(normalized);
    }

    if (level_ != LOG_LEVEL_OFF_VALUE && !log_to_stderr_ && file_path_.empty())
        log_to_stderr_ = true;
}

void Logger::shutdown()
{
    lock_guard<mutex> lock(mutex_);
    if (file_stream_.is_open())
        file_stream_.close();
}

LogMessage Logger::message(LogLevel level,
                           const char *file,
                           const char *function,
                           const string &module_name)
{
    const string file_name = file ? file : "";
    const string component = componentFromFile(file_name);
    return LogMessage(this,
                      level,
                      file_name,
                      function ? function : "",
                      module_name,
                      shouldLog(level, component));
}

string Logger::normalizeComponentName(const string &component)
{
    return canonicalComponent(component);
}

LogLevel Logger::parseLevel(const string &level)
{
    string normalized = normalizeToken(level);

    if (normalized == "0" || normalized == "off")
        return LOG_LEVEL_OFF_VALUE;
    if (normalized == "1" || normalized == "error")
        return LOG_LEVEL_ERROR_VALUE;
    if (normalized == "2" || normalized == "warn" || normalized == "warning")
        return LOG_LEVEL_WARN_VALUE;
    if (normalized == "3" || normalized == "info")
        return LOG_LEVEL_INFO_VALUE;
    if (normalized == "4" || normalized == "debug")
        return LOG_LEVEL_DEBUG_VALUE;
    if (normalized == "5" || normalized == "trace")
        return LOG_LEVEL_TRACE_VALUE;

    cerr << "Error: Invalid log level: " << level << endl;
    cerr << "Valid values are OFF, ERROR, WARN, INFO, DEBUG, TRACE (or 0-5)" << endl;
    exit(1);
}

string Logger::levelName(LogLevel level)
{
    switch (level) {
    case LOG_LEVEL_ERROR_VALUE:
        return "ERROR";
    case LOG_LEVEL_WARN_VALUE:
        return "WARN";
    case LOG_LEVEL_INFO_VALUE:
        return "INFO";
    case LOG_LEVEL_DEBUG_VALUE:
        return "DEBUG";
    case LOG_LEVEL_TRACE_VALUE:
        return "TRACE";
    case LOG_LEVEL_OFF_VALUE:
    default:
        return "OFF";
    }
}

string Logger::basenameStem(const string &path)
{
    const size_t slash = path.find_last_of("/\\");
    const string basename = (slash == string::npos) ? path : path.substr(slash + 1);
    const size_t dot = basename.find_last_of('.');
    return dot == string::npos ? basename : basename.substr(0, dot);
}

string Logger::componentFromFile(const string &file) const
{
    return canonicalComponent(basenameStem(file));
}

bool Logger::shouldLog(LogLevel level, const string &component) const
{
    if (level_ == LOG_LEVEL_OFF_VALUE || level > level_)
        return false;

    if (!components_.empty() && components_.count(component) == 0)
        return false;

    return true;
}

void Logger::write(LogLevel level,
                   const string &file,
                   const string &function,
                   const string &module_name,
                   const string &message)
{
    lock_guard<mutex> lock(mutex_);

    const string component = componentFromFile(file);
    ostringstream line;

    double cycles = 0.0;
    if (GlobalParams::clock_period_ps > 0)
        cycles = sc_time_stamp().to_double() / GlobalParams::clock_period_ps;

    line << setw(7) << left << cycles
         << " [" << levelName(level) << "]"
         << " [" << component << "] ";

    if (!module_name.empty())
        line << module_name;
    else
        line << basenameStem(file);

    if (!function.empty())
        line << "::" << function << "()";

    line << " --> " << message;

    const string rendered = line.str();

    if (log_to_stderr_)
        cerr << rendered;

    if (file_stream_.is_open()) {
        file_stream_ << rendered;
        file_stream_.flush();
    }
}

} // namespace noxim
