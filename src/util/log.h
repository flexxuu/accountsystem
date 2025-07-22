#ifndef LOG_H
#define LOG_H

#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>
#include <memory>
#include <string>

class Log {
public:
    static void initialize(const std::string& level, const std::string& file_path,
                          size_t max_size, size_t max_files);

    template<typename... Args>
    static void trace(const std::string& fmt, const Args&... args) {
        spdlog::trace(fmt, args...);
    }

    template<typename... Args>
    static void debug(const std::string& fmt, const Args&... args) {
        spdlog::debug(fmt, args...);
    }

    template<typename... Args>
    static void info(const std::string& fmt, const Args&... args) {
        spdlog::info(fmt, args...);
    }

    template<typename... Args>
    static void warn(const std::string& fmt, const Args&... args) {
        spdlog::warn(fmt, args...);
    }

    template<typename... Args>
    static void error(const std::string& fmt, const Args&... args) {
        spdlog::error(fmt, args...);
    }

    template<typename... Args>
    static void critical(const std::string& fmt, const Args&... args) {
        spdlog::critical(fmt, args...);
    }

private:
    static std::shared_ptr<spdlog::logger> logger_;
};

#endif // LOG_H