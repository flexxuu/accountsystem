#include "log.h"
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <algorithm>
#include <filesystem>
namespace fs = std::filesystem;

namespace util {

std::shared_ptr<spdlog::logger> Log::logger_;

void Log::initialize(const std::string& level, const std::string& file_path,
                    size_t max_size, size_t max_files) {
    // 创建日志目录
    std::filesystem::path log_path(file_path);
    if (!std::filesystem::exists(log_path.parent_path())) {
        std::filesystem::create_directories(log_path.parent_path());
        spdlog::info("日志目录创建成功: {}", log_path.parent_path().string());
    }

    // 创建控制台和文件输出
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        file_path, max_size, max_files);

    // 设置日志格式
    spdlog::sinks_init_list sink_list = {console_sink, file_sink};
    logger_ = std::make_shared<spdlog::logger>("account_system", sink_list);
    logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

    // 设置日志级别
    std::string level_str = level;
    std::transform(level_str.begin(), level_str.end(), level_str.begin(), ::tolower);
    if (level_str == "trace") {
        logger_->set_level(spdlog::level::trace);
    } else if (level_str == "debug") {
        logger_->set_level(spdlog::level::debug);
    } else if (level_str == "warn") {
        logger_->set_level(spdlog::level::warn);
    } else if (level_str == "error") {
        logger_->set_level(spdlog::level::err);
    } else if (level_str == "critical") {
        logger_->set_level(spdlog::level::critical);
    } else {
        logger_->set_level(spdlog::level::info);
    }

    spdlog::set_default_logger(logger_);
    spdlog::flush_on(spdlog::level::info);
}

} // namespace util