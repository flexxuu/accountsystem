#ifndef SERVICE_CONTAINER_H
#define SERVICE_CONTAINER_H

#include <memory>
#include <unordered_map>
#include <string>
#include <stdexcept>
#include <functional>

// 服务容器 - 实现依赖注入和服务定位
class ServiceContainer {
public:
    // 获取单例实例
    static ServiceContainer& getInstance() {
        static ServiceContainer instance;
        return instance;
    }

    // 禁止拷贝构造和赋值
    ServiceContainer(const ServiceContainer&) = delete;
    ServiceContainer& operator=(const ServiceContainer&) = delete;

    // 注册服务工厂
    template<typename T>
    void registerService(const std::string& serviceName, std::function<std::shared_ptr<T>()> factory) {
        std::string key = getServiceKey<T>(serviceName);
        factories_[key] = [factory]() { return factory(); };
    }

    // 获取服务实例
    template<typename T>
    std::shared_ptr<T> getService(const std::string& serviceName = "default") {
        std::string key = getServiceKey<T>(serviceName);
        auto it = services_.find(key);

        if (it != services_.end()) {
            return std::static_pointer_cast<T>(it->second);
        }

        // 如果服务未实例化，尝试通过工厂创建
        auto factoryIt = factories_.find(key);
        if (factoryIt != factories_.end()) {
            std::shared_ptr<void> service = factoryIt->second();
            services_[key] = service;
            return std::static_pointer_cast<T>(service);
        }

        throw std::runtime_error("Service not found: " + key);
    }

    // 检查服务是否已注册
    template<typename T>
    bool hasService(const std::string& serviceName = "default") {
        std::string key = getServiceKey<T>(serviceName);
        return services_.find(key) != services_.end() || factories_.find(key) != factories_.end();
    }

    // 清除所有服务实例
    void clear() {
        services_.clear();
    }

private:
    ServiceContainer() = default;

    // 生成服务唯一键
    template<typename T>
    std::string getServiceKey(const std::string& serviceName) {
        return std::string(typeid(T).name()) + "_" + serviceName;
    }

    // 服务实例存储
    std::unordered_map<std::string, std::shared_ptr<void>> services_;
    // 服务工厂存储
    std::unordered_map<std::string, std::function<std::shared_ptr<void>()>> factories_;
};

// 服务注册宏 - 注意反斜杠后不能有任何空格
#define REGISTER_SERVICE(T, name, factory) \
    ServiceContainer::getInstance().registerService<T>(name, factory)

// 服务获取宏 - 注意反斜杠后不能有任何空格
#define GET_SERVICE(T, name) \
    ServiceContainer::getInstance().getService<T>(name)

#endif // SERVICE_CONTAINER_H
