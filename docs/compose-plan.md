# 最小交付 Compose 方案

当前交付独立Go client与server。`docker compose up --build`启动server，在真实GET /health成功后运行client，从只读挂载JSON文件读取数据，经内部DNS访问http://server:8080/fingerprint，输出JSON数组后正常退出0。server持续提供服务。不要使用`up --wait`等待已正常退出的一次性client；该选项要求服务持续运行，会将正常退出误报为等待失败。

Dockerfile使用共享Go 1.26构建阶段，分别产出server/client target，运行阶段仅包含静态程序及必要规则，不携带编译器。两者均为65532非root、只读文件系统、cap_drop ALL和禁止提权。外置规则只读挂载，改动后重启server即可生效；格式或规则编译失败使server退出而非假健康。

client只连接独立internal backend网络；server另接ingress桥接网络以支持宿主机发布端口，client不发布端口，server默认仅发布宿主127.0.0.1:8080。无需数据库、凭据、Docker socket或特权。规则和输入为只读bind mount，不需要持久化写卷。日志轮转限制server日志大小。

server停止接收SIGTERM，使用独立context等待在途请求，最长60秒；Compose停止等待65秒。默认批次、Banner和body上限以及超时沿用公共配置。并发限制按批生效，无全局准入，未进行负载压测。

BANNER_INPUT_FILE选择本地输入文件；BANNER_HOST_PORT改变宿主端口；BANNER_BIND_HOST改变宿主绑定。完整启动、重复运行和清理命令见README。
