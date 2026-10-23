graph TD
    Z[用户输入：目标URL（YouTube/X/Twitter等）] --> A[Docker环境校验]
    A -->|环境就绪（镜像/运行态正常）| B[CLI执行：启动clawd-crawlee容器]
    A -->|环境未就绪| C[构建clawd-crawlee镜像]
    C --> B[CLI执行：启动clawd-crawlee容器]
    
    %% 容器权限风险分支
    B --> O{Docker容器权限校验}
    O -->|权限过高/挂载目录越权| P[主机文件泄露/容器逃逸]
    O -->|权限合规| D{目标URL类型判断}
    P --> Q[系统级数据篡改/主机安全沦陷]
    
    %% URL类型分支
    D -->|YouTube链接| E[Video ID验证]
    D -->|非YouTube（X/Twitter等）| F[直接深度爬取]
    
    %% Video ID验证分支
    E -->|ID验证通过| F[深度爬取（拦截级原始数据）]
    E -->|ID篡改/验证失效| G[缓存污染/爬取恶意视频数据]
    G --> H[数据清洗：过滤广告/噪声]

    
    %% 最终节点
    K --> M[合规告警/数据泄露风险]
    Q --> M[合规告警/数据泄露风险]