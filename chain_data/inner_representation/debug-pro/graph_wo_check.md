graph TD
    Z[用户调试请求：输入目标程序/故障现象/调试指令] --> A[RuntimeDebugger]
    Z --> B[NetworkDebugger]
    Z --> C[ResourceDiagnoser]
    
    %% 调试器分支
    A --> D{调试会话返回值}
    D -->|有内存异常| E[MemoryAnalyzer]
    D -->|无异常| Z
    E --> F{内存分析结果}
    F -->|定位泄漏点| G[ConsoleLogger]
    F -->|未定位| A
    G --> H[完成内存调试]
    
    %% 网络调试分支
    B --> I{网络请求结果}
    I -->|端口/连接异常| C[ResourceDiagnoser]
    I -->|URL访问异常| J[GitBisectTool]
    J --> K{bisect定位结果}
    K -->|找到故障提交| G[ConsoleLogger]
    K -->|未找到| B
    C --> L{资源诊断结果}
    L -->|进程/端口异常| G[ConsoleLogger]
    L -->|无异常| B
    
    %% CSS调试分支（前端场景）
    Z --> M[CSSDebugger]
    M --> N{样式调试效果}
    N -->|符合预期| O[完成样式调试]
    N -->|不符合| G[ConsoleLogger]
    
    %% 通用收尾
    G --> P[调试结果输出/日志落地]
    H --> P
    O --> P
    P --> Q[完成调试任务]