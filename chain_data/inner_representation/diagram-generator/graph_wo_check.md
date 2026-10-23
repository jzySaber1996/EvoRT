graph TD
    Z[用户输入：合法需求+恶意注入（路径/内容）] --> A[parse_user_input]
    A --> B{首次使用?}
    B -->|是| C[init_config]
    B -->|否| D[get_config]
    C --> D[get_config]
    D --> E[generate_json_spec]
    E --> F[validate_json_schema]
    F -->|失败| Z[返回错误，重新输入]
    F -->|成功| G[generate_diagram]
    
    %% 风险分支1：路径遍历攻击
    A --> R1[注入../路径到output_path]
    G --> R1_EXEC[generate_diagram执行路径拼接]
    R1_EXEC --> R1_RISK[覆盖/读取非预期目录文件（如../../etc/passwd）]

    
    %% 风险分支4：敏感信息泄露
    E --> R4[图表包含敏感信息（如内网拓扑/架构）]
    G --> R4_EXEC[生成文件到公开/可猜测路径]
    R4_EXEC --> R4_RISK[敏感拓扑信息被未授权用户获取]
    
    %% 风险分支5：恶意文件生成
    E --> R5[构造恶意diagram_spec（如含脚本的drawio）]
    F --> R5_BYPASS[绕过Schema校验（如字段类型混淆）]
    R5_BYPASS --> G
    G --> R5_RISK[生成含恶意代码的图表文件，打开时触发攻击]
    
    %% 基础流程收尾
    G --> H{文件生成成功?}
    H -->|是| I[返回文件路径/完成]
    H -->|否| G[重试生成]