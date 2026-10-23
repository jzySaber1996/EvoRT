graph TD
    Z[用户输入：MATON_API_KEY + 操作指令（如“获取会议摘要”）] --> A[AuthVerification]
    A -->|认证失败| Z[终止：返回401]
    A -->|认证成功| B{操作类型}
    
    B -->|连接管理| C[ListConnections/CreateConnection/GetConnection/DeleteConnection]
    B -->|会议数据查询| D[ListMeetings]
    B -->|录制内容获取| E[GetRecordingSummary/GetRecordingTranscript]
    B -->|团队数据查询| F[ListTeams/ListTeamMembers]
    B -->|Webhook管理| G[CreateWebhook/DeleteWebhook]
    
    C -->|返回连接列表/详情| H[用户接收结果]
    C -->|创建连接| I[返回授权URL → 用户浏览器完成OAuth]
    I --> H
    D -->|返回会议列表（含recording_id）| J{是否获取录制内容}
    J -->|是| E
    J -->|否| H
    E -->|同步返回| H
    E -->|异步回调| K[POST摘要/转录文本到destination_url]
    K --> H
    F -->|返回团队/成员列表| H
    G -->|创建Webhook| L[返回Webhook ID/secret → 持续接收会议数据推送]
    G -->|删除Webhook| M[返回204 → 停止推送]
    L --> H
    M --> H