graph TD
    Z[用户查询：输入触发词+待转换文本/配置指令] --> A[TriggerDetection]
    A -->|过滤触发词| B{文本合法性初检}
    B -->|合法| C[TTSConfigManager]
    B -->|非法| Z[拒绝执行，返回提示]
    C -->|读取配置| D{配置是否自定义}
    C -->|写入配置（管理员/用户指令）| C1[配置文件持久化]
    D -->|默认配置| E[TTSToolExecutor（内置tts工具）]
    D -->|自定义配置| F[VoiceListFetcher]
    F -->|返回可用语音列表| E[TTSToolExecutor（scripts/tts-converter.js）]
    E -->|参数校验| G{是否启用代理/字幕}
    G -->|启用代理| G1[代理配置校验]
    G -->|启用字幕| G2[SubtitleGenerator]
    G1 --> H[调用Microsoft Edge TTS服务]
    G2 --> H[调用Microsoft Edge TTS服务]
    G -->|无特殊配置| H[调用Microsoft Edge TTS服务]
    H --> I[AudioFileHandler]
    I -->|生成音频文件至临时目录| J{返回MEDIA路径}
    J -->|成功| K[ClawdbotMediaRouter]
    J -->|失败| E[重试TTSToolExecutor]
    K --> M[音频文件推送至用户渠道]
    M --> N[任务完成（临时文件未自动清理）]