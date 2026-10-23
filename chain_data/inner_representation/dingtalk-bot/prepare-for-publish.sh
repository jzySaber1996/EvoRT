#!/bin/bash

# 准备钉钉skill发布到ClawHub
echo "📦 准备发布 dingtalk-bot v0.0.1"

# 1. 清理敏感文件
echo "🧹 清理敏感文件..."
rm -rf credentials/ references/ screenshots/ test-all-scripts.ts
echo "✅ 敏感文件已清理"

# 2. 验证package.json
echo "🔍 验证package.json..."
cat package.json | grep -E "(name|version)"

# 3. 验证文档
echo "📄 验证文档完整性..."
if [ -f "SKILL.md" ] && [ -f "README.md" ]; then
    echo "✅ 文档文件存在"
else
    echo "❌ 缺少必要文档文件"
    exit 1
fi

# 4. 创建发布包
echo "📦 创建发布包..."
cd ..
tar -czf dingtalk-bot-v0.0.1.tar.gz dingtalk-api
echo "✅ 发布包已创建: dingtalk-bot-v0.0.1.tar.gz"

# 5. 显示发布信息
echo ""
echo "🚀 发布信息:"
echo "   名称: dingtalk-bot"
echo "   版本: 0.0.1"
echo "   描述: 钉钉开放平台 API 调用技能，支持传统API和Stream模式事件推送"
echo "   包大小: $(du -h dingtalk-bot-v0.0.1.tar.gz | cut -f1)"
echo ""
echo "📝 下一步:"
echo "   1. 获取 ClawHub API token"
echo "   2. 运行: clawhub login --token <your-token>"
echo "   3. 运行: clawhub publish ./dingtalk-api --slug dingtalk-bot --version 0.0.1"

echo ""
echo "✅ 准备完成！"