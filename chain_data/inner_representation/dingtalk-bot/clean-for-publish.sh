#!/bin/bash
# 清理钉钉skill用于发布到clawhub

echo "🧹 清理钉钉skill敏感文件..."

# 移除凭证文件
rm -f .env
rm -rf credentials/

# 移除测试和参考文件
rm -rf references/
rm -rf screenshots/
rm -f test-all-scripts.ts

# 清理脚本中的敏感信息（如果有）
# 检查所有脚本是否包含硬编码凭证
grep -r "Z79qoYdbr_y1dFWHefNKy6JO8DaYmGoyBt10ohvtHQoZhl6Xe5OPA5Vi3DeB_719" . --exclude-dir=.git
if [ $? -eq 0 ]; then
    echo "❌ 发现硬编码凭证，请手动清理！"
    exit 1
fi

# 创建示例配置文件
cat > .env.example << 'EOF'
# DingTalk API Configuration
# 请复制此文件为 .env 并填入您的实际凭证
export DINGTALK_APP_KEY=your_app_key_here
export DINGTALK_APP_SECRET=your_app_secret_here
EOF

echo "✅ 清理完成！现在可以安全发布到clawhub。"
echo "📝 记得更新 README.md 和 SKILL.md 中的配置说明。"