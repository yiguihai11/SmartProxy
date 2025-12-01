# SmartProxy 版本管理使用说明

## 概述
项目已初始化为 Git 仓库，并提供了版本管理工具。

## 版本管理工具

使用 `./versions.sh` 脚本来管理版本：

### 创建新版本
```bash
./versions.sh save "修复chnroutes显示问题"
```

### 列出所有版本
```bash
./versions.sh list
```

### 切换到指定版本
```bash
./versions.sh checkout v1.0.1
./versions.sh checkout v1.0.0
```

## Git 工作流程

### 1. 创建分支进行开发
```bash
# 为新功能创建分支
git checkout -b feature/chnroutes-fix
```

### 2. 提交更改
```bash
# 查看当前状态
git status

# 添加修改
git add .

# 提交
git commit -m "修复chnroutes显示问题"
```

### 3. 创建版本
```bash
# 使用版本管理工具
./versions.sh save "修复chnroutes显示问题，确保文件内容正确加载到编辑器"
```

### 4. 版本发布和回滚
```bash
# 查看所有版本
./versions.sh list

# 切换到指定版本
./versions.sh checkout v1.0.1

# 标记为发布版本
git tag -a v1.0.1 -m "正式发布版本1.0.1"
git push origin v1.0.1
```

## 建议的开发步骤

1. **备份当前状态**：
   ```bash
   ./versions.sh save "备份当前版本"
   ```

2. **开始修改**：
   ```bash
   git checkout -b feature/your-feature
   ```

3. **测试修改**：
   - 修改代码
   - 重启服务测试
   - 确认功能正常

4. **提交更改**：
   ```bash
   git add .
   git commit -m "实现xxx功能"
   ```

5. **创建版本**：
   ```bash
   ./versions.sh save "添加xxx功能"
   ```

## 文件结构
- `versions/` - 版本备份目录
- `version` - 当前版本号文件
- `VERSION_USAGE.md` - 本使用说明文档

现在您可以开始动手修改了！