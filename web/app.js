// 调试开关
const DEBUG_MODE = true;

// 调试函数
function debug(message, data = null) {
    if (DEBUG_MODE) {
        console.log(`[DEBUG] ${message}`, data || '');
    }
}

// 全局状态管理
const AppState = {
    currentConfig: {},
    currentTab: 'basic',
    autoRefreshInterval: null,
    isInitialized: false
};

// DOM 加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM 加载完成，开始初始化应用...');
    initializeApp();
});

// 初始化应用
async function initializeApp() {
    try {
        // 显示加载状态
        updateStatus('checking', '连接中...');

        // 初始化 layui
        if (typeof layui !== 'undefined') {
            layui.use(['form', 'layer', 'element'], function(){
                layui.form.render();
                layui.element.render();
            });
        }

        // 加载配置
        await loadConfig();

        // 刷新数据
        await refreshData();

        // 启动自动刷新
        startAutoRefresh();

        // 添加表单实时保存监听器
        setupAutoSave();

        // 标记为已初始化
        AppState.isInitialized = true;

        // 显示成功消息
        showAlert('success', '智能代理控制台已成功加载');

        console.log('应用初始化完成');

    } catch (error) {
        console.error('应用初始化失败:', error);
        showAlert('error', '应用初始化失败: ' + error.message);
        updateStatus('offline', '连接失败');
    }
}

// 设置自动保存功能
function setupAutoSave() {
    let saveTimeout;

    // 自动保存函数
    const autoSave = async () => {
        clearTimeout(saveTimeout);
        saveTimeout = setTimeout(async () => {
            try {
                // 收集表单数据
                collectFormData();

                // 保存到服务器
                await saveConfig();
                console.log('配置已自动保存');
            } catch (error) {
                console.error('自动保存失败:', error);
            }
        }, 2000); // 2秒后保存（防止频繁保存）
    };

    // 为所有输入框添加自动保存
    const inputs = document.querySelectorAll('input[type="text"], input[type="number"], input[type="checkbox"], select, textarea');
    inputs.forEach(input => {
        // 跳过模态框中的输入框
        if (input.closest('.modal')) return;

        input.addEventListener('change', autoSave);
        input.addEventListener('input', autoSave);

        // 端口输入框特殊处理
        if (input.id && input.id.includes('_port')) {
            input.addEventListener('input', () => checkPortWarning(input));
        }
    });

    // 为layui的下拉选择框添加监听
    if (typeof layui !== 'undefined') {
        layui.use(['form'], function(){
            layui.form.on('select(nat_mode)', autoSave);
            // enable_auth 有专门的事件处理器，不在这里添加自动保存
            layui.form.on('checkbox(chnroutes_enabled)', autoSave);
            layui.form.on('checkbox(smart_proxy_enabled)', autoSave);
        });
    }
}

// 更新状态显示
function updateStatus(status, text) {
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    // 移除所有状态类
    statusDot.className = 'status-dot';

    // 添加新状态类
    switch (status) {
        case 'online':
            statusDot.classList.add('online');
            break;
        case 'offline':
            statusDot.classList.add('offline');
            break;
        case 'checking':
            statusDot.classList.add('checking');
            break;
    }

    statusText.textContent = text;
}

// 切换标签页
function switchTab(tabName, event) {
    debug('开始切换标签', { tabName, event });

    // 检查元素是否存在
    const targetContent = document.getElementById(`${tabName}-config`);
    debug('目标元素', targetContent);

    if (!targetContent) {
        debug('错误：找不到目标元素', `${tabName}-config`);
        console.error('可用的配置容器ID:', Array.from(document.querySelectorAll('[id$="-config"]')).map(el => el.id));
        return;
    }

    // 更新按钮状态
    debug('更新按钮状态');
    document.querySelectorAll('.tab-btn').forEach(btn => {
        debug('移除按钮active类', btn);
        btn.classList.remove('active');
    });

    if (event && event.currentTarget) {
        debug('添加当前按钮active类', event.currentTarget);
        event.currentTarget.classList.add('active');
    }

    // 更新内容显示
    debug('更新内容显示');
    document.querySelectorAll('.config-content').forEach(content => {
        debug('隐藏配置内容', content.id);
        content.classList.remove('active');
    });

    debug('显示目标配置');
    targetContent.classList.add('active');

    // 验证切换结果
    setTimeout(() => {
        const computedStyle = window.getComputedStyle(targetContent);
        debug('切换完成', {
            targetId: `${tabName}-config`,
            display: computedStyle.display,
            hasActiveClass: targetContent.classList.contains('active')
        });
    }, 100);

    AppState.currentTab = tabName;
}

// 加载配置
async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        if (data.success) {
            AppState.currentConfig = data.data;
            populateConfigForms(data.data);
            console.log('配置加载成功');
        } else {
            throw new Error(data.error || '配置加载失败');
        }
    } catch (error) {
        console.error('加载配置失败:', error);
        throw error;
    }
}

// 填充配置表单
function populateConfigForms(config) {
    // 基础配置
    if (config.listener) {
        document.getElementById('socks5_port').value = config.listener.socks5_port || 1080;
        document.getElementById('dns_port').value = config.listener.dns_port || 1053;
        document.getElementById('ipv6_enabled').checked = config.listener.ipv6_enabled || false;
    }

    // Web界面配置
    if (config.web_interface) {
        document.getElementById('web_port').value = config.web_interface.port || 8080;
    }

    if (config.socks5) {
        document.getElementById('max_connections').value = config.socks5.max_connections || 1000;
        document.getElementById('cleanup_interval').value = config.socks5.cleanup_interval || 300;
        document.getElementById('nat_mode').value = config.socks5.nat_mode || 'full_core';

        // 设置enable_auth状态
        const authEnabled = config.socks5.enable_auth || false;
        const enableAuthCheckbox = document.getElementById('enable_auth');
        enableAuthCheckbox.checked = authEnabled;

        console.log('设置enable_auth状态:', authEnabled);
    }

    // 网络配置
    if (config.connection_settings) {
        document.getElementById('tcp_timeout_seconds').value = config.connection_settings.tcp_timeout_seconds || 60;
        document.getElementById('udp_timeout_seconds').value = config.connection_settings.udp_timeout_seconds || 300;
    }

    if (config.node_health_check) {
        document.getElementById('node_health_check_interval_seconds').value = config.node_health_check.interval_seconds || 600;
    }

    if (config.chnroutes) {
        document.getElementById('chnroutes_enable').checked = config.chnroutes.enable || false;
        document.getElementById('chnroutes_path').value = config.chnroutes.path || 'conf/chnroutes.txt';
    }

    // DNS 配置
    if (config.dns) {
        if (config.dns.cache) {
            document.getElementById('dns_cache_max_size').value = config.dns.cache.max_size || 2000;
            document.getElementById('dns_cache_default_ttl').value = config.dns.cache.default_ttl || 300;
            document.getElementById('dns_cache_cleanup_interval').value = config.dns.cache.cleanup_interval || 60;
        }

        if (config.dns.groups) {
            // DNS服务器配置应该是数组形式，每行一个服务器
            const cnServers = Array.isArray(config.dns.groups.cn) ? config.dns.groups.cn : [];
            const foreignServers = Array.isArray(config.dns.groups.foreign) ? config.dns.groups.foreign : [];

            // 过滤掉空值并去除首尾空格
            const cleanCnServers = cnServers.filter(server => server && server.trim());
            const cleanForeignServers = foreignServers.filter(server => server && server.trim());

            document.getElementById('dns_groups_cn').value = cleanCnServers.join('\n');
            document.getElementById('dns_groups_foreign').value = cleanForeignServers.join('\n');
        }
    }

    // 智能代理配置
    if (config.smart_proxy) {
        document.getElementById('smart_proxy_enable').checked = config.smart_proxy.enable || false;
        document.getElementById('smart_proxy_timeout_ms').value = config.smart_proxy.timeout_ms || 3000;
        document.getElementById('smart_proxy_blacklist_expiry_minutes').value = config.smart_proxy.blacklist_expiry_minutes || 360;
    }

    // 内存池配置
    if (config.memory_pool) {
        document.getElementById('memory_pool_size_mb').value = config.memory_pool.size_mb || 16;
        document.getElementById('memory_pool_auto_adjust').checked = config.memory_pool.auto_adjust !== false;
        const blockSizes = Array.isArray(config.memory_pool.block_sizes) ? config.memory_pool.block_sizes : [];
        document.getElementById('memory_pool_block_sizes').value = blockSizes.join('\n');
    }

    // 零拷贝配置
    if (config.zero_copy) {
        document.getElementById('zero_copy_enabled').checked = config.zero_copy.enabled !== false;
        document.getElementById('zero_copy_buffer_size').value = config.zero_copy.buffer_size || 65536;
    }

    // 连接池配置
    if (config.connection_pool) {
        document.getElementById('connection_pool_enabled').checked = config.connection_pool.enabled !== false;
        document.getElementById('connection_pool_max_per_host').value = config.connection_pool.max_per_host || 50;
        document.getElementById('connection_pool_max_idle').value = config.connection_pool.max_idle || 300;
        document.getElementById('connection_pool_max_age').value = config.connection_pool.max_age || 3600;
    }

    // 身份验证用户配置 - 只在启用时加载用户列表
    if (config.socks5 && config.socks5.enable_auth) {
        // 如果启用身份验证，则加载用户列表（如果有的话）
        if (config.socks5.auth_users && config.socks5.auth_users.length > 0) {
            populateAuthUsersTable(config.socks5.auth_users);
        } else {
            populateAuthUsersTable([]); // 显示空状态
        }
    }

    // 加载中国路由文件
    loadChnroutesFile();

    // 代理节点
    if (config.proxy_nodes) {
        populateProxyNodesTable(config.proxy_nodes);
    }

    // 重新渲染 layui 表单组件
    if (typeof layui !== 'undefined') {
        layui.use(['form'], function(){
            layui.form.render();

            // 在表单渲染后立即应用用户界面状态
            setTimeout(() => {
                const authCheckbox = document.getElementById('enable_auth');
                const authSection = document.getElementById('auth-users-section');
                const authEnabled = AppState.currentConfig.socks5 && AppState.currentConfig.socks5.enable_auth;

                console.log('表单渲染后应用状态:', authEnabled);

                if (authSection) {
                    authSection.style.display = authEnabled ? 'block' : 'none';
                    console.log('用户管理界面显示状态设置为:', authSection.style.display);
                }
            }, 100);

            // 移除enable_auth的layui事件监听，使用原生onchange处理
            // layui.form.on('checkbox(enable_auth)', function(data){
            //     // 已由handleAuthToggle处理
            // });
        });
    }
}

// 刷新数据
async function refreshData() {
    try {
        // 获取服务器状态
        const statusResponse = await fetch('/api/status');
        if (!statusResponse.ok) {
            throw new Error(`HTTP ${statusResponse.status}: ${statusResponse.statusText}`);
        }

        const statusData = await statusResponse.json();
        if (statusData.success) {
            let status = statusData.data;
            document.getElementById('active-connections').textContent = status.active_connections || '0';

            // 更新状态指示器
            updateStatus('online', '运行中');
        } else {
            updateStatus('offline', '离线');
        }

        // 获取统计信息
        const statsResponse = await fetch('/api/stats');
        if (!statsResponse.ok) {
            throw new Error(`HTTP ${statsResponse.status}: ${statsResponse.statusText}`);
        }

        const statsData = await statsResponse.json();
        if (statsData.success) {
            let stats = statsData.data;
            document.getElementById('dns-queries').textContent = stats.dns?.total_queries || '0';
            document.getElementById('uptime').textContent = stats.uptime || 'N/A';

            if (stats.proxy) {
                document.getElementById('proxy-nodes').textContent = Object.keys(stats.proxy).length;
            }
        }

    } catch (error) {
        console.error('刷新数据失败:', error);
        updateStatus('offline', '连接失败');
    }
}

// 启动自动刷新
function startAutoRefresh() {
    if (AppState.autoRefreshInterval) {
        clearInterval(AppState.autoRefreshInterval);
    }

    // 每5秒刷新一次状态数据（包括运行时间）
    AppState.autoRefreshInterval = setInterval(refreshData, 5000);
}

// 保存配置到服务器
async function saveConfig() {
    try {
        const response = await fetch('/api/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                config: AppState.currentConfig
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        if (data.success) {
            showAlert('success', '配置保存成功！');
            return true;
        } else {
            throw new Error(data.error || '配置保存失败');
        }
    } catch (error) {
        console.error('保存配置失败:', error);
        showAlert('error', '配置保存失败: ' + error.message);
        return false;
    }
}

// 从表单收集配置数据
function collectFormData() {
    const config = { ...AppState.currentConfig };

    // 基础配置
    if (!config.listener) config.listener = {};
    config.listener.socks5_port = parseInt(document.getElementById('socks5_port').value) || 1080;
    config.listener.dns_port = parseInt(document.getElementById('dns_port').value) || 1053;
    config.listener.ipv6_enabled = document.getElementById('ipv6_enabled').checked;

    // Web界面配置
    if (!config.web_interface) config.web_interface = {};
    config.web_interface.port = parseInt(document.getElementById('web_port').value) || 8080;
    config.web_interface.enabled = true; // 始终启用，因为用户正在使用Web界面

    // SOCKS5配置
    if (!config.socks5) config.socks5 = {};
    config.socks5.max_connections = parseInt(document.getElementById('max_connections').value) || 1000;
    config.socks5.cleanup_interval = parseInt(document.getElementById('cleanup_interval').value) || 300;
    config.socks5.enable_auth = document.getElementById('enable_auth').checked;
    config.socks5.nat_mode = document.getElementById('nat_mode').value || 'proxy';

    // 网络配置
    if (!config.connection_settings) config.connection_settings = {};
    config.connection_settings.tcp_timeout_seconds = parseInt(document.getElementById('tcp_timeout_seconds').value) || 60;
    config.connection_settings.udp_timeout_seconds = parseInt(document.getElementById('udp_timeout_seconds').value) || 300;

    if (!config.node_health_check) config.node_health_check = {};
    config.node_health_check.interval_seconds = parseInt(document.getElementById('node_health_check_interval_seconds').value) || 600;

    if (!config.chnroutes) config.chnroutes = {};
    config.chnroutes.enable = document.getElementById('chnroutes_enable').checked;
    config.chnroutes.path = document.getElementById('chnroutes_path').value || 'conf/chnroutes.txt';

    // DNS配置
    if (!config.dns) config.dns = {};
    if (!config.dns.cache) config.dns.cache = {};
    config.dns.cache.max_size = parseInt(document.getElementById('dns_cache_max_size').value) || 2000;
    config.dns.cache.default_ttl = parseInt(document.getElementById('dns_cache_default_ttl').value) || 300;
    config.dns.cache.cleanup_interval = parseInt(document.getElementById('dns_cache_cleanup_interval').value) || 60;

    // DNS服务器配置
    if (!config.dns.groups) config.dns.groups = {};
    const cnDnsServers = document.getElementById('dns_groups_cn').value
        .split('\n')
        .map(s => s.trim())
        .filter(s => s);
    const foreignDnsServers = document.getElementById('dns_groups_foreign').value
        .split('\n')
        .map(s => s.trim())
        .filter(s => s);

    config.dns.groups.cn = cnDnsServers;
    config.dns.groups.foreign = foreignDnsServers;

    // 智能代理配置
    if (!config.smart_proxy) config.smart_proxy = {};
    config.smart_proxy.enable = document.getElementById('smart_proxy_enable').checked;
    config.smart_proxy.timeout_ms = parseInt(document.getElementById('smart_proxy_timeout_ms').value) || 3000;
    config.smart_proxy.blacklist_expiry_minutes = parseInt(document.getElementById('smart_proxy_blacklist_expiry_minutes').value) || 360;

    // 内存池配置
    if (!config.memory_pool) config.memory_pool = {};
    config.memory_pool.size_mb = parseInt(document.getElementById('memory_pool_size_mb').value) || 16;
    config.memory_pool.auto_adjust = document.getElementById('memory_pool_auto_adjust').checked;
    const blockSizes = document.getElementById('memory_pool_block_sizes').value
        .split('\n')
        .map(s => s.trim())
        .filter(s => s);
    config.memory_pool.block_sizes = blockSizes.length > 0 ? blockSizes : ["4096", "16384", "65536", "262144"];

    // 零拷贝配置
    if (!config.zero_copy) config.zero_copy = {};
    config.zero_copy.enabled = document.getElementById('zero_copy_enabled').checked;
    config.zero_copy.buffer_size = parseInt(document.getElementById('zero_copy_buffer_size').value) || 65536;

    // 连接池配置
    if (!config.connection_pool) config.connection_pool = {};
    config.connection_pool.enabled = document.getElementById('connection_pool_enabled').checked;
    config.connection_pool.max_per_host = parseInt(document.getElementById('connection_pool_max_per_host').value) || 50;
    config.connection_pool.max_idle = parseInt(document.getElementById('connection_pool_max_idle').value) || 300;
    config.connection_pool.max_age = parseInt(document.getElementById('connection_pool_max_age').value) || 3600;

    // 更新当前配置
    AppState.currentConfig = config;
    return config;
}

// 显示警告消息
function showAlert(type, message) {
    const alertId = 'alert-' + Date.now();

    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type}">
            <i class="layui-icon layui-icon-${type === 'success' ? 'ok-circle' : 'warning'}"></i>
            <span>${message}</span>
        </div>
    `;

    // 插入到页面顶部
    const mainContainer = document.querySelector('.main-container');
    mainContainer.insertAdjacentHTML('afterbegin', alertHtml);

    // 3秒后自动移除
    setTimeout(() => {
        const alertElement = document.getElementById(alertId);
        if (alertElement) {
            alertElement.remove();
        }
    }, 3000);
}

// 生成星级显示
function generateStars(weight) {
    const maxWeight = 10;
    const filledStars = Math.round(weight);
    const emptyStars = maxWeight - filledStars;

    let stars = '';
    for (let i = 0; i < filledStars; i++) {
        stars += '<i class="layui-icon layui-icon-rate-solid" style="color: #FFB800; font-size: 14px;"></i>';
    }
    for (let i = 0; i < emptyStars; i++) {
        stars += '<i class="layui-icon layui-icon-rate" style="color: #ddd; font-size: 14px;"></i>';
    }

    return stars;
}

// 填充代理节点表格
function populateProxyNodesTable(nodes) {
    const tbody = document.getElementById('proxy-nodes-tbody');
    tbody.innerHTML = '';

    nodes.forEach((node, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>
                <div style="display: flex; align-items: center;">
                    <i class="layui-icon layui-icon-component" style="margin-right: 8px; color: var(--primary); font-size: 16px;"></i>
                    <strong>${node.identifier}</strong>
                </div>
            </td>
            <td><span class="layui-badge layui-bg-blue">${node.protocol}</span></td>
            <td>${node.ip}</td>
            <td>
                <span style="font-weight: 500; color: #495057;">${node.port}</span>
            </td>
            <td>
                <div style="display: flex; align-items: center; gap: 2px;">
                    ${generateStars(node.weight)}
                    <span style="margin-left: 4px; font-size: 12px; color: #6c757d;">(${node.weight})</span>
                </div>
            </td>
            <td>
                <span class="layui-badge ${node.enabled ? 'layui-bg-green' : 'layui-bg-gray'}">
                    <i class="layui-icon layui-icon-${node.enabled ? 'ok' : 'close'}"></i>
                    ${node.enabled ? '启用' : '禁用'}
                </span>
            </td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-primary" onclick="editProxyNode(${index})" title="编辑节点">
                        <i class="layui-icon layui-icon-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteProxyNode(${index})" title="删除节点">
                        <i class="layui-icon layui-icon-delete"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });

    // 更新代理节点统计
    const enabledNodes = nodes.filter(n => n.enabled).length;
    document.getElementById('proxy-nodes').textContent = enabledNodes;
}

// 添加代理节点
function addProxyNode() {
    // 清空表单
    document.getElementById('node-index').value = '';
    document.getElementById('modal-title-text').textContent = '添加代理节点';
    document.getElementById('node-identifier').value = '';
    document.getElementById('node-protocol').value = 'socks5';
    document.getElementById('node-ip').value = '';
    document.getElementById('node-port').value = '';
    document.getElementById('node-weight').value = '5';
    document.getElementById('node-enabled').checked = true;

    // 显示模态框
    document.getElementById('proxy-node-modal').style.display = 'flex';

    // 重新渲染 layui 表单
    if (typeof layui !== 'undefined') {
        layui.use(['form'], function(){
            layui.form.render();
        });
    }
}

// 编辑代理节点
function editProxyNode(index) {
    const nodes = AppState.currentConfig.proxy_nodes || [];
    const node = nodes[index];

    if (node) {
        // 填充表单数据
        document.getElementById('node-index').value = index;
        document.getElementById('modal-title-text').textContent = '编辑代理节点';
        document.getElementById('node-identifier').value = node.identifier || '';
        document.getElementById('node-protocol').value = node.protocol || 'socks5';
        document.getElementById('node-ip').value = node.ip || '';
        document.getElementById('node-port').value = node.port || '';
        document.getElementById('node-weight').value = node.weight || '5';
        document.getElementById('node-enabled').checked = node.enabled !== false;

        // 显示模态框
        document.getElementById('proxy-node-modal').style.display = 'flex';

        // 重新渲染 layui 表单
        if (typeof layui !== 'undefined') {
            layui.use(['form'], function(){
                layui.form.render();
            });
        }
    }
}

// 删除代理节点
function deleteProxyNode(index) {
    const nodes = AppState.currentConfig.proxy_nodes || [];
    const node = nodes[index];

    showConfirm(
        '删除确认',
        `确定要删除代理节点 "${node.identifier}" 吗？<br>IP: ${node.ip}:${node.port}`,
        function () {
            // 用户点击确定删除
            nodes.splice(index, 1);
            AppState.currentConfig.proxy_nodes = nodes;

            // 更新表格显示
            populateProxyNodesTable(nodes);

            // 更新代理节点统计
            const enabledNodes = nodes.filter(n => n.enabled).length;
            document.getElementById('proxy-nodes').textContent = enabledNodes;

            // 显示成功消息
            showAlert('success', '代理节点删除成功！');

            // 触发保存到服务器
            saveConfig().then(() => {
                // 保存成功
            }).catch(error => {
                showAlert('error', '保存删除操作失败: ' + error.message);
            });
        }
    );
}

// 关闭代理节点模态框
function closeProxyNodeModal() {
    document.getElementById('proxy-node-modal').style.display = 'none';
}

// 保存代理节点
async function saveProxyNode() {
    const form = document.getElementById('proxy-node-form');
    const index = document.getElementById('node-index').value;

    // 验证表单
    const identifier = document.getElementById('node-identifier').value.trim();
    const protocol = document.getElementById('node-protocol').value;
    const ip = document.getElementById('node-ip').value.trim();
    const port = parseInt(document.getElementById('node-port').value);
    const weight = parseInt(document.getElementById('node-weight').value);
    const enabled = document.getElementById('node-enabled').checked;

    // 基本验证
    if (!identifier) {
        showAlert('error', '请输入标识符');
        return;
    }
    if (!ip) {
        showAlert('error', '请输入IP地址');
        return;
    }
    if (isNaN(port) || port < 0 || port > 65535) {
        showAlert('error', '请输入有效的端口号 (0-65535)');
        return;
    }

    // 创建节点对象
    const node = {
        identifier,
        protocol,
        ip,
        port,
        weight: weight || 5,
        enabled,
        auth_method: 'none'
    };

    // 如果是直连协议，端口设为0
    if (protocol === 'direct') {
        node.port = 0;
    }

    // 添加或更新节点
    if (index === '') {
        // 添加新节点
        if (!AppState.currentConfig.proxy_nodes) {
            AppState.currentConfig.proxy_nodes = [];
        }
        AppState.currentConfig.proxy_nodes.push(node);
    } else {
        // 更新现有节点
        AppState.currentConfig.proxy_nodes[parseInt(index)] = node;
    }

    // 保存配置到服务器
    const saved = await saveConfig();
    if (saved) {
        // 更新表格显示
        populateProxyNodesTable(AppState.currentConfig.proxy_nodes);
        // 关闭模态框
        closeProxyNodeModal();
    }
}

// 键盘事件处理
document.addEventListener('keydown', function(e) {
    // F5 键刷新
    if (e.key === 'F5') {
        e.preventDefault();
        refreshData();
    }
    // Ctrl+T 测试API
    if (e.ctrlKey && e.key === 't') {
        e.preventDefault();
        testAPIs();
    }
});

// 测试所有API
function testAPIs() {
    console.log('测试所有API...');

    const apis = [
        { name: '状态API', url: '/api/status' },
        { name: '配置API', url: '/api/config' },
        { name: '统计API', url: '/api/stats' }
    ];

    apis.forEach(api => {
        fetch(api.url)
            .then(response => response.json())
            .then(data => {
                console.log(`${api.name} 测试成功:`, data);
                showAlert('success', `${api.name} 测试成功`);
            })
            .catch(error => {
                console.error(`${api.name} 测试失败:`, error);
                showAlert('error', `${api.name} 测试失败`);
            });
    });
}

// 填充认证用户表格
function populateAuthUsersTable(users) {
    const tbody = document.getElementById('auth-users-tbody');
    const emptyState = document.getElementById('auth-users-empty');

    tbody.innerHTML = '';

    if (!users || users.length === 0) {
        emptyState.style.display = 'block';
        tbody.parentElement.style.display = 'none';
        return;
    }

    emptyState.style.display = 'none';
    tbody.parentElement.style.display = 'table';

    users.forEach((user, index) => {
        const row = document.createElement('tr');
        const passwordDisplay = user.password_hash ?
            '<span class="text-muted"><i class="layui-icon layui-icon-password"></i> 已加密</span>' :
            (user.password ? '<span class="text-info"><i class="layui-icon layui-icon-ok"></i> ' + user.password.substring(0, 3) + '***</span>' :
             '<span class="text-muted"><i class="layui-icon layui-icon-close"></i> 未设置</span>');

        row.innerHTML = `
            <td>
                <div style="display: flex; align-items: center;">
                    <i class="layui-icon layui-icon-username" style="margin-right: 8px; color: var(--primary); font-size: 16px;"></i>
                    <strong>${user.username}</strong>
                </div>
            </td>
            <td>${passwordDisplay}</td>
            <td>
                <span class="layui-badge ${user.enabled ? 'layui-bg-green' : 'layui-bg-gray'}">
                    <i class="layui-icon layui-icon-${user.enabled ? 'ok' : 'close'}"></i>
                    ${user.enabled ? '启用' : '禁用'}
                </span>
            </td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-primary" onclick="editAuthUser(${index})" title="编辑用户">
                        <i class="layui-icon layui-icon-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteAuthUser(${index})" title="删除用户">
                        <i class="layui-icon layui-icon-delete"></i>
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// 添加认证用户
function addAuthUser() {
    // 清空表单
    document.getElementById('auth-user-index').value = '';
    document.getElementById('auth-modal-title-text').textContent = '添加认证用户';
    document.getElementById('auth-user-username').value = '';
    document.getElementById('auth-user-password').value = '';
    document.getElementById('auth-user-enabled').checked = true;

    // 重置密码输入框状态为隐藏
    const passwordInput = document.getElementById('auth-user-password');
    const wrapper = passwordInput.closest('.password-input-wrapper');
    const icon = wrapper.querySelector('.password-toggle-btn i');

    passwordInput.type = 'password';
    wrapper.classList.remove('password-visible');
    wrapper.classList.add('password-hidden');
    icon.className = 'layui-icon layui-icon-password';
    icon.title = '显示密码';

    // 显示模态框
    document.getElementById('auth-user-modal').style.display = 'flex';

    // 重新渲染 layui 表单
    if (typeof layui !== 'undefined') {
        layui.use(['form'], function(){
            layui.form.render();
        });
    }
}

// 编辑认证用户
function editAuthUser(index) {
    const users = AppState.currentConfig.socks5.auth_users || [];
    const user = users[index];

    if (user) {
        // 填充表单数据
        document.getElementById('auth-user-index').value = index;
        document.getElementById('auth-modal-title-text').textContent = '编辑认证用户';
        document.getElementById('auth-user-username').value = user.username || '';
        document.getElementById('auth-user-password').value = user.password || '';
        document.getElementById('auth-user-enabled').checked = user.enabled !== false;

        // 重置密码输入框状态为隐藏
        const passwordInput = document.getElementById('auth-user-password');
        const wrapper = passwordInput.closest('.password-input-wrapper');
        const icon = wrapper.querySelector('.password-toggle-btn i');

        passwordInput.type = 'password';
        wrapper.classList.remove('password-visible');
        wrapper.classList.add('password-hidden');
        icon.className = 'layui-icon layui-icon-password';
        icon.title = '显示密码';

        // 显示模态框
        document.getElementById('auth-user-modal').style.display = 'flex';

        // 重新渲染 layui 表单
        if (typeof layui !== 'undefined') {
            layui.use(['form'], function(){
                layui.form.render();
            });
        }
    }
}

// 删除认证用户
function deleteAuthUser(index) {
    const users = AppState.currentConfig.socks5.auth_users || [];
    const user = users[index];

    showConfirm(
        '删除确认',
        `确定要删除用户 "${user.username}" 吗？`,
        function () {
            // 用户点击确定删除
            users.splice(index, 1);
            AppState.currentConfig.socks5.auth_users = users;

            // 更新表格显示
            populateAuthUsersTable(users);

            // 显示成功消息
            showAlert('success', '用户删除成功！');

            // 触发保存到服务器
            saveConfig().then(() => {
                // 保存成功
            }).catch(error => {
                showAlert('error', '保存删除操作失败: ' + error.message);
            });
        }
    );
}

// 关闭认证用户模态框
function closeAuthUserModal() {
    document.getElementById('auth-user-modal').style.display = 'none';
}

// 保存认证用户
async function saveAuthUser() {
    const index = document.getElementById('auth-user-index').value;

    // 验证表单
    const username = document.getElementById('auth-user-username').value.trim();
    const password = document.getElementById('auth-user-password').value.trim();
    const enabled = document.getElementById('auth-user-enabled').checked;

    // 基本验证
    if (!username) {
        showAlert('error', '请输入用户名');
        return;
    }
    if (index === '' && !password) {
        showAlert('error', '新用户必须设置密码');
        return;
    }

    // 创建用户对象
    const user = {
        username,
        enabled
    };

    // 如果有密码，添加密码字段（编辑时如果密码为空则保留原密码）
    if (password) {
        user.password = password;
    } else if (index !== '') {
        // 编辑模式下如果密码为空，保留原密码
        const existingUsers = AppState.currentConfig.socks5.auth_users || [];
        const existingUser = existingUsers[parseInt(index)];
        if (existingUser.password) {
            user.password = existingUser.password;
        } else if (existingUser.password_hash) {
            user.password_hash = existingUser.password_hash;
        }
    }

    // 添加或更新用户
    if (index === '') {
        // 添加新用户
        if (!AppState.currentConfig.socks5.auth_users) {
            AppState.currentConfig.socks5.auth_users = [];
        }
        AppState.currentConfig.socks5.auth_users.push(user);
    } else {
        // 更新现有用户
        AppState.currentConfig.socks5.auth_users[parseInt(index)] = user;
    }

    // 保存配置到服务器
    const saved = await saveConfig();
    if (saved) {
        // 更新表格显示
        populateAuthUsersTable(AppState.currentConfig.socks5.auth_users);
        // 关闭模态框
        closeAuthUserModal();
    }
}

// 临时函数（开发中）
function addAclRule() {
    showAlert('warning', 'ACL规则管理功能开发中...');
}

function addProxyBindRule() {
    showAlert('warning', '绑定规则管理功能开发中...');
}

function addDnsHijackRule() {
    showAlert('warning', 'DNS劫持规则管理功能开发中...');
}

// 调试函数 - 检查enable_auth状态
function debugAuthStatus() {
    const authCheckbox = document.getElementById('enable_auth');
    const authSection = document.getElementById('auth-users-section');
    const authEnabled = AppState.currentConfig.socks5 && AppState.currentConfig.socks5.enable_auth;

    console.log('=== 调试信息 ===');
    console.log('配置中的enable_auth:', authEnabled);
    console.log('复选框元素:', authCheckbox);
    console.log('复选框checked状态:', authCheckbox ? authCheckbox.checked : 'not found');
    console.log('用户管理区域显示状态:', authSection ? authSection.style.display : 'not found');
    console.log('handleAuthToggle函数是否存在:', typeof handleAuthToggle);
    console.log('=================');

    // 如果状态不一致，强制同步
    if (authCheckbox && authCheckbox.checked !== authEnabled) {
        console.log('状态不一致，强制同步');
        authCheckbox.checked = authEnabled;

        // 重新渲染layui表单
        if (typeof layui !== 'undefined') {
            layui.use(['form'], function(){
                layui.form.render();
            });
        }

        // 根据正确状态显示/隐藏用户管理界面
        if (authSection) {
            authSection.style.display = authEnabled ? 'block' : 'none';
        }
    }

    // 测试handleAuthToggle函数
    if (authCheckbox && typeof handleAuthToggle === 'function') {
        console.log('测试handleAuthToggle函数...');
        // 模拟点击测试（注释掉避免影响用户）
        // handleAuthToggle(authCheckbox);
    }
}

// 直接的身份验证切换处理函数
function handleAuthToggle(checkbox) {
    const authUsersSection = document.getElementById('auth-users-section');
    console.log('handleAuthToggle called, checked:', checkbox.checked);

    // 更新配置状态
    if (AppState.currentConfig.socks5) {
        AppState.currentConfig.socks5.enable_auth = checkbox.checked;
    }

    // 立即显示/隐藏用户管理界面
    if (checkbox.checked) {
        console.log('显示用户管理界面');
        authUsersSection.style.display = 'block';

        // 如果没有用户，初始化空表格
        const currentUsers = AppState.currentConfig.socks5.auth_users || [];
        if (currentUsers.length === 0) {
            populateAuthUsersTable([]);
        }

        showAlert('success', '身份验证已启用，请添加认证用户');
    } else {
        console.log('隐藏用户管理界面');
        authUsersSection.style.display = 'none';
        showAlert('info', '身份验证已禁用');
    }

    // 保存配置
    saveConfig().then(() => {
        console.log('enable_auth配置保存完成');
    }).catch(error => {
        console.error('enable_auth配置保存失败:', error);
    });
}

// 切换密码显示/隐藏
function togglePasswordVisibility(inputId) {
    const passwordInput = document.getElementById(inputId);
    const wrapper = passwordInput.closest('.password-input-wrapper');
    const icon = wrapper.querySelector('.password-toggle-btn i');

    if (passwordInput.type === 'password') {
        // 显示密码
        passwordInput.type = 'text';
        wrapper.classList.remove('password-hidden');
        wrapper.classList.add('password-visible');

        // 尝试使用眼睛图标，如果不存在则使用其他图标
        try {
            icon.className = 'layui-icon layui-icon-ok-circle';
            icon.title = '隐藏密码';
        } catch (e) {
            icon.className = 'layui-icon layui-icon-password';
            icon.title = '隐藏密码';
        }
    } else {
        // 隐藏密码
        passwordInput.type = 'password';
        wrapper.classList.remove('password-visible');
        wrapper.classList.add('password-hidden');

        // 尝试使用眼睛图标，如果不存在则使用其他图标
        try {
            icon.className = 'layui-icon layui-icon-password';
            icon.title = '显示密码';
        } catch (e) {
            icon.className = 'layui-icon layui-icon-password';
            icon.title = '显示密码';
        }
    }

    console.log('密码可见性切换:', inputId, passwordInput.type);
}

// 页面加载后延迟检查状态
setTimeout(debugAuthStatus, 1000);

// 中国路由文件管理功能
async function loadChnroutesFile() {
    try {
        const response = await fetch('/api/file/chnroutes');
        const data = await response.json();

        if (data.success) {
            document.getElementById('chnroutes-editor').value = data.content;
            document.getElementById('chnroutes-size-value').textContent = data.size;
            document.getElementById('chnroutes-lines-value').textContent = data.lines;

            // 在前端计算数据行数
            updateDataLinesCount();
            updateScrollProgress();

            console.log('中国路由文件加载成功:', data);
        } else {
            showAlert('error', '加载中国路由文件失败: ' + data.error);
        }
    } catch (error) {
        console.error('加载中国路由文件失败:', error);
        showAlert('error', '加载中国路由文件失败: ' + error.message);
    }
}

async function saveChnroutesFile() {
    try {
        updateChnroutesStatus('saving', '保存中...');

        const content = document.getElementById('chnroutes-editor').value;
        const response = await fetch('/api/file/chnroutes/save', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content })
        });

        const data = await response.json();
        if (data.success) {
            updateChnroutesStatus('success', '保存成功');
            showAlert('success', '中国路由文件保存成功！');
            await loadChnroutesFile(); // 重新加载文件信息
            updateDataLinesCount(); // 更新数据行数
        } else {
            updateChnroutesStatus('error', '保存失败');
            showAlert('error', '保存中国路由文件失败: ' + data.error);
        }
    } catch (error) {
        updateChnroutesStatus('error', '保存失败');
        console.error('保存中国路由文件失败:', error);
        showAlert('error', '保存中国路由文件失败: ' + error.message);
    }
}

async function refreshChnroutesInfo() {
    await loadChnroutesFile();
    showAlert('info', '文件信息已刷新');
}

function uploadChnroutesFile(input) {
    const file = input.files[0];
    if (!file) return;

    if (confirm(`确定要上传文件 "${file.name}" 吗？这将覆盖当前的中国路由规则文件。`)) {
        const formData = new FormData();
        formData.append('file', file);

        updateChnroutesStatus('saving', '上传中...');

        fetch('/api/file/chnroutes/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateChnroutesStatus('success', '上传成功');
                showAlert('success', data.message);
                loadChnroutesFile(); // 重新加载文件内容
            } else {
                updateChnroutesStatus('error', '上传失败');
                showAlert('error', '上传失败: ' + data.error);
            }
        })
        .catch(error => {
            updateChnroutesStatus('error', '上传失败');
            showAlert('error', '上传失败: ' + error.message);
        });

        // 清空文件输入
        input.value = '';
    }
}

function downloadChnroutesFile() {
    const link = document.createElement('a');
    link.href = '/api/file/chnroutes/download';
    link.download = 'chnroutes.txt';
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function updateChnroutesStatus(status, text) {
    const statusElement = document.getElementById('chnroutes-status');
    const indicator = statusElement.querySelector('.status-indicator');
    const statusText = statusElement.querySelector('.status-text');

    // 移除所有状态类
    indicator.classList.remove('status-idle', 'status-saving', 'status-success', 'status-error');

    // 添加新状态类
    indicator.classList.add('status-' + status);
    statusText.textContent = text;

    // 3秒后恢复到空闲状态
    if (status === 'success' || status === 'error') {
        setTimeout(() => {
            indicator.classList.remove('status-saving', 'status-success', 'status-error');
            indicator.classList.add('status-idle');
            statusText.textContent = '准备就绪';
        }, 3000);
    }
}

// 更新滚动进度
function updateScrollProgress() {
    const editor = document.getElementById('chnroutes-editor');
    const scrollBar = document.getElementById('scroll-progress-bar');
    const scrollPosition = document.getElementById('scroll-position');
    const currentLine = document.getElementById('current-line');
    const scrollPercentage = document.getElementById('scroll-percentage');

    if (!editor || !scrollBar) {
        console.warn('滚动进度条元素未找到');
        return;
    }

    // 计算滚动进度
    const scrollTop = editor.scrollTop;
    const scrollHeight = editor.scrollHeight - editor.clientHeight;
    const progress = scrollHeight > 0 ? (scrollTop / scrollHeight) * 100 : 0;

    // 更新进度条
    scrollBar.style.width = progress + '%';

    // 确保进度条有最小宽度可见
    if (progress > 0 && progress < 1) {
        scrollBar.style.width = '2px';
    }

    // 更新百分比显示
    scrollPercentage.textContent = Math.round(progress) + '%';

    // 计算当前行
    const lineHeight = parseInt(window.getComputedStyle(editor).lineHeight);
    const currentLineNum = Math.round(scrollTop / lineHeight) + 1;
    currentLine.textContent = `第 ${currentLineNum} 行`;

    // 更新滚动位置描述
    if (progress === 0) {
        scrollPosition.textContent = '顶部';
    } else if (progress >= 99) {
        scrollPosition.textContent = '底部';
    } else if (progress < 33) {
        scrollPosition.textContent = '上部';
    } else if (progress < 67) {
        scrollPosition.textContent = '中部';
    } else {
        scrollPosition.textContent = '下部';
    }

    console.log('滚动进度:', progress.toFixed(1) + '%', '进度条宽度:', scrollBar.style.width);
}

// 实时计算数据行数（前端计算）
function updateDataLinesCount() {
    const editor = document.getElementById('chnroutes-editor');
    const content = editor.value;
    const lines = content.split('\n');

    // 计算有效数据行数（去除空行和注释行）
    let dataLines = 0;
    for (let line of lines) {
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('#')) {
            dataLines++;
        }
    }

    // 更新显示
    const dataLinesElement = document.getElementById('chnroutes-data-lines-value');
    if (dataLinesElement) {
        dataLinesElement.textContent = dataLines;
    }
}

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 创建防抖的数据行数计算函数
const debouncedUpdateDataLinesCount = debounce(updateDataLinesCount, 500);

// 端口警告检查函数
function checkPortWarning(input) {
    const port = parseInt(input.value);
    const warningId = input.id.replace('_port', '-port-warning');
    const warningElement = document.getElementById(warningId);

    if (warningElement) {
        if (port > 0 && port < 1024) {
            warningElement.classList.add('show');
            // 为输入框添加黄色边框和闪烁效果
            input.classList.add('port-input-warning');
        } else {
            warningElement.classList.remove('show');
            // 移除输入框的警告样式
            input.classList.remove('port-input-warning');
        }
    }
}

// 处理身份验证开关切换
async function handleAuthToggle(checkbox) {
    const authUsersSection = document.getElementById('auth-users-section');
    const enable = checkbox.checked;

    // 立即显示或隐藏用户管理区域
    if (authUsersSection) {
        if (enable) {
            authUsersSection.style.display = 'block';

            // 动态加载用户列表
            try {
                await loadAuthUsers();
            } catch (error) {
                console.error('加载用户列表失败:', error);
                showAlert('error', '加载用户列表失败: ' + error.message);
            }
        } else {
            authUsersSection.style.display = 'none';
        }
    }
}

// 动态加载认证用户列表
async function loadAuthUsers() {
    try {
        const response = await fetch('/api/config');
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        if (data.success && data.data.socks5 && data.data.socks5.auth_users) {
            populateAuthUsersTable(data.data.socks5.auth_users);
        } else {
            populateAuthUsersTable([]); // 显示空状态
        }
    } catch (error) {
        console.error('加载认证用户失败:', error);
        populateAuthUsersTable([]); // 出错时显示空状态
        throw error;
    }
}

// 初始化端口警告状态
function initializePortWarnings() {
    ['socks5_port', 'dns_port', 'web_port'].forEach(portId => {
        const input = document.getElementById(portId);
        if (input) {
            checkPortWarning(input);
        }
    });
}


// 在编辑器内容变化时使用防抖函数
document.addEventListener('DOMContentLoaded', function() {
    debug('页面DOM加载完成');

    // 检查关键元素
    const tabButtons = document.querySelectorAll('.tab-btn');
    const configContents = document.querySelectorAll('.config-content');

    debug('标签按钮数量', tabButtons.length);
    debug('配置内容数量', configContents.length);
    debug('配置内容ID列表', Array.from(configContents).map(el => el.id));

    
    const editor = document.getElementById('chnroutes-editor');
    if (editor) {
        editor.addEventListener('input', debouncedUpdateDataLinesCount);
    }

    // 初始化端口警告
    initializePortWarnings();

    // 初始化用户认证管理区域显示状态
    const authUsersSection = document.getElementById('auth-users-section');
    const enableAuthCheckbox = document.getElementById('enable_auth');
    if (enableAuthCheckbox && authUsersSection) {
        if (enableAuthCheckbox.checked) {
            authUsersSection.style.display = 'block';
        } else {
            authUsersSection.style.display = 'none';
        }
    }
});

// 全局确认函数，优先使用layui的layer，fallback到原生confirm
function showConfirm(title, message, onConfirm, onCancel) {
    if (typeof layui !== 'undefined' && layui.layer) {
        layui.layer.confirm(
            message,
            {
                icon: 3,
                title: title,
                btn: ['确定', '取消'],
                skin: 'layui-layer-molv'
            },
            function (layerIndex) {
                layui.layer.close(layerIndex);
                if (onConfirm) onConfirm();
            },
            function (layerIndex) {
                layui.layer.close(layerIndex);
                if (onCancel) onCancel();
            }
        );
    } else {
        // Fallback to native confirm
        if (confirm(message.replace(/<br>/g, '\n'))) {
            if (onConfirm) onConfirm();
        } else {
            if (onCancel) onCancel();
        }
    }
}

console.log('SmartProxy 现代化控制台脚本加载完成');