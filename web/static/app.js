// 调试开关
const DEBUG_MODE = false;

// 全局状态管理
const AppState = {
    currentConfig: {},
    currentTab: 'basic',
    autoRefreshInterval: null,
    isInitialized: false,
    layuiForm: null,
    layuiLayer: null,
    layuiElement: null,
    layuiLaydate: null,
};

// 安全的DOM元素获取函数
function safeGetElement(id) {
    const element = document.getElementById(id);
    return element || null;
}

// 安全的checkbox值获取函数
function safeGetCheckboxValue(id) {
    const element = safeGetElement(id);
    return element ? element.checked : false;
}

// 安全的input值获取函数
function safeGetInputValue(id) {
    const element = safeGetElement(id);
    return element ? element.value : '';
}

// DOM 加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

// 初始化应用
async function initializeApp() {
    try {
        updateStatus('checking', '连接中...');
        if (typeof layui !== 'undefined') {
            layui.use(['form', 'layer', 'element', 'laydate'], function(){
                AppState.layuiForm = layui.form;
                AppState.layuiLayer = layui.layer;
                AppState.layuiElement = layui.element;
                AppState.layuiLaydate = layui.laydate;
                AppState.layuiForm.render();
                AppState.layuiElement.render();
            });
        }
        await loadConfig();
        await loadUsers(); // 分开加载用户数据
        await refreshData();
        startAutoRefresh();
        setupAutoSave();
        AppState.isInitialized = true;
        showAlert('success', '智能代理控制台已成功加载');
    } catch (error) {
        console.error('应用初始化失败:', error);
        showAlert('error', '应用初始化失败: ' + error.message);
        updateStatus('offline', '连接失败');
    }
}

// 设置自动保存功能
function setupAutoSave() {
    let saveTimeout;
    let lastSaveTime = 0;
    const autoSave = async () => {
        clearTimeout(saveTimeout);
        saveTimeout = setTimeout(async () => {
            try {
                collectFormData(); // 确保 currentConfig 是最新的
                const success = await saveConfig(); // 保存到服务器

                // 显示自动保存提示（避免频繁显示）
                const now = Date.now();
                if (success && (now - lastSaveTime > 5000)) { // 5秒内只显示一次
                    showAlert('autosave', '配置已自动保存');
                    lastSaveTime = now;
                } else if (!success) {
                    showAlert('error', '自动保存失败，请检查网络连接');
                }
            } catch (error) {
                console.error('自动保存失败:', error);
                showAlert('error', '自动保存失败: ' + error.message);
            }
        }, 2000);
    };

    const inputs = document.querySelectorAll('input[type="text"], input[type="number"], input[type="checkbox"], select, textarea');
    inputs.forEach(input => {
        if (input.closest('.modal')) return;
        input.addEventListener('change', autoSave);
        input.addEventListener('input', autoSave);
        if (input.id && input.id.includes('_port')) {
            input.addEventListener('input', () => checkPortWarning(input));
        }
    });

    if (AppState.layuiForm) {
        AppState.layuiForm.on('select', autoSave); // 通用select监听
        AppState.layuiForm.on('checkbox', function(data){
            // 排除enable_auth，它有专门的handleAuthToggle处理
            if(data.elem.id !== 'enable_auth') {
                autoSave();
            }
        });
    }
}

// 更新状态显示
function updateStatus(status, text) {
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    statusDot.className = 'status-dot';
    switch (status) {
        case 'online': statusDot.classList.add('online'); break;
        case 'offline': statusDot.classList.add('offline'); break;
        case 'checking': statusDot.classList.add('checking'); break;
    }
    statusText.textContent = text;
}

// 切换标签页
function switchTab(tabName, event) {
    // 安全检查：确保元素存在
    const buttons = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.config-content');
    const targetContent = document.getElementById(`${tabName}-config`);

    if (!buttons.length || !contents.length || !targetContent) {
        console.error('switchTab: Required elements not found');
        return;
    }

    // 移除所有active类
    buttons.forEach(btn => btn.classList.remove('active'));
    contents.forEach(content => content.classList.remove('active'));

    // 添加active类到当前元素
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    } else {
        // 如果event为null，通过tabName查找对应的按钮
        const targetButton = Array.from(buttons).find(btn =>
            btn.getAttribute('onclick') && btn.getAttribute('onclick').includes(tabName)
        );
        if (targetButton) {
            targetButton.classList.add('active');
        }
    }

    if (targetContent) {
        targetContent.classList.add('active');
    }
    AppState.currentTab = tabName;

    // 刷新相应的表格
    try {
        if (tabName === 'hijack') {
            populateDnsHijackRulesTable();
        } else if (tabName === 'acl') { // 'acl' is the ID for the router rules tab now
            populateRouterRulesTable();
        } else if (tabName === 'chnroutes') {
            loadChnroutesFile();
        }
    } catch (error) {
        console.error(`Error loading tab ${tabName}:`, error);
    }
}

// 加载完整配置 (除用户外)
async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (data.success) {
            AppState.currentConfig = data.data;
            populateConfigForms(data.data);
        } else {
            throw new Error(data.error || '配置加载失败');
        }
    } catch (error) {
        console.error('加载配置失败:', error);
        throw error;
    }
}

// 加载用户数据
async function loadUsers() {
    try {
        const response = await fetch('/api/users');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (data.success) {
            if (!AppState.currentConfig.socks5) AppState.currentConfig.socks5 = {};
            AppState.currentConfig.socks5.auth_users = data.data;
            populateAuthUsersTable(data.data);
        } else {
            throw new Error(data.error || '用户数据加载失败');
        }
    } catch (error) {
        console.error('加载用户数据失败:', error);
        throw error;
    }
}

// 填充配置表单
function populateConfigForms(config) {
    if (config.listener) {
        const socks5PortElement = safeGetElement('socks5_port');
        const webPortElement = safeGetElement('web_port');
        const dnsPortElement = safeGetElement('dns_port');
        const ipv6EnabledElement = safeGetElement('ipv6_enabled');

        if (socks5PortElement) socks5PortElement.value = config.listener.socks5_port || 1080;
        if (webPortElement) webPortElement.value = config.listener.web_port || 8080;
        if (dnsPortElement) dnsPortElement.value = config.listener.dns_port || 1053;
        if (ipv6EnabledElement) ipv6EnabledElement.checked = config.listener.ipv6_enabled || false;
    }

    if (config.socks5) {
        const maxConnectionsElement = safeGetElement('max_connections');
        const cleanupIntervalElement = safeGetElement('cleanup_interval');
        const enableAuthCheckbox = safeGetElement('enable_auth');
        const authUsersSection = safeGetElement('auth-users-section');

        if (maxConnectionsElement) maxConnectionsElement.value = config.socks5.max_connections || 1000;
        if (cleanupIntervalElement) cleanupIntervalElement.value = config.socks5.cleanup_interval || 300;
        if (enableAuthCheckbox) enableAuthCheckbox.checked = config.socks5.enable_auth || false;

        // 初始化时直接设置显示状态，不触发saveConfig
        if (authUsersSection) {
            authUsersSection.style.display = enableAuthCheckbox.checked ? 'block' : 'none';
        }
    }
    if (config.connection_settings) {
        const tcpTimeoutElement = safeGetElement('tcp_timeout_seconds');
        const udpTimeoutElement = safeGetElement('udp_timeout_seconds');

        if (tcpTimeoutElement) tcpTimeoutElement.value = config.connection_settings.tcp_timeout_seconds || 60;
        if (udpTimeoutElement) udpTimeoutElement.value = config.connection_settings.udp_timeout_seconds || 300;
    }

    if (config.router && config.router.chnroutes) {
        const chnroutesEnableElement = safeGetElement('chnroutes_enable');
        const chnroutesPathElement = safeGetElement('chnroutes_path');

        if (chnroutesEnableElement) chnroutesEnableElement.checked = config.router.chnroutes.enable || false;
        if (chnroutesPathElement) chnroutesPathElement.value = config.router.chnroutes.path || 'conf/chnroutes.txt';
    }

    if (config.dns) {
        const dnsEnabledElement = safeGetElement('dns_enabled');
        if (dnsEnabledElement) dnsEnabledElement.checked = config.dns.enabled || false;

        if (config.dns.cache) {
            const dnsCacheMaxSizeElement = safeGetElement('dns_cache_max_size');
            const dnsCacheDefaultTtlElement = safeGetElement('dns_cache_default_ttl');
            const dnsCacheCleanupIntervalElement = safeGetElement('dns_cache_cleanup_interval');

            if (dnsCacheMaxSizeElement) dnsCacheMaxSizeElement.value = config.dns.cache.max_size || 2000;
            if (dnsCacheDefaultTtlElement) dnsCacheDefaultTtlElement.value = config.dns.cache.default_ttl || 300;
            if (dnsCacheCleanupIntervalElement) dnsCacheCleanupIntervalElement.value = config.dns.cache.cleanup_interval || 60;
        }
        if (config.dns.groups) {
            const dnsGroupsCnElement = safeGetElement('dns_groups_cn');
            const dnsGroupsForeignElement = safeGetElement('dns_groups_foreign');

            if (dnsGroupsCnElement) dnsGroupsCnElement.value = (config.dns.groups.cn || []).filter(s => s.trim()).join('\n');
            if (dnsGroupsForeignElement) dnsGroupsForeignElement.value = (config.dns.groups.foreign || []).filter(s => s.trim()).join('\n');
        }
    }

    if (config.traffic_detection) {
        const trafficDetectionElement = document.getElementById('traffic_detection_enabled');
        if (trafficDetectionElement) trafficDetectionElement.checked = config.traffic_detection.enabled || false;
        if (config.traffic_detection.enhanced_probing) {
            const probing = config.traffic_detection.enhanced_probing;
            const enhancedProbingElement = document.getElementById('enhanced_probing_enable');
            const sniExtractionElement = document.getElementById('sni_extraction');
            const httpValidationElement = document.getElementById('http_validation');
            if (enhancedProbingElement) enhancedProbingElement.checked = probing.enable || false;
            if (sniExtractionElement) sniExtractionElement.checked = probing.sni_extraction || false;
            if (httpValidationElement) httpValidationElement.checked = probing.http_validation || false;
            const maxInitialDataSizeElement = document.getElementById('max_initial_data_size');
            const validationTimeoutElement = document.getElementById('validation_timeout_ms');
            const probingPortsElement = document.getElementById('probing_ports');
            if (maxInitialDataSizeElement) maxInitialDataSizeElement.value = probing.max_initial_data_size || 4096;
            if (validationTimeoutElement) validationTimeoutElement.value = probing.validation_timeout_ms || 1500;
            if (probingPortsElement) probingPortsElement.value = (probing.probing_ports || []).join(',');
        }
    }
    
    if (config.logging) {
        const logLevelElement = document.getElementById('log_level');
        const enableUserLogsElement = document.getElementById('enable_user_logs');
        const enableAccessLogsElement = document.getElementById('enable_access_logs');
        const logFileElement = document.getElementById('log_file');

        if (logLevelElement) logLevelElement.value = config.logging.level || 'info';
        if (enableUserLogsElement) enableUserLogsElement.checked = config.logging.enable_user_logs || false;
        if (enableAccessLogsElement) enableAccessLogsElement.checked = config.logging.enable_access_logs || false;
        if (logFileElement) logFileElement.value = config.logging.log_file || 'proxy.log';
    }

    // 重新渲染 layui 表单组件
    if (AppState.layuiForm) { AppState.layuiForm.render(); }
    initializePortWarnings();
    loadChnroutesFile(); // 加载中国路由文件
    populateProxyNodesTable((config.router?.proxy_nodes || config.proxy_nodes || []));
    // 初始化时不填充所有表格以提高性能，在切换到相应标签页时再填充
}

// 刷新数据
async function refreshData() {
    try {
        const statusResponse = await fetch('/api/status');
        const statusData = await statusResponse.json();
        if (statusData.success) {
            document.getElementById('active-connections').textContent = statusData.data.active_connections || '0';
            updateStatus('online', '运行中');
        } else { updateStatus('offline', '离线'); }

        const statsResponse = await fetch('/api/stats');
        const statsData = await statsResponse.json();
        if (statsData.success) {
            document.getElementById('dns-queries').textContent = statsData.data.dns?.total_queries || '0';
            document.getElementById('uptime').textContent = statsData.data.uptime || 'N/A';
            if (statsData.data.proxy) { document.getElementById('proxy-nodes').textContent = Object.keys(statsData.data.proxy).length; }
        }
    } catch (error) {
        console.error('刷新数据失败:', error);
        updateStatus('offline', '连接失败');
    }
}

// 启动自动刷新
function startAutoRefresh() {
    if (AppState.autoRefreshInterval) clearInterval(AppState.autoRefreshInterval);
    AppState.autoRefreshInterval = setInterval(refreshData, 5000);
}

// 保存配置到服务器
async function saveConfig() {
    try {
        console.log('saveConfig: 开始保存配置');
        const response = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(AppState.currentConfig)
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        console.log('saveConfig: 服务器响应', data);
        if (data.success) {
            // 不在这里显示成功消息，让调用方决定
            return true;
        } else {
            throw new Error(data.error || '配置保存失败');
        }
    } catch (error) {
        console.error('保存配置失败:', error);
        // 不在这里显示错误消息，让调用方决定
        return false;
    }
}

// 从表单收集配置数据
function collectFormData() {
    const config = { ...AppState.currentConfig };

    // 基础配置
    config.listener = {
        socks5_port: parseInt(document.getElementById('socks5_port').value) || 1080,
        web_port: parseInt(document.getElementById('web_port').value) || 8080,
        dns_port: parseInt(document.getElementById('dns_port').value) || 1053,
        ipv6_enabled: (document.getElementById('ipv6_enabled') || {}).checked || false
    };

    if (!config.socks5) config.socks5 = {};
    config.socks5.max_connections = parseInt(document.getElementById('max_connections').value) || 1000;
    config.socks5.cleanup_interval = parseInt(document.getElementById('cleanup_interval').value) || 300;
    config.socks5.enable_auth = (document.getElementById('enable_auth') || {}).checked || false;
    config.socks5.auth_users = AppState.currentConfig.socks5?.auth_users || []; // 用户列表单独管理

    config.connection_settings = {
        tcp_timeout_seconds: parseInt(document.getElementById('tcp_timeout_seconds').value) || 60,
        udp_timeout_seconds: parseInt(document.getElementById('udp_timeout_seconds').value) || 300
    };

    if (!config.router) {
        config.router = {};
    }
    if (!config.router.chnroutes) {
        config.router.chnroutes = {};
    }
    const chnroutesEnableElement = document.getElementById('chnroutes_enable');
    const chnroutesPathElement = document.getElementById('chnroutes_path');
    config.router.chnroutes.enable = chnroutesEnableElement ? chnroutesEnableElement.checked : false;
    config.router.chnroutes.path = chnroutesPathElement ? chnroutesPathElement.value : 'conf/chnroutes.txt';

    if (!config.dns) config.dns = {};
    const dnsEnabledElement = document.getElementById('dns_enabled');
    config.dns.enabled = dnsEnabledElement ? dnsEnabledElement.checked : false;
    config.dns.cache = {
        max_size: parseInt(document.getElementById('dns_cache_max_size').value) || 2000,
        default_ttl: parseInt(document.getElementById('dns_cache_default_ttl').value) || 300,
        cleanup_interval: parseInt(document.getElementById('dns_cache_cleanup_interval').value) || 60
    };
    const dnsGroupsCnElement = document.getElementById('dns_groups_cn');
    const dnsGroupsForeignElement = document.getElementById('dns_groups_foreign');
    config.dns.groups = {
        cn: dnsGroupsCnElement ? dnsGroupsCnElement.value.split('\n').map(s => s.trim()).filter(s => s) : [],
        foreign: dnsGroupsForeignElement ? dnsGroupsForeignElement.value.split('\n').map(s => s.trim()).filter(s => s) : []
    };
    config.dns.hijack_rules = AppState.currentConfig.dns?.hijack_rules || []; // 劫持规则单独管理

    if (!config.traffic_detection) config.traffic_detection = {};
    config.traffic_detection.enabled = safeGetCheckboxValue('traffic_detection_enabled');
    if (!config.traffic_detection.enhanced_probing) config.traffic_detection.enhanced_probing = {};
    const probing = config.traffic_detection.enhanced_probing;
    probing.enable = safeGetCheckboxValue('enhanced_probing_enable');
    probing.sni_extraction = safeGetCheckboxValue('sni_extraction');
    probing.http_validation = safeGetCheckboxValue('http_validation');
    probing.max_initial_data_size = parseInt(safeGetInputValue('max_initial_data_size')) || 4096;
    probing.validation_timeout_ms = parseInt(safeGetInputValue('validation_timeout_ms')) || 1500;
    const probingPortsElement = safeGetElement('probing_ports');
    if (probingPortsElement) {
        probing.probing_ports = probingPortsElement.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
    } else {
        probing.probing_ports = [];
    }

    if (!config.logging) config.logging = {};
    config.logging.level = safeGetInputValue('log_level') || 'info';
    config.logging.enable_user_logs = safeGetCheckboxValue('enable_user_logs');
    config.logging.enable_access_logs = safeGetCheckboxValue('enable_access_logs');
    config.logging.log_file = safeGetInputValue('log_file') || 'proxy.log';

    AppState.currentConfig = config;
    return config;
}

// 显示警告消息 - 右上角悬浮条幅效果
function showAlert(type, message) {
    console.log('showAlert被调用:', type, message);
    const alertId = 'alert-' + Date.now();

    // 创建alert容器和内容
    const alertContainer = document.createElement('div');
    alertContainer.id = alertId;
    alertContainer.className = `alert-toast alert-${type}`;

    // 根据消息长度决定是否需要换行样式
    if (message.length > 30) {
        alertContainer.classList.add('long-message');
    }

    // 根据类型选择图标和自动隐藏时间
    let iconClass = '';
    let autoHide = 3000; // 默认3秒自动隐藏
    switch(type) {
        case 'success':
            iconClass = 'layui-icon-ok-circle';
            autoHide = 3000;
            break;
        case 'error':
            iconClass = 'layui-icon-close';
            autoHide = 5000; // 错误消息显示5秒
            break;
        case 'warning':
            iconClass = 'layui-icon-warning';
            autoHide = 4000; // 警告消息显示4秒
            break;
        case 'info':
            iconClass = 'layui-icon-about';
            autoHide = 3000;
            break;
        case 'autosave':
            iconClass = 'layui-icon-refresh';
            autoHide = 2000; // 自动保存消息只显示2秒，更简洁
            break;
        default:
            iconClass = 'layui-icon-about';
            autoHide = 3000;
    }

    // 根据类型获取标题
    const typeConfig = {
        success: { title: '成功', icon: 'layui-icon-ok-circle' },
        error: { title: '错误', icon: 'layui-icon-close' },
        warning: { title: '警告', icon: 'layui-icon-warning' },
        info: { title: '信息', icon: 'layui-icon-about' },
        autosave: { title: '自动保存', icon: 'layui-icon-refresh' },
        default: { title: '通知', icon: 'layui-icon-about' }
    };
    const config = typeConfig[type] || typeConfig.default;

    // 检查是否需要长消息样式
    if (message.length > 60) {
        alertContainer.classList.add('long-message');
    }

    alertContainer.innerHTML = `
        <div class="alert-icon">
            <i class="layui-icon ${config.icon}"></i>
        </div>
        <div class="alert-content">
            <div class="alert-title">${config.title}</div>
            <div class="alert-message">${message}</div>
        </div>
        <div class="alert-close">
            <i class="layui-icon layui-icon-close"></i>
        </div>
    `;

    // 添加到页面右上角
    document.body.appendChild(alertContainer);

    // 触发进入动画
    setTimeout(() => {
        alertContainer.classList.add('show');
    }, 50); // 增加延迟确保DOM更新完成

    // 自动隐藏（点击关闭或定时）
    const hideTimeout = setTimeout(() => {
        alertContainer.classList.add('hide');
        setTimeout(() => {
            if (document.getElementById(alertId)) {
                alertContainer.remove();
            }
        }, 400); // 等待退出动画完成
    }, autoHide); // 使用动态的隐藏时间

    // 鼠标悬停时取消自动隐藏
    alertContainer.addEventListener('mouseenter', () => {
        clearTimeout(hideTimeout);
    });

    alertContainer.addEventListener('mouseleave', () => {
        setTimeout(() => {
            alertContainer.classList.add('hide');
            setTimeout(() => {
                if (document.getElementById(alertId)) {
                    alertContainer.remove();
                }
            }, 400);
        }, 1000); // 鼠标离开后1秒隐藏
    });

    // 添加关闭事件监听器
    const closeButton = alertContainer.querySelector('.alert-close');
    if (closeButton) {
        closeButton.addEventListener('click', (e) => {
            e.stopPropagation(); // 阻止事件冒泡
            alertContainer.classList.add('hide');
            setTimeout(() => {
                if (document.getElementById(alertId)) {
                    alertContainer.remove();
                }
            }, 400);
        });
    }

    return alertContainer; // 返回容器引用，方便调试
}

// 生成星级显示
function generateStars(weight) {
    const maxWeight = 10;
    const filledStars = Math.round(weight);
    const emptyStars = maxWeight - filledStars;
    let stars = '';
    for (let i = 0; i < filledStars; i++) stars += '<i class="layui-icon layui-icon-rate-solid" style="color: #FFB800; font-size: 14px;"></i>';
    for (let i = 0; i < emptyStars; i++) stars += '<i class="layui-icon layui-icon-rate" style="color: #ddd; font-size: 14px;"></i>';
    return stars;
}

// 填充代理节点表格
function populateProxyNodesTable(nodes) {
    const tbody = document.getElementById('proxy-nodes-tbody');
    tbody.innerHTML = '';
    if (!nodes || nodes.length === 0) return;

    nodes.forEach((node, index) => {
        const row = document.createElement('tr');
        // Handle different node structures (legacy vs current)
        const name = node.name || node.identifier || 'Unknown';
        const type = node.type || node.protocol || 'unknown';
        const address = node.address || node.ip || 'Unknown';
        const port = node.port || 0;
        const weight = node.weight || 5;
        const enabled = node.enabled !== false;

        row.innerHTML = `
            <td><div style="display: flex; align-items: center;"><i class="layui-icon layui-icon-component" style="margin-right: 8px; color: var(--primary); font-size: 16px;"></i><strong>${name}</strong></div></td>
            <td><span class="layui-badge layui-bg-blue">${type}</span></td>
            <td>${address}</td>
            <td><span style="font-weight: 500; color: #495057;">${port}</span></td>
            <td><div style="display: flex; align-items: center; gap: 2px;">${generateStars(weight)}<span style="margin-left: 4px; font-size: 12px; color: #6c757d;">(${weight})</span></div></td>
            <td><span class="layui-badge ${enabled ? 'layui-bg-green' : 'layui-bg-gray'}"><i class="layui-icon layui-icon-${enabled ? 'ok' : 'close'}"></i>${enabled ? '启用' : '禁用'}</span></td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-primary" onclick="editProxyNode(${index})"><i class="layui-icon layui-icon-edit"></i> 编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteProxyNode(${index})"><i class="layui-icon layui-icon-delete"></i> 删除</button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
    // Update the proxy nodes count
    const enabledCount = nodes.filter(n => n.enabled !== false).length;
    const countElement = document.getElementById('proxy-nodes');
    if (countElement) {
        countElement.textContent = enabledCount;
    }
}

// 添加代理节点
function addProxyNode() {
    const nodeIndex = document.getElementById('node-index');
    const modalTitle = document.getElementById('modal-title-text');
    const nodeIdentifier = document.getElementById('node-identifier');
    const nodeProtocol = document.getElementById('node-protocol');
    const nodeIp = document.getElementById('node-ip');
    const nodePort = document.getElementById('node-port');
    const nodeWeight = document.getElementById('node-weight');
    const nodeEnabled = document.getElementById('node-enabled');
    const modal = document.getElementById('proxy-node-modal');

    if (nodeIndex) nodeIndex.value = '';
    if (modalTitle) modalTitle.textContent = '添加代理节点';
    if (nodeIdentifier) nodeIdentifier.value = '';
    if (nodeProtocol) nodeProtocol.value = 'socks5';
    if (nodeIp) nodeIp.value = '';
    if (nodePort) nodePort.value = '';
    if (nodeWeight) nodeWeight.value = '5';
    if (nodeEnabled) nodeEnabled.checked = true;
    if (modal) modal.style.display = 'flex';
    if (AppState.layuiForm) AppState.layuiForm.render();
}

// 编辑代理节点
function editProxyNode(index) {
    // Support both router.proxy_nodes and legacy proxy_nodes structure
    const nodes = AppState.currentConfig.router?.proxy_nodes || AppState.currentConfig.proxy_nodes || [];
    const node = nodes[index];
    if (node) {
        const nodeIndex = document.getElementById('node-index');
        const modalTitle = document.getElementById('modal-title-text');
        const nodeIdentifier = document.getElementById('node-identifier');
        const nodeProtocol = document.getElementById('node-protocol');
        const nodeIp = document.getElementById('node-ip');
        const nodePort = document.getElementById('node-port');
        const nodeWeight = document.getElementById('node-weight');
        const nodeEnabled = document.getElementById('node-enabled');
        const modal = document.getElementById('proxy-node-modal');

        if (nodeIndex) nodeIndex.value = index;
        if (modalTitle) modalTitle.textContent = '编辑代理节点';
        // Handle different field names between structures
        if (nodeIdentifier) nodeIdentifier.value = node.name || node.identifier || '';
        if (nodeProtocol) nodeProtocol.value = node.type || node.protocol || 'socks5';
        if (nodeIp) nodeIp.value = node.address || node.ip || '';
        if (nodePort) nodePort.value = node.port || '';
        if (nodeWeight) nodeWeight.value = node.weight || '5';
        if (nodeEnabled) nodeEnabled.checked = node.enabled !== false;
        if (modal) modal.style.display = 'flex';
        if (AppState.layuiForm) AppState.layuiForm.render();
    }
}

// 删除代理节点
function deleteProxyNode(index) {
    // Support both router.proxy_nodes and legacy proxy_nodes structure
    const nodes = AppState.currentConfig.router?.proxy_nodes || AppState.currentConfig.proxy_nodes || [];
    const node = nodes[index];
    const nodeName = node.name || node.identifier || 'Unknown';
    const nodeAddress = node.address || node.ip || 'Unknown';
    const nodePort = node.port || 'Unknown';

    showConfirm('删除确认', `确定要删除代理节点 "${nodeName}" 吗？<br>IP: ${nodeAddress}:${nodePort}`, async function () {
        // Update both structures for compatibility
        if (AppState.currentConfig.router?.proxy_nodes) {
            AppState.currentConfig.router.proxy_nodes.splice(index, 1);
        }
        if (AppState.currentConfig.proxy_nodes) {
            AppState.currentConfig.proxy_nodes.splice(index, 1);
        }

        const saved = await saveConfig();
        if (saved) {
            showAlert('success', '代理节点删除成功！');
            populateProxyNodesTable(AppState.currentConfig.router?.proxy_nodes || AppState.currentConfig.proxy_nodes || []);
        }
    });
}

// 关闭代理节点模态框
function closeProxyNodeModal() {
    document.getElementById('proxy-node-modal').style.display = 'none';
}

// 保存代理节点
async function saveProxyNode() {
    const index = document.getElementById('node-index').value;
    const identifier = document.getElementById('node-identifier').value.trim();
    const protocol = document.getElementById('node-protocol').value;
    const ip = document.getElementById('node-ip').value.trim();
    const port = parseInt(document.getElementById('node-port').value);
    const weight = parseInt(document.getElementById('node-weight').value);
    const enabled = document.getElementById('node-enabled').checked;

    if (!identifier || !ip || isNaN(port) || port < 0 || port > 65535) {
        showAlert('error', '请填写所有必填项并输入有效端口号');
        return;
    }
    const node = {
        name: identifier, // Match backend structure
        type: protocol, // Match backend structure
        address: ip, // Match backend structure
        port: port,
        weight: weight || 5,
        enabled: enabled,
        auth_method: 'none',
        description: `${protocol} proxy - ${ip}:${port}` // Add description
    };
    if (protocol === 'direct') node.port = 0;

    // Fix: Support both config structures
    if (!AppState.currentConfig.router) {
        AppState.currentConfig.router = {};
    }
    if (!AppState.currentConfig.router.proxy_nodes) {
        AppState.currentConfig.router.proxy_nodes = [];
    }
    // Also support legacy proxy_nodes
    if (!AppState.currentConfig.proxy_nodes) {
        AppState.currentConfig.proxy_nodes = [];
    }

    if (index === '') {
        AppState.currentConfig.router.proxy_nodes.push(node);
        AppState.currentConfig.proxy_nodes.push(node); // Update both for compatibility
    } else {
        const idx = parseInt(index);
        AppState.currentConfig.router.proxy_nodes[idx] = node;
        AppState.currentConfig.proxy_nodes[idx] = node; // Update both for compatibility
    }

    const saved = await saveConfig();
    if (saved) {
        showAlert('success', '代理节点保存成功！');
        closeProxyNodeModal();
        populateProxyNodesTable(AppState.currentConfig.router?.proxy_nodes || AppState.currentConfig.proxy_nodes || []);
    }
}

// 键盘事件处理
document.addEventListener('keydown', function(e) {
    if (e.key === 'F5') { e.preventDefault(); refreshData(); }
    if (e.ctrlKey && e.key === 't') { e.preventDefault(); testAPIs(); }
});

// 测试所有API (此处省略具体实现)
function testAPIs() {
    showAlert('info', 'API测试功能待实现');
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
        const rateLimit = user.rate_limit || {};
        const connLimit = user.connection_limit || {};
        const row = document.createElement('tr');
        const formatValue = (value, unit = '', isRate = false) => {
            if (value === null || typeof value === 'undefined' || value === 0) {
                return `<span class="text-muted">不限制</span>`;
            }
            if (isRate) {
                return `<strong>${(value / 1024).toFixed(1)}</strong> <span class="text-muted">${unit}</span>`;
            }
            return `<strong>${value}</strong> <span class="text-muted">${unit}</span>`;
        };

        row.innerHTML = `
            <td><strong>${user.username}</strong></td>
            <td><span class="layui-badge ${user.enabled ? 'layui-bg-green' : 'layui-bg-gray'}">${user.enabled ? '启用' : '禁用'}</span></td>
            <td>${formatValue(connLimit.max_connections)}</td>
            <td>${formatValue(rateLimit.download_bps, 'KB/s', true)}</td>
            <td>${formatValue(rateLimit.upload_bps, 'KB/s', true)}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-primary" onclick="editAuthUser(${index})"><i class="layui-icon layui-icon-edit"></i> 编辑</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteAuthUser(${index})"><i class="layui-icon layui-icon-delete"></i> 删除</button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// 添加认证用户
function addAuthUser() {
    const authUserIndex = document.getElementById('auth-user-index');
    const authModalTitle = document.getElementById('auth-modal-title-text');
    const authUserUsername = document.getElementById('auth-user-username');
    const authUserPassword = document.getElementById('auth-user-password');
    const authUserEnabled = document.getElementById('auth-user-enabled');

    const aclMaxConnections = document.getElementById('acl-max-connections');
    const aclRateLimitDown = document.getElementById('acl-rate-limit-down');
    const aclRateLimitUp = document.getElementById('acl-rate-limit-up');
    const aclExpiresAfter = document.getElementById('acl-expires-after');
    const aclUserGroups = document.getElementById('acl-user-groups');
    const aclAllowFrom = document.getElementById('acl-allow-from');
    const aclBlockFrom = document.getElementById('acl-block-from');
    const timeRulesList = document.getElementById('time-rules-list');

    if (authUserIndex) authUserIndex.value = '';
    if (authModalTitle) authModalTitle.textContent = '添加认证用户';
    if (authUserUsername) {
        authUserUsername.value = '';
        authUserUsername.disabled = false;
    }
    if (authUserPassword) {
        authUserPassword.value = '';
        authUserPassword.placeholder = '新用户必须设置密码';
    }
    if (authUserEnabled) authUserEnabled.checked = true;

    // 重置ACLs表单
    if (aclMaxConnections) aclMaxConnections.value = '0';
    if (aclRateLimitDown) aclRateLimitDown.value = '0';
    if (aclRateLimitUp) aclRateLimitUp.value = '0';
    if (aclExpiresAfter) aclExpiresAfter.value = '0';
    if (aclUserGroups) aclUserGroups.value = '';
    if (aclAllowFrom) aclAllowFrom.value = '';
    if (aclBlockFrom) aclBlockFrom.value = '';

    // 清空时间规则
    if (timeRulesList) timeRulesList.innerHTML = '';
    resetTimeRuleInputs();

    openAuthUserModal();
}

// 编辑认证用户

function editAuthUser(index) {
    const users = AppState.currentConfig.socks5.auth_users || [];
    const user = users[index];

    if (!user) return;

    const authUserIndex = document.getElementById('auth-user-index');
    const authModalTitle = document.getElementById('auth-modal-title-text');
    const authUserUsername = document.getElementById('auth-user-username');
    const authUserPassword = document.getElementById('auth-user-password');
    const authUserEnabled = document.getElementById('auth-user-enabled');

    if (authUserIndex) authUserIndex.value = index;
    if (authModalTitle) authModalTitle.textContent = `编辑用户: ${user.username}`;
    if (authUserUsername) {
        authUserUsername.value = user.username;
        authUserUsername.disabled = true;
    }
    if (authUserPassword) {
        authUserPassword.value = '';
        authUserPassword.placeholder = '留空则不修改';
    }
    if (authUserEnabled) authUserEnabled.checked = user.enabled !== false;



    const connLimit = user.connection_limit || {};
    const rateLimit = user.rate_limit || {};
    const timeRestriction = connLimit.time_restriction || {};

    const aclMaxConnections = document.getElementById('acl-max-connections');
    const aclExpiresAfter = document.getElementById('acl-expires-after');
    const aclAllowFrom = document.getElementById('acl-allow-from');
    const aclBlockFrom = document.getElementById('acl-block-from');
    const aclUserGroups = document.getElementById('acl-user-groups');
    const aclRateLimitDown = document.getElementById('acl-rate-limit-down');
    const aclRateLimitUp = document.getElementById('acl-rate-limit-up');

    if (aclMaxConnections) aclMaxConnections.value = connLimit.max_connections || '0';
    if (aclExpiresAfter) aclExpiresAfter.value = connLimit.expires_after_minutes || '0';
    if (aclAllowFrom) aclAllowFrom.value = (connLimit.allow_from_ips || []).join(',');
    if (aclBlockFrom) aclBlockFrom.value = (connLimit.block_from_ips || []).join(',');
    if (aclUserGroups) aclUserGroups.value = (user.user_groups || []).join(',');
    if (aclRateLimitDown) aclRateLimitDown.value = rateLimit.download_bps ? (rateLimit.download_bps / 1024) : '0';
    if (aclRateLimitUp) aclRateLimitUp.value = rateLimit.upload_bps ? (rateLimit.upload_bps / 1024) : '0';



    // 渲染时间规则

    const timeRulesList = document.getElementById('time-rules-list');

    timeRulesList.innerHTML = '';

    if (timeRestriction.allowed_hours && timeRestriction.allowed_hours.length > 0) {

        const ruleString = `${(timeRestriction.allowed_days || []).join(',')}:${timeRestriction.allowed_hours[0]}`;

        renderTimeRuleToList(ruleString);

    }

    resetTimeRuleInputs();

    

    openAuthUserModal();

}

function openAuthUserModal() {
    document.getElementById('auth-user-modal').style.display = 'flex';
    // 渲染laydate
    if (AppState.layuiLaydate) {
        AppState.layuiLaydate.render({ elem: '#time-rule-start', type: 'time', format: 'HH:mm' });
        AppState.layuiLaydate.render({ elem: '#time-rule-end', type: 'time', format: 'HH:mm' });
    }
}

function closeAuthUserModal() {
    document.getElementById('auth-user-modal').style.display = 'none';
}

// 删除认证用户
async function deleteAuthUser(index) {
    const users = AppState.currentConfig.socks5.auth_users || [];
    const user = users[index];
    showConfirm('删除确认', `确定要删除用户 "${user.username}" 吗？`, async function () {
        users.splice(index, 1);
        AppState.currentConfig.socks5.auth_users = users;
        const success = await saveConfig(); 
        if(success) {
            showAlert('success', '用户删除成功！');
            await loadUsers();
        }
    });
}

// 保存认证用户

async function saveAuthUser() {

    const index = document.getElementById('auth-user-index').value;

    const username = document.getElementById('auth-user-username').value.trim();

    if (!username) { showAlert('error', '请输入用户名'); return; }



    const password = document.getElementById('auth-user-password').value;

    const enabled = document.getElementById('auth-user-enabled').checked;



    const timeRuleItems = Array.from(document.querySelectorAll('#time-rules-list li'));

    let timeRestriction = null;

    if (timeRuleItems.length > 0) {

        // 简单处理，只取第一个时间规则

        const ruleString = timeRuleItems[0].dataset.rule;

        const [daysStr, hoursStr] = ruleString.split(':');

        timeRestriction = {

            allowed_days: daysStr ? daysStr.split(',') : [],

            allowed_hours: hoursStr ? [hoursStr] : [],

            timezone: "Asia/Shanghai" // 假设一个默认值

        };

    }



    const rateLimit = {

        download_bps: (parseInt(document.getElementById('acl-rate-limit-down').value) || 0) * 1024,

        upload_bps: (parseInt(document.getElementById('acl-rate-limit-up').value) || 0) * 1024,

        burst_size: ((parseInt(document.getElementById('acl-rate-limit-down').value) || 0) + (parseInt(document.getElementById('acl-rate-limit-up').value) || 0)) * 1024 * 5 // 假设一个值

    };



    const connectionLimit = {

        max_connections: parseInt(document.getElementById('acl-max-connections').value) || 0,

        expires_after_minutes: parseInt(document.getElementById('acl-expires-after').value) || 0,

        allow_from_ips: document.getElementById('acl-allow-from').value.split(',').map(s => s.trim()).filter(s => s),

        block_from_ips: document.getElementById('acl-block-from').value.split(',').map(s => s.trim()).filter(s => s),

        time_restriction: timeRestriction

    };



    let userPayload = { 

        username: username, 

        enabled: enabled,

        user_groups: document.getElementById('acl-user-groups').value.split(',').map(s => s.trim()).filter(s => s),

        rate_limit: (rateLimit.download_bps > 0 || rateLimit.upload_bps > 0) ? rateLimit : null,

        connection_limit: (connectionLimit.max_connections > 0 || connectionLimit.expires_after_minutes > 0 || connectionLimit.allow_from_ips.length > 0 || connectionLimit.block_from_ips.length > 0 || connectionLimit.time_restriction != null) ? connectionLimit : null,

    };

    if (password) { userPayload.password = password; } 

    else if (index === '' && !password) { showAlert('error', '新用户必须设置密码'); return; }



    // 更新 AppState.currentConfig.socks5.auth_users 中的用户

    if (index === '') {

        // 添加新用户

        if (!AppState.currentConfig.socks5.auth_users) AppState.currentConfig.socks5.auth_users = [];

        AppState.currentConfig.socks5.auth_users.push(userPayload);

    } else {

        // 更新现有用户

        const existingUser = AppState.currentConfig.socks5.auth_users[parseInt(index)];

        AppState.currentConfig.socks5.auth_users[parseInt(index)] = { ...existingUser, ...userPayload };

    }

    

    const success = await saveConfig();

    if(success) {

        showAlert('success', `用户 '${username}' 保存成功!`);

        closeAuthUserModal();

        await loadUsers(); // 重新加载以刷新表格

    }

}

// --- 时间规则UI辅助函数 ---
function addTimeRule() {
    const days = Array.from(document.querySelectorAll('.day-selector input:checked')).map(cb => cb.value);
    const start = document.getElementById('time-rule-start').value;
    const end = document.getElementById('time-rule-end').value;

    if (days.length === 0) { showAlert('warning', '请至少选择一个星期'); return; }
    if (!start || !end) { showAlert('warning', '请选择开始和结束时间'); return; }

    const daysStr = days.includes('*') ? '*' : days.join(',');
    const ruleString = `${daysStr}:${start}-${end}`;

    // 检查是否重复
    const currentRules = Array.from(document.querySelectorAll('#time-rules-list li')).map(li => li.dataset.rule);
    if (currentRules.includes(ruleString)) {
        showAlert('warning', '此时间规则已存在');
        return;
    }

    renderTimeRuleToList(ruleString);
    resetTimeRuleInputs();
}

function renderTimeRuleToList(ruleString) {
    const list = document.getElementById('time-rules-list');
    const li = document.createElement('li');
    li.dataset.rule = ruleString;
    li.className = 'time-rule-item';
    li.innerHTML = `
        <span>${ruleString}</span>
        <button type="button" class="btn btn-sm btn-danger" onclick="this.parentElement.remove()">
            <i class="layui-icon layui-icon-delete"></i>
        </button>
    `;
    list.appendChild(li);
}

function resetTimeRuleInputs() {
    document.querySelectorAll('.day-selector input').forEach(cb => cb.checked = false);
    document.getElementById('time-rule-start').value = '';
    document.getElementById('time-rule-end').value = '';
}

// --- Router Rule Management ---

function populateRouterRulesTable() {
    const tbody = document.getElementById('router-rules-tbody');
    if (!tbody) return; // Exit if the element doesn't exist
    const rules = AppState.currentConfig.router?.rules || [];

    tbody.innerHTML = '';
    if (rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #999; padding: 20px;">暂无路由规则</td></tr>';
        return;
    }

    rules.forEach((rule, index) => {
        // 为不同Action类型创建不同颜色的徽章
        let actionIcon = '';
        let actionClass = '';
        let actionText = rule.action.toUpperCase();

        switch (rule.action) {
            case 'allow':
                actionIcon = '<i class="layui-icon layui-icon-ok"></i>';
                actionClass = 'action-badge-allow';
                break;
            case 'deny':
                actionIcon = '<i class="layui-icon layui-icon-close"></i>';
                actionClass = 'action-badge-deny';
                break;
            case 'block':
                actionIcon = '<i class="layui-icon layui-icon-delete"></i>';
                actionClass = 'action-badge-block';
                break;
            case 'proxy':
                actionIcon = '<i class="layui-icon layui-icon-component"></i>';
                actionClass = 'action-badge-proxy';
                break;
            default:
                actionIcon = '<i class="layui-icon layui-icon-help"></i>';
                actionClass = 'action-badge-proxy';
                actionText = rule.action;
        }

        const actionBadge = `<span class="action-badge ${actionClass}">${actionIcon} ${actionText}</span>`;
        // 处理patterns的长文本省略显示
        const patterns = rule.patterns || [];
        const patternsText = patterns.map(p => `<code>${p}</code>`).join(' ');
        const shouldTruncate = patterns.length > 3 || patternsText.length > 100;

        let patternsHtml = '';
        if (shouldTruncate) {
            patternsHtml = `
                <div class="patterns-cell">
                    <div class="patterns-content" id="patterns-content-${index}">
                        ${patternsText}
                    </div>
                    <div class="patterns-toggle" onclick="togglePatterns(${index})">
                        <i class="layui-icon layui-icon-down" id="patterns-icon-${index}"></i>
                        <span id="patterns-text-${index}">展开</span>
                    </div>
                </div>
            `;
        } else {
            patternsHtml = `<div class="patterns-cell"><div class="patterns-content">${patternsText}</div></div>`;
        }
        const proxyNode = rule.proxy_node || '-';

        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${actionBadge}</td>
            <td>${patternsHtml}</td>
            <td>${proxyNode}</td>
            <td>${rule.description || '-'}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-primary" onclick="editRouterRule(${index})">
                        <i class="layui-icon layui-icon-edit"></i> 编辑
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteRouterRule(${index})">
                        <i class="layui-icon layui-icon-delete"></i> 删除
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function addRouterRule() {
    document.getElementById('router-rule-index').value = '';
    document.getElementById('router-rule-modal-title-text').textContent = '添加路由规则';
    document.getElementById('router-rule-action').value = 'proxy';
    document.getElementById('router-rule-patterns').value = '';
    document.getElementById('router-rule-proxy-node').value = '';
    document.getElementById('router-rule-description').value = '';
    document.getElementById('router-rule-modal').style.display = 'flex';
    if (AppState.layuiForm) AppState.layuiForm.render('select');
}

function editRouterRule(index) {
    const rules = AppState.currentConfig.router?.rules || [];
    const rule = rules[index];
    if (!rule) return;

    document.getElementById('router-rule-index').value = index;
    document.getElementById('router-rule-modal-title-text').textContent = '编辑路由规则';
    document.getElementById('router-rule-action').value = rule.action;
    document.getElementById('router-rule-patterns').value = (rule.patterns || []).join('\n');
    document.getElementById('router-rule-proxy-node').value = rule.proxy_node || '';
    document.getElementById('router-rule-description').value = rule.description || '';
    document.getElementById('router-rule-modal').style.display = 'flex';
    if (AppState.layuiForm) AppState.layuiForm.render('select');
}

async function saveRouterRule() {
    const index = document.getElementById('router-rule-index').value;
    const action = document.getElementById('router-rule-action').value;
    const patterns = document.getElementById('router-rule-patterns').value.split('\n').map(s => s.trim()).filter(s => s);
    const proxyNode = document.getElementById('router-rule-proxy-node').value.trim();
    const description = document.getElementById('router-rule-description').value.trim();

    if (patterns.length === 0) {
        showAlert('error', '请至少填写一个模式 (Pattern)');
        return;
    }

    if (action === 'proxy' && !proxyNode) {
        showAlert('error', '当动作为 "proxy" 时，必须指定代理节点');
        return;
    }
    
    const rule = {
        action: action,
        patterns: patterns,
        description: description
    };

    if (action === 'proxy') {
        rule.proxy_node = proxyNode;
    }

    if (!AppState.currentConfig.router) AppState.currentConfig.router = {};
    if (!AppState.currentConfig.router.rules) AppState.currentConfig.router.rules = [];

    if (index === '') {
        AppState.currentConfig.router.rules.push(rule);
    } else {
        AppState.currentConfig.router.rules[parseInt(index)] = rule;
    }

    const saved = await saveConfig();
    if (saved) {
        showAlert('success', '路由规则保存成功！');
        closeRouterRuleModal();
        populateRouterRulesTable();
    }
}

function deleteRouterRule(index) {
    const rules = AppState.currentConfig.router?.rules || [];
    const rule = rules[index];
    if (!rule) return;

    showConfirm('删除确认', `确定要删除此路由规则吗？<br>描述: ${rule.description || '无'}`, async function () {
        rules.splice(index, 1);
        AppState.currentConfig.router.rules = rules;

        const saved = await saveConfig();
        if (saved) {
            showAlert('success', '路由规则删除成功！');
            populateRouterRulesTable();
        }
    });
}

function closeRouterRuleModal() {
    document.getElementById('router-rule-modal').style.display = 'none';
}

// DNS劫持规则管理功能
let currentDnsHijackRules = [];

function addDnsHijackRule() {
    document.getElementById('hijack-rule-index').value = '';
    document.getElementById('hijack-modal-title-text').textContent = '添加DNS劫持规则';
    document.getElementById('hijack-pattern').value = '';
    document.getElementById('hijack-target').value = '';
    document.getElementById('hijack-description').value = '';
    document.getElementById('dns-hijack-rule-modal').style.display = 'flex';
}

function closeDnsHijackRuleModal() {
    document.getElementById('dns-hijack-rule-modal').style.display = 'none';
}

function saveDnsHijackRule() {
    const pattern = document.getElementById('hijack-pattern').value.trim();
    const target = document.getElementById('hijack-target').value.trim();
    const description = document.getElementById('hijack-description').value.trim();

    if (!pattern || !target) {
        showAlert('warning', '请填写域名模式和目标地址');
        return;
    }

    const rule = {
        pattern: pattern,
        target: target,
        description: description || `${pattern} -> ${target}`
    };

    // 更新当前配置中的DNS劫持规则
    if (!AppState.currentConfig.dns) {
        AppState.currentConfig.dns = {};
    }
    if (!AppState.currentConfig.dns.hijack_rules) {
        AppState.currentConfig.dns.hijack_rules = [];
    }

    // 检查是否重复
    const existingIndex = AppState.currentConfig.dns.hijack_rules.findIndex(r => r.pattern === pattern);
    if (existingIndex >= 0) {
        AppState.currentConfig.dns.hijack_rules[existingIndex] = rule;
    } else {
        AppState.currentConfig.dns.hijack_rules.push(rule);
    }

    // 保存配置
    saveConfig().then(success => {
        if (success) {
            showAlert('success', 'DNS劫持规则保存成功！');
            closeDnsHijackRuleModal();
            populateDnsHijackRulesTable();
        }
    });
}

function populateDnsHijackRulesTable() {
    const tbody = document.getElementById('dns-hijack-rules-tbody');
    const rules = AppState.currentConfig.dns?.hijack_rules || [];

    tbody.innerHTML = '';
    if (rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #999; padding: 20px;">暂无DNS劫持规则</td></tr>';
        return;
    }

    rules.forEach((rule, index) => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${rule.pattern}</code></td>
            <td><code>${rule.target}</code></td>
            <td>${rule.description || '-'}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-primary" onclick="editDnsHijackRule(${index})">
                        <i class="layui-icon layui-icon-edit"></i> 编辑
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteDnsHijackRule(${index})">
                        <i class="layui-icon layui-icon-delete"></i> 删除
                    </button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function editDnsHijackRule(index) {
    const rules = AppState.currentConfig.dns?.hijack_rules || [];
    const rule = rules[index];
    if (!rule) return;

    document.getElementById('hijack-rule-index').value = index;
    document.getElementById('hijack-modal-title-text').textContent = '编辑DNS劫持规则';
    document.getElementById('hijack-pattern').value = rule.pattern;
    document.getElementById('hijack-target').value = rule.target;
    document.getElementById('hijack-description').value = rule.description || '';
    document.getElementById('dns-hijack-rule-modal').style.display = 'flex';
}

function deleteDnsHijackRule(index) {
    const rules = AppState.currentConfig.dns?.hijack_rules || [];
    const rule = rules[index];
    if (!rule) return;

    showConfirm('删除确认', `确定要删除DNS劫持规则 "${rule.pattern}" 吗？`, async function () {
        rules.splice(index, 1);
        AppState.currentConfig.dns.hijack_rules = rules;

        const saved = await saveConfig();
        if (saved) {
            showAlert('success', 'DNS劫持规则删除成功！');
            populateDnsHijackRulesTable();
        }
    });
}


// 直接的身份验证切换处理函数
function handleAuthToggle(checkbox) {
    if (!checkbox) {
        console.error('handleAuthToggle: checkbox is null');
        return;
    }

    const authUsersSection = document.getElementById('auth-users-section');
    const enable = checkbox.checked;

    if (authUsersSection) {
        authUsersSection.style.display = enable ? 'block' : 'none';
        if (enable) {
            loadUsers().catch(error => console.error('加载用户列表失败:', error));
            showAlert('success', '身份验证已启用');
        } else {
            showAlert('info', '身份验证已禁用');
        }
    }
    // 保存配置
    saveConfig().catch(error => console.error('enable_auth配置保存失败:', error));
}

// 页面加载后延迟检查状态
setTimeout(function() {
    // 确保DOM元素存在并设置正确的显示状态
    const enableAuthCheckbox = document.getElementById('enable_auth');
    const authUsersSection = document.getElementById('auth-users-section');
    if (enableAuthCheckbox && authUsersSection) {
        authUsersSection.style.display = enableAuthCheckbox.checked ? 'block' : 'none';
    }
}, 1000);


// 中国路由文件管理功能
async function loadChnroutesFile() {
    try {
        const response = await fetch('/api/file/chnroutes');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (data.success) {
            const editor = document.getElementById('chnroutes-editor');
            if (editor) {
                // 修复：API返回的数据结构是 {success: true, data: {content: "..."}}
                editor.value = data.data.content || '';

                document.getElementById('chnroutes-lines-value').textContent = data.data.lines || '0';
                document.getElementById('chnroutes-size-value').textContent = data.data.size || '0 B';

                // 触发数据行数计算
                updateDataLinesCount();

                // 重置滚动进度
                updateScrollProgress();
            }
        } else {
            showAlert('warning', '中国路由文件加载失败: ' + (data.error || '未知错误'));
        }
    } catch (error) {
        console.error('加载中国路由文件失败:', error);
        showAlert('error', '中国路由文件加载失败: ' + error.message);
    }
}

async function saveChnroutesFile() {
    try {
        const editor = document.getElementById('chnroutes-editor');
        const content = editor ? editor.value : '';

        const response = await fetch('/api/file/chnroutes/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: content })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();

        if (data.success) {
            showAlert('success', '中国路由文件保存成功！');
            // 更新数据行数显示
            updateDataLinesCount();
        } else {
            showAlert('error', '保存失败: ' + (data.error || '未知错误'));
        }
    } catch (error) {
        console.error('保存中国路由文件失败:', error);
        showAlert('error', '中国路由文件保存失败: ' + error.message);
    }
}

async function refreshChnroutesInfo() {
    updateChnroutesStatus('loading', '刷新中...');
    await loadChnroutesFile();
    updateChnroutesStatus('success', '刷新完成');
}

function uploadChnroutesFile(input) {
    if (!input.files || !input.files[0]) {
        showAlert('warning', '请选择要上传的文件');
        return;
    }

    const file = input.files[0];
    if (!file.name.endsWith('.txt') && !file.name.endsWith('.conf')) {
        showAlert('warning', '请选择 .txt 或 .conf 格式的文件');
        return;
    }

    const reader = new FileReader();
    reader.onload = async function(e) {
        try {
            const content = e.target.result;
            const editor = document.getElementById('chnroutes-editor');
            if (editor) {
                editor.value = content;
                // 立即更新数据行数显示
                updateDataLinesCount();
            }

            const response = await fetch('/api/file/chnroutes/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content })
            });

            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const data = await response.json();

            if (data.success) {
                showAlert('success', `文件 ${file.name} 上传成功！`);
                // 不再需要重新加载，因为我们已经设置了内容
            } else {
                showAlert('error', '上传失败: ' + (data.error || '未知错误'));
            }
        } catch (error) {
            console.error('上传文件失败:', error);
            showAlert('error', '文件上传失败: ' + error.message);
        }
    };
    reader.readAsText(file);
    input.value = ''; // 清空input以允许重复上传同一文件
}

function downloadChnroutesFile() {
    const editor = document.getElementById('chnroutes-editor');
    const content = editor ? editor.value : '';

    if (!content.trim()) {
        showAlert('warning', '文件内容为空，无法下载');
        return;
    }

    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'chnroutes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    showAlert('success', '文件下载已开始');
}

function updateChnroutesStatus(status, text) {
    const statusElement = document.getElementById('chnroutes-status');
    if (!statusElement) return;

    const statusIndicator = statusElement.querySelector('.status-indicator');
    const statusText = statusElement.querySelector('.status-text');

    statusIndicator.className = 'status-indicator';
    switch (status) {
        case 'loading':
            statusIndicator.classList.add('status-loading');
            break;
        case 'success':
            statusIndicator.classList.add('status-success');
            break;
        case 'error':
            statusIndicator.classList.add('status-error');
            break;
        default:
            statusIndicator.classList.add('status-idle');
    }

    statusText.textContent = text;
}

// 更新滚动进度
function updateScrollProgress() {
    const editor = document.getElementById('chnroutes-editor');
    const scrollProgress = document.getElementById('scroll-progress-bar');
    const scrollPosition = document.getElementById('scroll-position');
    const currentLine = document.getElementById('current-line');
    const scrollPercentage = document.getElementById('scroll-percentage');

    if (!editor || !scrollProgress) return;

    const scrollTop = editor.scrollTop;
    const scrollHeight = editor.scrollHeight - editor.clientHeight;
    const percentage = scrollHeight > 0 ? (scrollTop / scrollHeight) * 100 : 0;

    // 更新进度条
    scrollProgress.style.width = percentage + '%';

    // 计算当前行号
    const lineHeight = parseInt(window.getComputedStyle(editor).lineHeight) || 20;
    const currentLineNum = Math.floor(scrollTop / lineHeight) + 1;
    const totalLines = Math.floor(editor.scrollHeight / lineHeight);

    // 更新信息显示
    const thirdLines = Math.floor(totalLines / 3);
    const twoThirdLines = Math.floor(totalLines * 2 / 3);
    if (scrollPosition) {
        if (scrollTop === 0) {
            scrollPosition.textContent = '顶部';
        } else if (scrollTop >= scrollHeight - 1) {
            scrollPosition.textContent = '底部';
        } else if (currentLineNum <= thirdLines) {
            scrollPosition.textContent = '顶部三分之一';
        } else if (currentLineNum <= twoThirdLines) {
            scrollPosition.textContent = '中间';
        } else {
            scrollPosition.textContent = '底部三分之二';
        }
    }
    if (currentLine) currentLine.textContent = `第 ${currentLineNum} 行`;
    if (scrollPercentage) scrollPercentage.textContent = `${Math.round(percentage)}%`;
}

// 实时计算数据行数（前端计算）
function updateDataLinesCount() {
    const editor = document.getElementById('chnroutes-editor');
    const dataLinesValue = document.getElementById('chnroutes-data-lines-value');

    if (!editor || !dataLinesValue) return;

    const content = editor.value;
    const lines = content.split('\n');

    // 计算总行数
    const totalLines = lines.length;

    // 计算有效数据行数（非空行且非注释行）
    const dataLines = lines.filter(line => {
        const trimmed = line.trim();
        return trimmed && !trimmed.startsWith('#');
    }).length;

    // 更新显示
    if (dataLinesValue) {
        dataLinesValue.textContent = dataLines;
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
    if (!input) return;

    const value = parseInt(input.value);
    const warningId = input.id.replace('_port', '-port-warning');
    const warningElement = document.getElementById(warningId);

    if (warningElement) {
        if (value < 1024 && value > 0) {
            warningElement.classList.add('show');
            input.classList.add('port-input-warning');
        } else {
            warningElement.classList.remove('show');
            input.classList.remove('port-input-warning');
        }
    }
}

// 初始化端口警告状态
function initializePortWarnings() {
    const portInputs = document.querySelectorAll('input[type="number"][id*="_port"]');
    portInputs.forEach(input => {
        checkPortWarning(input);
    });
}

// 在编辑器内容变化时使用防抖函数
document.addEventListener('DOMContentLoaded', function() {
    const editor = document.getElementById('chnroutes-editor');
    if (editor) {
        // 输入事件：防抖计算数据行数
        editor.addEventListener('input', debouncedUpdateDataLinesCount);

        // 滚动事件：实时更新进度条
        editor.addEventListener('scroll', updateScrollProgress);
    }
    initializePortWarnings();

    // 初始化用户认证管理区域显示状态
    const authUsersSection = document.getElementById('auth-users-section');
    const enableAuthCheckbox = document.getElementById('enable_auth');
    if (enableAuthCheckbox && authUsersSection) {
        // 注意：这里handleAuthToggle函数可能还没完全加载，需要确保其可用性
        // 或者直接根据AppState.currentConfig设置display
        if (AppState.currentConfig.socks5 && AppState.currentConfig.socks5.enable_auth) {
            authUsersSection.style.display = 'block';
        } else {
            authUsersSection.style.display = 'none';
        }
    }
});

// 全局确认函数，优先使用layui的layer，fallback到原生confirm
function showConfirm(title, message, onConfirm, onCancel) {
    if (AppState.layuiLayer) {
        AppState.layuiLayer.confirm( message, { icon: 3, title: title, btn: ['确定', '取消'], skin: 'layui-layer-molv' },
            function (layerIndex) { AppState.layuiLayer.close(layerIndex); if (onConfirm) onConfirm(); },
            function (layerIndex) { AppState.layuiLayer.close(layerIndex); if (onCancel) onCancel(); }
        );
    } else {
        if (confirm(message.replace(/<br>/g, '\n'))) { if (onConfirm) onConfirm(); } else { if (onCancel) onCancel(); }
    }
}

// --- Router Rules Patterns Toggle ---

function togglePatterns(index) {
    const content = document.getElementById(`patterns-content-${index}`);
    const icon = document.getElementById(`patterns-icon-${index}`);
    const text = document.getElementById(`patterns-text-${index}`);

    if (!content || !icon || !text) return;

    if (content.classList.contains('expanded')) {
        // 收缩
        content.classList.remove('expanded');
        icon.className = 'layui-icon layui-icon-down';
        text.textContent = '展开';
    } else {
        // 展开
        content.classList.add('expanded');
        icon.className = 'layui-icon layui-icon-up';
        text.textContent = '收缩';
    }
}

console.log('SmartProxy 现代化控制台脚本加载完成');
