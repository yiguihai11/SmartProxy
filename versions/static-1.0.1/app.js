// 中国路由文件管理功能
async function loadChnroutesFile() {
    try {
        const response = await fetch('/api/file/chnroutes');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();

        if (data.success) {
            const editor = document.getElementById('chnroutes-editor');
            if (editor) {
                editor.value = data.data.content || '';

                // 设置统计信息
                const stats = data.data || {};
                document.getElementById('chnroutes-lines-value').textContent = stats.lines || '0';
                document.getElementById('chnroutes-size-value').textContent = stats.size || '0 B';
                document.getElementById('chnroutes-data-lines-value').textContent = stats.data_lines || '0';

                updateDataLinesCount();
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