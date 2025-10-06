import sys
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QTextEdit, QPushButton, QLabel, QProgressBar,
                             QListWidget, QFileDialog, QMessageBox, QWidget,
                             QSplitter, QFrame, QTabWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont


class RTSPDetector(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str, bool, str)

    def __init__(self, targets):
        super().__init__()
        self.targets = targets
        self.running = True

    def stop(self):
        self.running = False

    def check_rtsp_unauth(self, target):
        try:
            if ':' in target:
                ip, port = target.split(':')
                port = int(port)
            else:
                ip = target
                port = 554

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, port))

            rtsp_request = "OPTIONS rtsp://{}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".format(ip)
            sock.send(rtsp_request.encode())
            response = sock.recv(1024).decode()

            describe_request = "DESCRIBE rtsp://{}/ RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n".format(ip)
            sock.send(describe_request.encode())
            describe_response = sock.recv(2048).decode()

            sock.close()

            if "RTSP/1.0 200" in response:
                if "RTSP/1.0 200" in describe_response and "sdp" in describe_response.lower():
                    return target, True, "RTSP未授权访问"
                else:
                    return target, False, "服务存在但无法获取流信息"
            else:
                return target, False, "服务响应异常"

        except socket.timeout:
            return target, False, "连接超时"
        except ConnectionRefusedError:
            return target, False, "连接被拒绝"
        except Exception as e:
            return target, False, f"错误: {str(e)}"

        return target, False, "未知错误"

    def run(self):
        total = len(self.targets)
        completed = 0

        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_target = {
                executor.submit(self.check_rtsp_unauth, target): target
                for target in self.targets
            }

            for future in as_completed(future_to_target):
                if not self.running:
                    break

                target = future_to_target[future]
                try:
                    ip, status, message = future.result()
                    completed += 1
                    progress = int((completed / total) * 100)

                    self.progress_signal.emit(progress)
                    self.result_signal.emit(ip, status, message)
                    self.update_signal.emit(f"检测完成: {ip} - {message}")

                except Exception as e:
                    self.update_signal.emit(f"检测错误: {target} - {str(e)}")

        self.update_signal.emit("扫描完成！")


class RTSPScanner(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.detector = None

    def init_ui(self):
        self.setWindowTitle("RTSP未授权漏洞检测工具 by Talenturm")
        self.setGeometry(100, 100, 1200, 800)

        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a0a, stop:0.3 #1a1a2e, stop:0.7 #16213e, stop:1 #0f3460);
                color: #00ffcc;
            }
            QTextEdit, QListWidget {
                background-color: rgba(0, 20, 40, 0.8);
                border: 1px solid #00ffcc;
                border-radius: 8px;
                color: #00ffcc;
                font-family: 'Consolas';
                font-size: 12px;
                padding: 10px;
                selection-background-color: #00ffcc;
                selection-color: #000;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffcc, stop:0.3 #0088cc, stop:1 #0055aa);
                border: 1px solid #00ffcc;
                border-radius: 5px;
                color: #000000;
                font-weight: bold;
                font-size: 12px;
                padding: 8px 15px;
                min-width: 100px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:0.3 #00aaff, stop:1 #0077ff);
                border: 1px solid #00ffff;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #008888, stop:0.3 #0066aa, stop:1 #004488);
            }
            QPushButton:disabled {
                background: #333333;
                border: 1px solid #666666;
                color: #666666;
            }
            QLabel {
                color: #00ffcc;
                font-family: 'Arial';
                font-size: 14px;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #00ffcc;
                border-radius: 5px;
                text-align: center;
                color: #00ffcc;
                font-weight: bold;
                background-color: rgba(0, 20, 40, 0.8);
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffcc, stop:0.5 #0088cc, stop:1 #ff00cc);
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #00ffcc;
                border-radius: 8px;
                background-color: rgba(0, 20, 40, 0.8);
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #333333, stop:0.5 #222222, stop:1 #111111);
                border: 1px solid #00ffcc;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 8px 15px;
                color: #00ffcc;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffcc, stop:0.5 #0088cc, stop:1 #0055aa);
                color: #000000;
            }
            QTabBar::tab:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:0.5 #00aaff, stop:1 #0077ff);
                color: #000000;
            }
            QFrame {
                background-color: rgba(0, 20, 40, 0.6);
                border-radius: 8px;
            }
            QSplitter::handle {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffcc, stop:0.5 #0088cc, stop:1 #ff00cc);
            }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("⚡ RTSP未授权漏洞检测工具 by Talenturm ⚡")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet(
            "QLabel { color: #00ffcc; background-color: rgba(0, 20, 40, 0.8); border-radius: 10px; padding: 10px; }")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.setFont(QFont("Arial", 10))
        layout.addWidget(tabs)

        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        scan_layout.setSpacing(8)
        scan_layout.setContentsMargins(8, 8, 8, 8)

        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        control_layout.setSpacing(8)

        self.btn_import = QPushButton("📁 导入目标")
        self.btn_start = QPushButton("🚀 开始扫描")
        self.btn_stop = QPushButton("⏹️ 停止扫描")
        self.btn_clear = QPushButton("🗑️ 清空结果")
        self.btn_info = QPushButton("📖 工具详情")

        self.btn_stop.setEnabled(False)

        buttons = [self.btn_import, self.btn_start, self.btn_stop, self.btn_clear, self.btn_info]
        for btn in buttons:
            btn.setMinimumHeight(30)
            btn.setFont(QFont("Arial", 10))

        control_layout.addWidget(self.btn_import)
        control_layout.addWidget(self.btn_start)
        control_layout.addWidget(self.btn_stop)
        control_layout.addWidget(self.btn_clear)
        control_layout.addWidget(self.btn_info)
        control_layout.addStretch()

        scan_layout.addWidget(control_frame)

        splitter = QSplitter(Qt.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setSpacing(5)

        left_title = QLabel("🎯 目标列表")
        left_title.setFont(QFont("Arial", 12, QFont.Bold))
        left_layout.addWidget(left_title)

        self.target_list = QListWidget()
        self.target_list.setFont(QFont("Consolas", 10))
        left_layout.addWidget(self.target_list)

        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setSpacing(5)

        right_title = QLabel("🔴 存在漏洞的目标")
        right_title.setFont(QFont("Arial", 12, QFont.Bold))
        right_layout.addWidget(right_title)

        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)
        self.result_display.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.result_display)

        log_title = QLabel("📝 扫描日志")
        log_title.setFont(QFont("Arial", 12, QFont.Bold))
        right_layout.addWidget(log_title)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.log_display)

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])

        scan_layout.addWidget(splitter)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(20)
        scan_layout.addWidget(self.progress_bar)

        stats_frame = QFrame()
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setSpacing(15)

        self.lbl_total = QLabel("🎯 总计: 0")
        self.lbl_vulnerable = QLabel("🔴 漏洞: 0")
        self.lbl_safe = QLabel("🟢 安全: 0")
        self.lbl_scanned = QLabel("📊 已扫描: 0")

        stats_labels = [self.lbl_total, self.lbl_vulnerable, self.lbl_safe, self.lbl_scanned]
        for label in stats_labels:
            label.setFont(QFont("Arial", 11, QFont.Bold))
            label.setStyleSheet(
                "QLabel { background-color: rgba(0, 20, 40, 0.8); border-radius: 5px; padding: 5px 10px; }")

        stats_layout.addWidget(self.lbl_total)
        stats_layout.addWidget(self.lbl_vulnerable)
        stats_layout.addWidget(self.lbl_safe)
        stats_layout.addWidget(self.lbl_scanned)
        stats_layout.addStretch()

        scan_layout.addWidget(stats_frame)

        tabs.addTab(scan_tab, "🔍 漏洞扫描")

        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)

        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setFont(QFont("Arial", 11))
        info_text.append("<h2 style='color:#00ffcc;'>工具详情</h2>")
        info_text.append("<h3 style='color:#00ffcc;'>功能特性:</h3>")
        info_text.append("• 多线程快速检测RTSP未授权访问漏洞")
        info_text.append("• 检测端口：554")
        info_text.append("• 增强验证：使用DESCRIBE方法验证实际可访问性")
        info_text.append("• 支持批量目标导入和扫描")
        info_text.append("<h3 style='color:#00ffcc;'>检测范围:</h3>")
        info_text.append("• 🔴 RTSP未授权访问")
        info_text.append("<h3 style='color:#00ffcc;'>项目地址:</h3>")
        info_text.append("https://github.com/yuanmeng-MINGI/GUI-rtsp-unauthorized-detection-tool")
        info_text.append("<h3 style='color:#00ffcc;'>免责声明</h3>")
        info_text.append("本工具仅用于安全检测和教育目的")
        info_text.append("仅对您拥有合法权限的系统进行测试")
        info_text.append("不得用于非法入侵或攻击他人系统")
        info_text.append("使用者需对自身行为承担全部法律责任")
        info_text.append("<h3 style='color:#00ffcc;'>使用说明:</h3>")
        info_text.append("1. 准备目标IP列表文件")
        info_text.append("2. 点击导入目标加载目标列表")
        info_text.append("3. 点击开始扫描启动漏洞检测")
        info_text.append("4. 查看右侧结果面板获取检测结果")

        info_layout.addWidget(info_text)
        tabs.addTab(info_tab, "📋 工具说明")

        self.btn_import.clicked.connect(self.import_targets)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_info.clicked.connect(self.show_info)

        self.stats = {'total': 0, 'vulnerable': 0, 'safe': 0, 'scanned': 0}
        self.update_stats()

    def import_targets(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "Text Files (*.txt);;All Files (*)")

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    targets = [line.strip() for line in f if line.strip()]

                self.target_list.clear()
                self.target_list.addItems(targets)
                self.stats['total'] = len(targets)
                self.update_stats()
                self.log_display.append(f"[+] 成功导入 {len(targets)} 个目标")

            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入文件失败: {str(e)}")

    def start_scan(self):
        targets = [self.target_list.item(i).text()
                   for i in range(self.target_list.count())]

        if not targets:
            QMessageBox.warning(self, "警告", "请先导入目标列表")
            return

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.stats.update({'vulnerable': 0, 'safe': 0, 'scanned': 0})
        self.update_stats()

        self.result_display.clear()
        self.log_display.append(f"[+] 开始扫描 {len(targets)} 个目标...")

        self.detector = RTSPDetector(targets)
        self.detector.update_signal.connect(self.update_log)
        self.detector.progress_signal.connect(self.update_progress)
        self.detector.result_signal.connect(self.handle_result)
        self.detector.start()

    def stop_scan(self):
        if self.detector and self.detector.isRunning():
            self.detector.stop()
            self.detector.wait()

        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.log_display.append("[!] 扫描已停止")

    def clear_results(self):
        self.target_list.clear()
        self.result_display.clear()
        self.log_display.clear()
        self.progress_bar.setValue(0)

        self.stats = {'total': 0, 'vulnerable': 0, 'safe': 0, 'scanned': 0}
        self.update_stats()

    def show_info(self):
        QMessageBox.information(self, "工具说明",
                                "RTSP未授权漏洞检测工具 by Talenturm\n\n"
                                "功能特性:\n"
                                "• 多线程快速检测RTSP漏洞\n"
                                "• 检测端口：554\n"
                                "• 增强验证：使用DESCRIBE方法验证实际可访问性\n"
                                "• 支持批量目标扫描\n\n"
                                 "项目地址:\n"
                                "https://github.com/yuanmeng-MINGI/GUI-rtsp-unauthorized-detection-tool\n\n"
                                "免责声明:\n"
                                "本工具仅用于安全检测，请勿用于非法用途！")

    def update_log(self, message):
        self.log_display.append(message)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def handle_result(self, ip, is_vulnerable, message):
        self.stats['scanned'] += 1

        if is_vulnerable:
            self.stats['vulnerable'] += 1
            result_text = f"🔴 {ip} - {message}"
            self.result_display.append(f'<font color="#ff0066">{result_text}</font>')
        else:
            self.stats['safe'] += 1

        self.update_stats()

    def update_stats(self):
        self.lbl_total.setText(f"🎯 总计: {self.stats['total']}")
        self.lbl_vulnerable.setText(f"🔴 漏洞: {self.stats['vulnerable']}")
        self.lbl_safe.setText(f"🟢 安全: {self.stats['safe']}")
        self.lbl_scanned.setText(f"📊 已扫描: {self.stats['scanned']}")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    font = QFont("Arial", 10)
    app.setFont(font)
    scanner = RTSPScanner()
    scanner.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()