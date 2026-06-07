import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QProgressBar,
                             QFileDialog, QTextEdit, QFrame, QRadioButton, QButtonGroup)
from PyQt6.QtCore import QSize, QThread, pyqtSignal
from PyQt6.QtGui import QFont


VIRUS_DATABASE = {
    "e0ec2cd43f71c80d42cd7b0f17802c73": "Malware/Trojan.Mirai",
    "55142f1d393c5ba7405239f232a6c059": "Xbash/Infector.TRJ"
}


class ScanWorker(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    finished = pyqtSignal(int, int)

    def __init__(self, mode, custom_path=None):
        super().__init__()
        self.mode = mode
        self.custom_path = custom_path
        self._is_running = True

    def run(self):
        self.log.emit("[INFO] Подготовка к анализу...")
        paths = ["/tmp"]
        if self.mode == "full": paths = ["/"]
        if self.mode == "custom" and self.custom_path: paths = [self.custom_path]

        files_to_check = []
        for p in paths:
            for root, dirs, files in os.walk(p):
                if any(x in root for x in ["/proc", "/sys", "/dev", "/run", ".snapshots"]): continue
                for f in files:
                    if not self._is_running: return
                    files_to_check.append(os.path.join(root, f))

        total = len(files_to_check)
        if total == 0:
            self.finished.emit(0, 0)
            return

        self.log.emit(f"[INFO] Сканирование {total} файлов...")
        for idx, path in enumerate(files_to_check):
            if not self._is_running: break
            self.progress.emit(int((idx / total) * 100))

        self.finished.emit(total, 0)

    def stop(self):
        self._is_running = False


class HasonAntivirusGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.selected_dir = ""
        self.scan_thread = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Hason Legal Security")
        self.setMinimumSize(QSize(800, 520))
        self.setStyleSheet("background-color: #1a1a22; color: #ffffff;")

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        sidebar = QVBoxLayout()
        logo = QLabel("HASON\nLEGAL SECURITY")
        logo.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        sidebar.addWidget(logo)

        self.radio_group = QButtonGroup(self)
        self.radio_fast = QRadioButton("Быстрая")
        self.radio_full = QRadioButton("Полная")
        self.radio_custom = QRadioButton("Выборочная")
        self.radio_fast.setChecked(True)

        for i, r in enumerate([self.radio_fast, self.radio_full, self.radio_custom]):
            self.radio_group.addButton(r, i)
            sidebar.addWidget(r)

        sidebar.addStretch()
        self.btn_select = QPushButton("Выбрать папку")
        self.btn_select.setEnabled(False)
        sidebar.addWidget(self.btn_select)
        main_layout.addLayout(sidebar)

        content = QVBoxLayout()
        self.status_label = QLabel("Система готова")
        self.status_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        content.addWidget(self.status_label)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background-color: #0f0f14; color: #39ff14; font-family: monospace;")
        content.addWidget(self.console)

        self.progress_bar = QProgressBar()
        content.addWidget(self.progress_bar)

        self.btn_action = QPushButton("Запустить сканирование")
        self.btn_action.setStyleSheet("background-color: #4361ee; padding: 10px; font-weight: bold;")
        content.addWidget(self.btn_action)
        main_layout.addLayout(content, stretch=2)

        self.radio_group.buttonClicked.connect(self.toggle_mode)
        self.btn_select.clicked.connect(self.select_folder)
        self.btn_action.clicked.connect(self.handle_action)

    def toggle_mode(self):
        self.btn_select.setEnabled(self.radio_custom.isChecked())

    def select_folder(self):
        res = QFileDialog.getExistingDirectory(self, "Выбор папки", os.path.expanduser("~"))
        if res:
            self.selected_dir = res
            self.console.append(f"[USER] Выбрано: {res}")

    def handle_action(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.btn_action.setText("Запустить сканирование")
            return

        mode = "fast"
        if self.radio_full.isChecked(): mode = "full"
        if self.radio_custom.isChecked(): mode = "custom"

        self.btn_action.setText("Остановить")
        self.scan_thread = ScanWorker(mode, self.selected_dir)
        self.scan_thread.progress.connect(self.progress_bar.setValue)
        self.scan_thread.log.connect(self.console.append)
        self.scan_thread.finished.connect(self.scan_done)
        self.scan_thread.start()

    def scan_done(self, total, threats):
        self.btn_action.setText("Запустить сканирование")
        self.console.append(f"\n[FINISH] Проверено: {total}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = HasonAntivirusGUI()
    gui.show()
    sys.exit(app.exec())
