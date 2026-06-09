import sys
import os
import hashlib
import stat  # Добавили для точной проверки типов файлов (сокетов/каналов)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QProgressBar,
                             QFileDialog, QTextEdit, QRadioButton, QButtonGroup)
from PyQt6.QtCore import QSize, QThread, pyqtSignal
from PyQt6.QtGui import QFont


VIRUS_DATABASE = {
    "f3748213653564a889d54c5320d2864695526200aaa28612b5ea8b6be888d9a9": "Malware/Trojan.Mirai",
    "6590bc6689622edab379471166444007d4b4cc8630cf9d690a42bc56b3e7a759": "Xbash/Infector.TRJ",
    "7163fefbf2f865ef78a2d3d4480532fffb979300d6f0a77b6f3fc5c4b0d2cada": "Windows.Trojan/PartTable.Killer/Stealer.Salinewin",
    "283f195bad35cac6e9452c2791eaeb90d9cd6d506aa16c6505247e5be74aabf0": "UltraTrojan/Win32.MBRKiller!Hydrogen",
    "4bb94cf51bee6e55a2adf0107562d5e8076fc863f3e6610355aed39e040ce466":  "Pankoza.Trojan/MBRKiller.PASSWORDStealer",
    "5c5a88062018f89614b330031e2e9796aa733bad53fbaed42f2b381bd09b0d7a": "Pankoza.Trojan/PASSWORDStealer",
    "785489dfa2c67bba1eb28df800e6f102214c224bf7d55a0acb885699a5280597": "Trojan/NoDanger:Joke.Generic",
    "1ab7375550516d7445c47fd9b551ed864f227401a14ff3f1ff0d70caca3bd997": "Trojan/Joke.Malware:NoWarning",
    "a92d754db62ccc19611e39c5c5bbb63db1f620c5dfd787d5d1878549e1d65d4c": "VirusTotal:Trojan.BadJoke/generickdq",
    "8c05af517e990d3f641a53d81e9a13c9ca443636d34da7723f3771bc34b7c7f7": "VirusTotal:trojan.badjoke/msil",
    "abdd8dcd4f23e70b81a874179012208a8db88503aff38f637016eeb5516757a0": "Joke.Generic/NoStealers",
    "c463f90368241c8e844ad85a864005869dfcd7dea6d6c940571aef3f41737208": "MBRKiller/NoSafety"
    ""
}


class ScanWorker(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)
    finished = pyqtSignal(int, int)  # Передает: (всего_файлов, найдено_угроз)

    def __init__(self, mode, custom_path=None):
        super().__init__()
        self.mode = mode
        self.custom_path = custom_path
        self._is_running = True

    def calculate_sha256(self, filepath):
        """Безопасное чтение файла и вычисление его SHA256 хэша"""
        try:
            # Игнорируем символические ссылки
            if os.path.islink(filepath):
                return None

            # Проверяем тип файла через stat системные флаги
            file_stat = os.stat(filepath)
            # Если это сокет, именованный канал FIFO или устройство — пропускаем
            if not stat.S_ISREG(file_stat.st_mode):
                return None

        except (PermissionError, FileNotFoundError, OSError):
            # Если нет прав доступа или файл заблокирован системой — пропускаем
            return None

        # Хэширование файла
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Читаем блоками по 4 КБ, чтобы не перегружать ОЗУ
                for byte_block in iter(lambda: f.read(4096), b""):
                    if not self._is_running:
                        return None
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except OSError:
            # Защита от непредвиденных ошибок чтения (включая Errno 6 / ENXIO)
            return None

    def run(self):
        self.log.emit("[INFO] Подготовка к анализу...")
        paths = ["/tmp"]
        if self.mode == "full": paths = ["/"]
        if self.mode == "custom" and self.custom_path: paths = [self.custom_path]

        files_to_check = []
        for p in paths:
            if not os.path.exists(p): continue
            for root, dirs, files in os.walk(p):
                # Исключаем виртуальные файловые системы Linux и проблемные папки
                if any(x in root for x in ["/proc", "/sys", "/dev", "/run", ".snapshots", "/snap"]):
                    continue
                for f in files:
                    if not self._is_running: return
                    files_to_check.append(os.path.join(root, f))

        total = len(files_to_check)
        threats_found = 0

        if total == 0:
            self.finished.emit(0, 0)
            return

        self.log.emit(f"[INFO] Найдено файлов для проверки: {total}...")

        for idx, path in enumerate(files_to_check):
            if not self._is_running:
                break

            file_hash = self.calculate_sha256(path)

            if file_hash and file_hash in VIRUS_DATABASE:
                threats_found += 1
                virus_name = VIRUS_DATABASE[file_hash]
                self.log.emit(f"[!!!] ОБНАРУЖЕНА УГРОЗА: {path} -> {virus_name}")

            # Плавный расчет прогресс-бара
            self.progress.emit(int(((idx + 1) / total) * 100))

        self.finished.emit(total, threats_found)

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

        if mode == "custom" and not self.selected_dir:
            self.console.append("[ERROR] Пожалуйста, выберите папку для сканирования!")
            return

        self.btn_action.setText("Остановить")
        self.progress_bar.setValue(0)
        self.status_label.setText("Идет сканирование...")

        self.scan_thread = ScanWorker(mode, self.selected_dir)
        self.scan_thread.progress.connect(self.progress_bar.setValue)
        self.scan_thread.log.connect(self.console.append)
        self.scan_thread.finished.connect(self.scan_done)
        self.scan_thread.start()

    def scan_done(self, total, threats):
        self.btn_action.setText("Запустить сканирование")
        self.status_label.setText("Сканирование завершено")
        self.console.append(f"\n[FINISH] Проверено файлов: {total}")
        self.console.append(f"[FINISH] Найдено угроз: {threats}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = HasonAntivirusGUI()
    gui.show()
    sys.exit(app.exec())
