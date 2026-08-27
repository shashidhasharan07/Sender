import sys
import pandas as pd
import numpy as np
import re
import time
from PyQt5 import QtWidgets, QtCore
import pyqtgraph as pg

pg.setConfigOptions(useOpenGL=True)

TIME_WINDOW = 10
RIGHT_MARGIN = 2
ROW_PER_SECOND_MODE = True  # Toggle: True = one CSV row per second


# =====================================================
# PLAYBACK CLOCK
# =====================================================
class PlaybackClock:
    def __init__(self):
        self.time = 0.0
        self.speed = 1.0
        self.last = time.time()

    def reset(self):
        self.time = 0.0
        self.last = time.time()

    def update(self, paused=False):
        if paused:
            self.last = time.time()
            return
        now = time.time()
        dt = now - self.last
        self.last = now
        self.time += dt * self.speed

    def set_speed(self, s):
        self.speed = s

    def get(self):
        return self.time


# =====================================================
# REPLAY PLOT WINDOW
# =====================================================
class ReplayPlotWindow(QtWidgets.QWidget):
    def __init__(self, df, param=None):
        super().__init__()
        self.setWindowTitle("Telemetry CSV Replay Viewer")
        self.resize(1150, 700)

        self.df_original = df.copy()
        self.df = None
        self.time_data = None

        self.playback = PlaybackClock()
        self.current_index = 0
        self.paused = True

        self.selected_param = param
        self.child_windows = []  # Keep references to new windows

        self.init_ui()
        self.prepare_data()

    # ================= UI =================
    def init_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        controls = QtWidgets.QHBoxLayout()
        self.column_dropdown = QtWidgets.QComboBox()
        controls.addWidget(self.column_dropdown)

        self.new_window_btn = QtWidgets.QPushButton("Open New Window")
        controls.addWidget(self.new_window_btn)

        self.speed_dropdown = QtWidgets.QComboBox()
        self.speed_dropdown.addItems(["0.25x", "0.5x", "1x", "2x", "4x"])
        self.speed_dropdown.setCurrentText("1x")
        controls.addWidget(self.speed_dropdown)

        self.play_btn = QtWidgets.QPushButton("Play")
        self.pause_btn = QtWidgets.QPushButton("Pause")
        self.restart_btn = QtWidgets.QPushButton("Restart")
        controls.addWidget(self.play_btn)
        controls.addWidget(self.pause_btn)
        controls.addWidget(self.restart_btn)

        layout.addLayout(controls)

        self.value_label = QtWidgets.QLabel("Current Value: ---")
        self.value_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(self.value_label)

        self.plot_widget = pg.PlotWidget()
        self.plot_widget.showGrid(x=True, y=True)
        layout.addWidget(self.plot_widget)

        self.curve = self.plot_widget.plot(pen=pg.mkPen(width=2))

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_plot)
        self.timer.start(40)  # Smooth updates

        # Connections
        self.play_btn.clicked.connect(self.start_replay)
        self.pause_btn.clicked.connect(self.pause_replay)
        self.restart_btn.clicked.connect(self.restart_replay)
        self.speed_dropdown.currentTextChanged.connect(self.change_speed)
        self.new_window_btn.clicked.connect(self.open_new_window)

    # ================= DATA =================
    def prepare_data(self):
        self.df = self.df_original.copy()
        for col in self.df.columns:
            if col.lower().startswith("data"):
                self.df[col] = self.df[col].apply(self.smart_convert)
                self.df[col] = self.df[col].replace("na", np.nan)
                self.df[col] = self.df[col].ffill()
                self.df[col] = self.df[col].fillna(0)

        if ROW_PER_SECOND_MODE:
            self.time_data = np.arange(len(self.df))
        else:
            self.time_data = self.df.iloc[:, 1].astype(float) / 1e6

        self.data_columns = [col for col in self.df.columns if col.lower().startswith("data")]
        self.column_dropdown.clear()
        self.column_dropdown.addItems(self.data_columns)

        if self.selected_param and self.selected_param in self.data_columns:
            self.column_dropdown.setCurrentText(self.selected_param)

    def smart_convert(self, val):
        if isinstance(val, str):
            val = val.strip()
            if val.lower() == "na":
                return np.nan
            val = re.sub(r'(\d)\+e', r'\1e', val)
            val = re.sub(r'(\d)-e', r'\1e-', val)
            if re.match(r"^(0x)?[0-9A-Fa-f]+$", val):
                return int(val, 16)
            try:
                return float(val)
            except:
                return np.nan
        return val

    # ================= CONTROLS =================
    def start_replay(self):
        self.paused = False

    def pause_replay(self):
        self.paused = True

    def restart_replay(self):
        self.current_index = 0
        self.playback.reset()
        self.curve.setData([], [])
        self.value_label.setText("Current Value: ---")

    def change_speed(self):
        speed = float(self.speed_dropdown.currentText().replace("x", ""))
        self.playback.set_speed(speed)

    def open_new_window(self):
        param = self.column_dropdown.currentText()
        new_win = ReplayPlotWindow(self.df_original, param)
        new_win.show()
        self.child_windows.append(new_win)  # Keep reference so it doesn't close

    # ================= UPDATE =================
    def update_plot(self):
        self.playback.update(self.paused)
        current_play_time = self.playback.get()

        if ROW_PER_SECOND_MODE:
            self.current_index = min(int(current_play_time), len(self.df) - 1)
        else:
            while self.current_index < len(self.time_data) and self.time_data[self.current_index] <= current_play_time:
                self.current_index += 1

        if self.current_index < 0 or self.current_index >= len(self.time_data):
            return

        selected_col = self.column_dropdown.currentText()
        x_data = self.time_data[:self.current_index + 1]
        y_data = self.df[selected_col].iloc[:self.current_index + 1].values

        self.curve.setData(x_data, y_data)
        self.value_label.setText(f"Current Value: {y_data[-1]:.3f}")

        # Sliding window
        self.plot_widget.setXRange(max(x_data[-1] - TIME_WINDOW, 0),
                                   x_data[-1] + RIGHT_MARGIN, padding=0)


# =====================================================
# MAIN
# =====================================================
def main():
    app = QtWidgets.QApplication(sys.argv)
    file_path = "Book1.csv"  # <-- change to your CSV
    df = pd.read_csv(file_path)



    window = ReplayPlotWindow(df)
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()







def aesa_receiver(group, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        socket.IPPROTO_UDP
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    sock.bind(("", port))

    mreq = struct.pack(
        "4sl",
        socket.inet_aton(group),
        socket.INADDR_ANY
    )

    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_ADD_MEMBERSHIP,
        mreq
    )

    print(f"Listening AESA multicast {group}:{port}")

    while True:

        pkt, _ = sock.recvfrom(65535)

        # AESA header is 28 bytes
        if len(pkt) < AESA_HEADER_SIZE:
            continue

        # Decode 28-byte AESA header
        header = struct.unpack(
            AESA_HEADER_FMT,
            pkt[:AESA_HEADER_SIZE]
        )

        # First field is Message Code = OPCODE
        opcode = header[0]

        # Remaining AESA fields
        message_day   = header[1]
        message_month = header[2]
        message_tod   = header[3]

        param5 = header[4]
        param6 = header[5]
        param7 = header[6]
        param8 = header[7]
        param9 = header[8]

        print("AESA OPCODE:", opcode)
        print("Day:", message_day)
        print("Month:", message_month)
        print("TOD:", message_tod)

        # Decode according to opcode
        try:
            decoded, labels = decode_from_icd(opcode, pkt)
        except Exception as e:
            print(f"Decode error opcode {opcode}: {e}")
            continue
