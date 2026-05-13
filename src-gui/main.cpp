#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QFileDialog>
#include <QProgressBar>
#include <QTextEdit>
#include <QComboBox>
#include <QMessageBox>
#include <QTimer>
#include <odin4/odin4.h>
#include <thread>
#include <mutex>

class OdinGui : public QMainWindow {
    Q_OBJECT
public:
    OdinGui(QWidget *parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("Odin4 GUI - Llucs");
        setMinimumSize(700, 500);

        auto *centralWidget = new QWidget(this);
        auto *layout = new QVBoxLayout(centralWidget);

        auto createBrowseRow = [&](const QString &label, QLineEdit *&edit) {
            auto *row = new QHBoxLayout();
            row->addWidget(new QLabel(label + ":"), 0);
            edit = new QLineEdit();
            row->addWidget(edit, 1);
            auto *btn = new QPushButton("Browse");
            connect(btn, &QPushButton::clicked, [this, edit]() {
                QString file = QFileDialog::getOpenFileName(this, "Select File", "", "Samsung Firmware (*.tar *.tar.md5 *.lz4 *.bin)");
                if (!file.isEmpty()) edit->setText(file);
            });
            row->addWidget(btn, 0);
            layout->addLayout(row);
        };

        createBrowseRow("BL", editBL);
        createBrowseRow("AP", editAP);
        createBrowseRow("CP", editCP);
        createBrowseRow("CSC", editCSC);
        createBrowseRow("UMS", editUMS);

        auto *devRow = new QHBoxLayout();
        devRow->addWidget(new QLabel("Device:"));
        comboDevices = new QComboBox();
        devRow->addWidget(comboDevices, 1);
        auto *btnRefresh = new QPushButton("Refresh");
        connect(btnRefresh, &QPushButton::clicked, this, &OdinGui::refreshDevices);
        devRow->addWidget(btnRefresh);
        layout->addLayout(devRow);

        logView = new QTextEdit();
        logView->setReadOnly(true);
        logView->setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: monospace;");
        layout->addWidget(logView);

        progressBar = new QProgressBar();
        layout->addWidget(progressBar);

        auto *btnRow = new QHBoxLayout();
        btnStart = new QPushButton("Start Flash");
        btnStart->setMinimumHeight(40);
        connect(btnStart, &QPushButton::clicked, this, &OdinGui::startFlash);
        btnRow->addWidget(btnStart);
        layout->addLayout(btnRow);

        setCentralWidget(centralWidget);
        
        // Setup log callback
        odin4_set_log_callback([](int level, const char* message) {
            QString msg = QString("[%1] %2").arg(level).arg(message);
            // Post to UI thread
            QMetaObject::invokeMethod(qApp, [msg]() {
                auto *win = qobject_cast<OdinGui*>(qApp->activeWindow());
                if (win) win->appendLog(msg);
            });
        });

        refreshDevices();
    }

    void appendLog(const QString &msg) {
        logView->append(msg);
    }

private slots:
    void refreshDevices() {
        comboDevices->clear();
        OdinConfig cfg;
        auto devices = odin4_list_devices(cfg);
        for (const auto &dev : devices) {
            comboDevices->addItem(QString::fromStdString(dev));
        }
        if (devices.empty()) comboDevices->addItem("No device detected");
    }

    void startFlash() {
        OdinConfig cfg;
        cfg.bootloader = editBL->text().toStdString();
        cfg.ap = editAP->text().toStdString();
        cfg.cp = editCP->text().toStdString();
        cfg.csc = editCSC->text().toStdString();
        cfg.ums = editUMS->text().toStdString();
        cfg.device_path = comboDevices->currentText().toStdString();

        if (cfg.bootloader.empty() && cfg.ap.empty() && cfg.cp.empty() && cfg.csc.empty() && cfg.ums.empty()) {
            QMessageBox::warning(this, "Error", "Please select at least one file to flash.");
            return;
        }

        if (cfg.device_path == "No device detected") {
            QMessageBox::warning(this, "Error", "No device selected.");
            return;
        }

        btnStart->setEnabled(false);
        logView->clear();
        logView->append("--- Starting Flash Process ---");
        progressBar->setRange(0, 0);

        std::thread([this, cfg]() {
            odin4_init(cfg);
            auto result = odin4_run(cfg);
            QMetaObject::invokeMethod(this, [this, result]() {
                btnStart->setEnabled(true);
                progressBar->setRange(0, 100);
                if (result == OdinExitCode::Success) {
                    logView->append("<b>Flash successful!</b>");
                    progressBar->setValue(100);
                } else {
                    logView->append(QString("<span style='color:red;'>Flash failed with code: %1</span>").arg(static_cast<int>(result)));
                    progressBar->setValue(0);
                }
            });
        }).detach();
    }

private:
    QLineEdit *editBL, *editAP, *editCP, *editCSC, *editUMS;
    QComboBox *comboDevices;
    QTextEdit *logView;
    QProgressBar *progressBar;
    QPushButton *btnStart;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    OdinGui gui;
    gui.show();
    return app.exec();
}

#include "main.moc"
