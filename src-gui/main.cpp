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

class OdinGui : public QMainWindow {
    Q_OBJECT
public:
    OdinGui(QWidget *parent = nullptr) : QMainWindow(parent) {
        setWindowTitle("Odin4 GUI - Llucs");
        setMinimumSize(600, 450);

        auto *centralWidget = new QWidget(this);
        auto *layout = new QVBoxLayout(centralWidget);

        auto createBrowseRow = [&](const QString &label, QLineEdit *&edit) {
            auto *row = new QHBoxLayout();
            row->addWidget(new QLabel(label + ":"));
            edit = new QLineEdit();
            row->addWidget(edit);
            auto *btn = new QPushButton("Browse");
            connect(btn, &QPushButton::clicked, [this, edit]() {
                QString file = QFileDialog::getOpenFileName(this, "Select File", "", "Samsung Firmware (*.tar *.tar.md5 *.lz4 *.bin)");
                if (!file.isEmpty()) edit->setText(file);
            });
            row->addWidget(btn);
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
        layout->addWidget(logView);

        progressBar = new QProgressBar();
        layout->addWidget(progressBar);

        auto *btnRow = new QHBoxLayout();
        btnStart = new QPushButton("Start");
        connect(btnStart, &QPushButton::clicked, this, &OdinGui::startFlash);
        btnRow->addWidget(btnStart);
        layout->addLayout(btnRow);

        setCentralWidget(centralWidget);
        refreshDevices();
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

        btnStart->setEnabled(false);
        logView->append("Starting flash process...");
        progressBar->setRange(0, 0);

        std::thread([this, cfg]() {
            odin4_init(cfg);
            auto result = odin4_run(cfg);
            QMetaObject::invokeMethod(this, [this, result]() {
                btnStart->setEnabled(true);
                progressBar->setRange(0, 100);
                if (result == OdinExitCode::Success) {
                    logView->append("Flash successful!");
                    progressBar->setValue(100);
                } else {
                    logView->append("Flash failed with code: " + QString::number(static_cast<int>(result)));
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
