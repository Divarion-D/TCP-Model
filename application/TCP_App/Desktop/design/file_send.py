# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'file_send.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_File_send(object):
    def setupUi(self, File_send):
        if not File_send.objectName():
            File_send.setObjectName(u"File_send")
        File_send.resize(273, 133)
        self.pushButton = QPushButton(File_send)
        self.pushButton.setObjectName(u"pushButton")
        self.pushButton.setGeometry(QRect(90, 90, 90, 28))

        self.retranslateUi(File_send)

        QMetaObject.connectSlotsByName(File_send)
    # setupUi

    def retranslateUi(self, File_send):
        File_send.setWindowTitle(QCoreApplication.translate("File_send", u"Dialog", None))
        self.pushButton.setText(QCoreApplication.translate("File_send", u"PushButton", None))
    # retranslateUi

