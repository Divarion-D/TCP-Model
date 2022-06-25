# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'auth.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide2.QtCore import *
from PySide2.QtGui import *
from PySide2.QtWidgets import *


class Ui_Auth(object):
    def setupUi(self, Auth):
        if not Auth.objectName():
            Auth.setObjectName(u"Auth")
        Auth.resize(318, 222)
        self.pushButton = QPushButton(Auth)
        self.pushButton.setObjectName(u"pushButton")
        self.pushButton.setGeometry(QRect(80, 150, 151, 28))
        font = QFont()
        font.setPointSize(12)
        self.pushButton.setFont(font)
        self.pushButton_2 = QPushButton(Auth)
        self.pushButton_2.setObjectName(u"pushButton_2")
        self.pushButton_2.setGeometry(QRect(80, 180, 151, 28))
        self.pushButton_2.setFont(font)
        self.lineEdit = QLineEdit(Auth)
        self.lineEdit.setObjectName(u"lineEdit")
        self.lineEdit.setGeometry(QRect(30, 40, 251, 28))
        self.lineEdit_2 = QLineEdit(Auth)
        self.lineEdit_2.setObjectName(u"lineEdit_2")
        self.lineEdit_2.setGeometry(QRect(32, 100, 251, 28))
        self.lineEdit_2.setEchoMode(QLineEdit.Password)
        self.label1 = QLabel(Auth)
        self.label1.setObjectName(u"label1")
        self.label1.setGeometry(QRect(130, 20, 51, 21))
        self.label1.setFont(font)
        self.label_2 = QLabel(Auth)
        self.label_2.setObjectName(u"label_2")
        self.label_2.setGeometry(QRect(120, 80, 81, 21))
        self.label_2.setFont(font)

        self.retranslateUi(Auth)

        QMetaObject.connectSlotsByName(Auth)
    # setupUi

    def retranslateUi(self, Auth):
        Auth.setWindowTitle(QCoreApplication.translate("Auth", u"Dialog", None))
        self.pushButton.setText(QCoreApplication.translate("Auth", u"Login", None))
        self.pushButton_2.setText(QCoreApplication.translate("Auth", u"SignUp", None))
        self.label1.setText(QCoreApplication.translate("Auth", u"Login", None))
        self.label_2.setText(QCoreApplication.translate("Auth", u"Password", None))
    # retranslateUi

