import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Common import LabTcpClient
from Desktop.design.auth import Ui_Auth
from Desktop.design.file_send import Ui_File_send
from PySide2 import QtWidgets

BUFFER_SIZE = 4096
HOST = '127.0.1.1'
PORT = 9999

CLT = LabTcpClient(HOST, PORT, BUFFER_SIZE)

class Auth(QtWidgets.QMainWindow, Ui_Auth):
    def __init__(self):
        super().__init__()
        # Создание формы и Ui (наш дизайн)
        self.setupUi(self)
        self.show()

        self.dialog = QtWidgets.QMessageBox()

        self.pushButton.clicked.connect(self.auth)
        self.pushButton_2.clicked.connect(self.auth)

    def auth(self):
        sender = self.sender()
        if sender:
            if self.lineEdit.text() != "":
                if self.lineEdit_2.text() != "":
                    reg_data = {'username': self.lineEdit.text(),
                            'password': self.lineEdit_2.text()}
                    if sender == self.pushButton:
                        reg_data['send_key'] = 'LOGIN'
                        CLT.send_data_server(reg_data, True)
                        data = CLT.recv_data_server(True)
                    elif sender == self.pushButton_2:
                        reg_data['send_key'] = 'SIGNUP'
                        CLT.send_data_server(reg_data, True)
                        data = CLT.recv_data_server(True)

                    if data:
                        if data['status'] == 'OK':
                            # Уже авторизировался и можно открыть главный интерфейс
                            self.close() # Закрываем окно
                            self.dialog = File_send() # Создаем окно
                            self.dialog.show() # Отображаем окно
                        else:
                            self.dialog.setText(data['message'])
                            self.dialog.exec_()
                    else:
                        self.dialog.setText('No connection to server')
                        self.dialog.exec_()

                else:
                    self.dialog.setText("Введите пароль")
                    self.dialog.exec_()
            else:
                self.dialog.setText("Введите логин")
                self.dialog.exec_()

class File_send(QtWidgets.QMainWindow, Ui_File_send):
    def __init__(self):
        super().__init__()
        # Создание формы и Ui (наш дизайн)
        self.setupUi(self)
        self.show()

        self.dialog = QtWidgets.QMessageBox()

        self.pushButton.clicked.connect(self.send_file)
    
    def send_file(self):
        sender = self.sender()
        if sender == self.pushButton:
            path = QtWidgets.QFileDialog.getOpenFileName(self, "Open File", os.getcwd())
            if path[0]:
                file_name = os.path.basename(path[0])
                data = {'file_name': file_name, 'send_key': 'FILE UPLOAD'}

                with open(path[0], 'rb') as f:
                    data_file = f.read()
                
                CLT.send_data_server(data, True)
                if CLT.recv_data_server(True)['status'] == 'OK':
                    CLT.send_data_server(data_file, False)



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv) 
    auth = Auth() # Create a new window
    auth.show() # show window
    sys.exit(app.exec_()) #Run application